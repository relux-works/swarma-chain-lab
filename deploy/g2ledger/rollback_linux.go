package g2ledger

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

// NodeController is the runtime boundary. Observe must distinguish a stopped
// process from a failed lookup. Policy must attest the loaded configuration,
// covering RPC authentication AND whitelists, rather than reread the disk file.
// An unavailable policy observation is explicit and leads to a deliberate stop.
type NodeController interface {
	Observe(unit string) (bool, error)
	Stop(unit string) error
	Start(unit string) error
	Policy(unit string) (NodePolicy, error)
}
type NodePolicy struct {
	Readable     bool
	ConfigSHA256 string
}

// systemNode uses the plan's systemctl command interface. It cannot attest the
// loaded RPC policy, so the native adapter deliberately leaves the node stopped.
// No shell command, credential argument or node RPC is used by this adapter.
type systemNode struct{ sys System }

func (n systemNode) Observe(unit string) (bool, error) {
	out, status, err := n.sys.Run("/usr/bin/systemctl", "show", "-p", "LoadState", "-p", "ActiveState", "-p", "MainPID", unit)
	if err != nil || status != 0 {
		return false, errors.New("NODE_STATUS_UNAVAILABLE")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 || fields[kv[0]] != "" {
			return false, errors.New("NODE_STATUS_SCHEMA")
		}
		switch kv[0] {
		case "LoadState", "ActiveState", "MainPID":
		default:
			return false, errors.New("NODE_STATUS_SCHEMA")
		}
		fields[kv[0]] = kv[1]
	}
	pid, err := strconv.ParseUint(fields["MainPID"], 10, 32)
	if err != nil || fields["LoadState"] != "loaded" || len(fields) != 3 {
		return false, errors.New("NODE_STATUS_SCHEMA")
	}
	if fields["ActiveState"] == "active" && pid > 0 {
		return true, nil
	}
	if (fields["ActiveState"] == "inactive" || fields["ActiveState"] == "failed") && pid == 0 {
		return false, nil
	}
	return false, errors.New("NODE_TRANSITIONAL_STATE")
}
func (n systemNode) Stop(unit string) error {
	return commandOK(n.sys, "/usr/bin/systemctl", "stop", unit)
}
func (n systemNode) Start(unit string) error {
	return commandOK(n.sys, "/usr/bin/systemctl", "start", unit)
}
func (n systemNode) Policy(string) (NodePolicy, error) { return NodePolicy{}, nil }

func nodeS0(g *Genesis) *Identity {
	if g.Scope.Node == nil {
		return nil
	}
	for _, o := range g.S0 {
		if o.Kind == "file" && o.Name == g.Scope.Node.Config {
			return o.Identity
		}
	}
	return nil
}
func validateNodeGenesis(g *Genesis) error {
	if g.Scope.Node == nil {
		if g.Node != nil {
			return errors.New("NODE_BASELINE_WITHOUT_SCOPE")
		}
		return nil
	}
	n := g.Scope.Node
	old := nodeS0(g)
	if g.Purpose != "station" || g.Node == nil || old == nil || old.FS == nil || !strings.HasPrefix(n.Preimage, g.Baseline+"/") {
		return errors.New("NODE_BASELINE_REQUIRED")
	}
	for _, p := range g.Scope.Paths {
		if p.Path == n.Preimage {
			return errors.New("NODE_PREIMAGE_IS_TARGET")
		}
	}
	return nil
}
func captureNodeBaseline(n *NodeScope, baseline string, s0 []BaselineObject, sys System) (*NodeBaseline, error) {
	if n == nil {
		return nil, nil
	}
	g := &Genesis{Purpose: "station", Scope: Scope{Node: n}, Baseline: baseline, S0: s0, Node: &NodeBaseline{}}
	if err := validateNodeGenesis(g); err != nil {
		return nil, stopped("NODE_INIT", err)
	}
	raw, err := readFile(n.Preimage, 64<<20)
	if err != nil {
		return nil, fail(1, "NODE_PREIMAGE_UNREADABLE")
	}
	defer clear(raw)
	if digest(raw) != nodeS0(g).FS.SHA256 {
		return nil, fail(1, "NODE_PREIMAGE_MISMATCH")
	}
	running, err := (systemNode{sys}).Observe(n.Unit)
	if err != nil {
		return nil, stopped("NODE_BASELINE_READ", err)
	}
	return &NodeBaseline{Running: running}, nil
}
func validateNodeAction(g *Genesis, a Action) error {
	n := g.Scope.Node
	if a.Backup != n.Preimage || len(a.Before) != 1 || !identityEqual(a.Before[0], *nodeS0(g)) {
		return fail(1, "NODE_MODIFY_NOT_BASELINE")
	}
	return nil
}
func (l *Ledger) validateNodeModify(a Action) error {
	return validateNodeAction(l.rows[0].Body.Genesis, a)
}

func validRollbackStep(s *RollbackStep) bool {
	if s == nil {
		return false
	}
	switch s.Phase {
	case "stop-intent", "stopped", "restore-intent", "restored", "replay-intent", "replayed", "start-intent", "started", "check-intent", "verified", "refused":
	default:
		return false
	}
	switch s.Disk {
	case "preinstall", "installed", "mismatch", "unreadable":
	default:
		return false
	}
	switch s.Node {
	case "running", "stopped", "unknown":
	default:
		return false
	}
	switch s.Reason {
	case "", "BASELINE_STOPPED", "LIVE_POLICY_UNREADABLE", "STOP_FAILED", "STOP_READBACK", "RESTORE_FAILED", "REPLAY_FAILED", "START_FAILED", "READBACK_FAILED", "CHECKPOINT_FAILED", "CONFIG_MISMATCH", "LIVE_POLICY_MISMATCH", "NODE_STATE_MISMATCH":
	default:
		return false
	}
	if (s.Phase == "restore-intent") != (s.Restore != nil) || s.Restore != nil && validateIdentity(*s.Restore, "modify") != nil {
		return false
	}
	return s.Phase != "refused" || s.Reason != ""
}

// nodeAttemptPhase is derived from sealed effects, never an invocation's before /
// after hashes. Disk observations refine recovery state but cannot erase the
// restart obligation of a recorded modification, even after partial replay.
func (l *Ledger) nodeAttemptPhase() (string, *Record) {
	n := l.rows[0].Body.Genesis.Scope.Node
	var effect *Record
	for i := range l.rows {
		r := &l.rows[i]
		if r.Body.Op == "commit" {
			a := l.rows[r.Body.Result.Intent].Body.Action
			if a.Kind == "modify" && a.Paths[0] == n.Config {
				effect = r
			}
		}
	}
	if effect == nil {
		return "pre-change", nil
	}
	phase := "config-changed"
	for _, r := range l.rows {
		if r.Body.Op == "parent-replay" && r.Body.ParentReplay.Commit == effect.Seq {
			phase = "partially-replayed"
		}
		if r.Body.Op == "rollback" {
			phase = "rollback-" + r.Body.Rollback.Phase
		}
	}
	return phase, effect
}
func (l *Ledger) nodeDisk() string {
	g := l.rows[0].Body.Genesis
	id, err := observe(g.Scope.Node.Config, "modify")
	if err != nil || id == nil {
		return "unreadable"
	}
	old := nodeS0(g)
	if id.FS.SHA256 == old.FS.SHA256 && id.FS.UID == old.FS.UID && id.FS.GID == old.FS.GID && id.FS.Mode == old.FS.Mode && id.FS.MtimeNS == old.FS.MtimeNS {
		return "preinstall"
	}
	_, effect := l.nodeAttemptPhase()
	if effect != nil && identityEqual(*id, effect.Body.Result.Identities[0]) {
		return "installed"
	}
	return "mismatch"
}

func (l *Ledger) rollbackCheckpoint(phase string, c NodeController, reason string, restore ...*Identity) error {
	node := "unknown"
	if running, err := c.Observe(l.rows[0].Body.Genesis.Scope.Node.Unit); err == nil {
		node = "stopped"
		if running {
			node = "running"
		}
	}
	disk := l.nodeDisk()
	if phase == "verified" {
		expected := "stopped"
		if l.rows[0].Body.Genesis.Node.Running && reason == "" {
			expected = "running"
		}
		if disk != "preinstall" || node != expected {
			return fail(1, "FINAL_CHECKPOINT_MISMATCH")
		}
	}
	var target *Identity
	if len(restore) > 0 {
		target = restore[0]
	}
	if err := l.append(Body{Op: "rollback", Rollback: &RollbackStep{Phase: phase, Disk: disk, Node: node, Reason: reason, Restore: target}}); err != nil {
		return err
	}
	if l.rollbackHook != nil {
		return l.rollbackHook(phase)
	}
	return nil
}

// Rollback reconciles the node before ordinary reverse replay and rechecks the
// restored bytes/metadata AND the live policy (or a named deliberate stop).
// Every run reestablishes the stop/restore barrier; progress records are audit
// evidence, never permission to skip runtime reconciliation on a retry.
func (l *Ledger) Rollback(mode string, controller NodeController) error {
	if mode != "station" && mode != "rehearsal" {
		return fail(2, "ROLLBACK_MODE")
	}
	if err := l.load(); err != nil {
		return rollbackLedgerRefusal(err)
	}
	if l.poisoned {
		return fail(1, "LEDGER_POISONED")
	}
	g := l.rows[0].Body.Genesis
	if !purposeMatches(g.Purpose, mode) {
		return fail(1, "MODE_PURPOSE_MISMATCH")
	}
	if g.Scope.Node == nil {
		// Rehearsal explicitly has no node. A legacy station ledger cannot silently
		// claim node recovery without a sealed baseline runtime declaration.
		if mode == "rehearsal" {
			return l.Replay(mode)
		}
		return fail(1, "NODE_DECLARATION_REQUIRED phase=validate disk=unverified node=unverified; initialize scope.node before installation")
	}
	if controller == nil {
		controller = systemNode{l.sys}
	}
	n := g.Scope.Node
	attempt, effect := l.nodeAttemptPhase()
	phase := "validate"
	refuse := func(reason string, cause error) error {
		state := "unknown"
		if running, e := controller.Observe(n.Unit); e == nil {
			state = "stopped"
			if running {
				state = "running"
			}
		}
		disk := l.nodeDisk()
		// Do not echo command errors: they may contain credentials. Keep phase,
		// remaining state and the original numeric ledger failure classification.
		code := 1
		if cause != nil && ExitCode(cause) == 3 {
			code = 3
		}
		if !l.poisoned {
			if e := l.rollbackCheckpoint("refused", controller, reason); e != nil {
				return fail(code, fmt.Sprintf("ROLLBACK_CHECKPOINT_FAILED phase=%s attempt=%s disk=%s node=%s", phase, attempt, disk, state))
			}
		}
		return fail(code, fmt.Sprintf("ROLLBACK_%s phase=%s attempt=%s disk=%s node=%s", reason, phase, attempt, disk, state))
	}
	checkpoint := func(p string) error {
		phase = p
		if err := l.rollbackCheckpoint(p, controller, ""); err != nil {
			return refuse("CHECKPOINT_FAILED", err)
		}
		return nil
	}
	old, err := readFile(n.Preimage, 64<<20)
	if err != nil {
		return refuse("RESTORE_FAILED", err)
	}
	defer clear(old)
	if digest(old) != nodeS0(g).FS.SHA256 {
		return refuse("CONFIG_MISMATCH", nil)
	}
	if err := checkpoint("stop-intent"); err != nil {
		return err
	}
	if err := controller.Stop(n.Unit); err != nil {
		return refuse("STOP_FAILED", err)
	}
	if running, err := controller.Observe(n.Unit); err != nil || running {
		return refuse("STOP_READBACK", err)
	}
	if err := checkpoint("stopped"); err != nil {
		return err
	}
	phase = "restore-intent"
	got, err := observe(n.Config, "modify")
	if err != nil || got == nil {
		return refuse("RESTORE_FAILED", err)
	}
	expected := nodeS0(g)
	restored := got.FS.SHA256 == expected.FS.SHA256 && got.FS.UID == expected.FS.UID && got.FS.GID == expected.FS.GID && got.FS.Mode == expected.FS.Mode
	if !restored && (effect == nil || !identityEqual(*got, effect.Body.Result.Identities[0])) && !restoreInodeAuthorized(l.rows, *got) {
		return refuse("CONFIG_MISMATCH", nil)
	}
	// Without a committed change only the exact S0 identity is authorized.
	if effect == nil && !identityEqual(*got, *expected) {
		return refuse("CONFIG_MISMATCH", nil)
	}
	// Persist the held destination identity before any in-place write. This
	// authorizes retry of a partially written inode, without adopting a foreign
	// replacement. Keeping the node down avoids publishing a partial config.
	if err := l.rollbackCheckpoint("restore-intent", controller, "", got); err != nil {
		return refuse("CHECKPOINT_FAILED", err)
	}
	if !restored || got.FS.MtimeNS != expected.FS.MtimeNS {
		if err := l.restoreNodeFile(*got, old, *expected.FS); err != nil {
			return refuse("RESTORE_FAILED", err)
		}
	}
	if l.nodeDisk() != "preinstall" {
		return refuse("CONFIG_MISMATCH", nil)
	}
	if err := checkpoint("restored"); err != nil {
		return err
	}
	if err := checkpoint("replay-intent"); err != nil {
		return err
	}
	if err := l.replay(mode, true); err != nil {
		return refuse("REPLAY_FAILED", err)
	}
	if err := checkpoint("replayed"); err != nil {
		return err
	}
	reason := "BASELINE_STOPPED"
	if g.Node.Running {
		if err := checkpoint("start-intent"); err != nil {
			return err
		}
		// Recheck at the actual effect boundary; a checkpoint is not a disk lock.
		if l.nodeDisk() != "preinstall" {
			return refuse("CONFIG_MISMATCH", nil)
		}
		if err := controller.Start(n.Unit); err != nil {
			return refuse("START_FAILED", err)
		}
		if err := checkpoint("started"); err != nil {
			return err
		}
		reason = ""
	}
	if err := checkpoint("check-intent"); err != nil {
		return err
	}
	if l.nodeDisk() != "preinstall" {
		return refuse("CONFIG_MISMATCH", nil)
	}
	// Compare actual bytes too, rather than using a recorded successful restore.
	actual, err := readFile(n.Config, 64<<20)
	if err != nil {
		return refuse("READBACK_FAILED", err)
	}
	equal := bytes.Equal(actual, old)
	clear(actual)
	if !equal {
		return refuse("CONFIG_MISMATCH", nil)
	}
	running, err := controller.Observe(n.Unit)
	if err != nil {
		return refuse("READBACK_FAILED", err)
	}
	if running != g.Node.Running {
		return refuse("NODE_STATE_MISMATCH", nil)
	}
	if running {
		policy, err := controller.Policy(n.Unit)
		if err != nil {
			return refuse("READBACK_FAILED", err)
		}
		if policy.Readable {
			if policy.ConfigSHA256 != digest(old) {
				return refuse("LIVE_POLICY_MISMATCH", nil)
			}
		} else {
			// A missing runtime observation is never interpreted as successful policy
			// adoption. Stop and read back that deliberate, named terminal state.
			phase = "stop-unreadable-policy"
			if err := l.rollbackCheckpoint("stop-intent", controller, "LIVE_POLICY_UNREADABLE"); err != nil {
				return refuse("CHECKPOINT_FAILED", err)
			}
			if err := controller.Stop(n.Unit); err != nil {
				return refuse("STOP_FAILED", err)
			}
			if active, err := controller.Observe(n.Unit); err != nil || active {
				return refuse("STOP_READBACK", err)
			}
			reason = "LIVE_POLICY_UNREADABLE"
		}
	}
	// The stop controller may have changed the file: recheck after the last effect.
	if l.nodeDisk() != "preinstall" {
		return refuse("CONFIG_MISMATCH", nil)
	}
	if err := l.rollbackCheckpoint("verified", controller, reason); err != nil {
		return refuse("CHECKPOINT_FAILED", err)
	}
	if l.output != nil {
		if err := checkedWrite(l.output, append(canonical(struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		}{"rollback_verified", reason}), '\n')); err != nil {
			return fail(1, "ROLLBACK_OUTPUT_FAILED state=verified safe-to-rerun")
		}
	}
	return nil
}

// RunRollback keeps shell inputs limited to ledger location and purpose. Node
// identity, baseline runtime state, preimage and phase all come from the ledger.
func RunRollback(args []string, sys System, out io.Writer) error {
	f := flag.NewFlagSet("g2-rollback", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", "", "private ledger directory")
	mode := f.String("mode", "", "station|rehearsal")
	if f.Parse(args) != nil || f.NArg() != 0 || !validPath(*dir) || (*mode != "station" && *mode != "rehearsal") {
		return fail(2, "USAGE_ROLLBACK")
	}
	l, err := Open(filepath.Clean(*dir), sys)
	if err != nil {
		return rollbackLedgerRefusal(err)
	}
	defer l.Close()
	l.output = out
	return l.Rollback(*mode, nil)
}

func rollbackLedgerRefusal(err error) error {
	reason := "UNVERIFIED"
	var f *Failure
	if errors.As(err, &f) {
		token := strings.Fields(f.Reason)
		if len(token) > 0 && strings.IndexFunc(token[0], func(r rune) bool { return r != '_' && (r < 'A' || r > 'Z') }) < 0 {
			reason = token[0]
		}
	}
	return fail(ExitCode(err), "ROLLBACK_LEDGER_REFUSED phase=validate disk=unverified node=unverified cause="+reason)
}

// restoreInodeAuthorized is limited to a durable restore intent. Content/size/
// mtime can be partial, but replacement, type and ownership are never adopted.
func restoreInodeAuthorized(rows []Record, got Identity) bool {
	for i := len(rows) - 1; i >= 0; i-- {
		if s := rows[i].Body.Rollback; s != nil {
			switch s.Phase {
			case "restored", "replay-intent", "replayed", "start-intent", "started", "check-intent", "verified":
				return false
			}
			if s.Restore == nil {
				continue
			}
			a, b := s.Restore.FS, got.FS
			return got.Path == s.Restore.Path && a.Dev == b.Dev && a.Ino == b.Ino && a.Type == b.Type && a.UID == b.UID && a.GID == b.GID && a.Mode == b.Mode
		}
	}
	return false
}
func (l *Ledger) restoreNodeFile(want Identity, old []byte, metadata FSIdentity) error {
	d, n, err := parent(want.Path)
	if err != nil {
		return err
	}
	defer d.Close()
	f, err := at(d, n, unix.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	id, err := fsIdentity(f, "modify")
	if err != nil {
		return err
	}
	if !identityEqual(Identity{Path: want.Path, FS: id}, want) {
		return errors.New("NODE_RESTORE_IDENTITY_CHANGED")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err = l.write(f, old); err != nil {
		return err
	}
	if err = f.Truncate(int64(len(old))); err != nil {
		return err
	}
	if err = setMetadata(f, metadata.UID, metadata.GID, metadata.Mode, l.sys); err != nil {
		return err
	}
	if err = unix.UtimesNanoAt(int(f.Fd()), "", []unix.Timespec{{Nsec: unix.UTIME_OMIT}, unix.NsecToTimespec(metadata.MtimeNS)}, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	return f.Sync()
}
