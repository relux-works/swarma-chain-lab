//go:build linux

package g2run

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// These capability interfaces are integration boundaries, not alternate exec
// paths. There is intentionally no default implementation using subprocesses.
// E2 adapters must use Ctx.Exec for external programs and validated typed fields.

type PortDatabase string

const (
	PortPasswd PortDatabase = "passwd"
	PortGroup  PortDatabase = "group"
)

type PortLookup struct {
	Database PortDatabase
	Key      string
}

func (q PortLookup) Validate() error {
	if q.Database != PortPasswd && q.Database != PortGroup {
		return errors.New("LOOKUP_DATABASE")
	}
	if q.Key != "" && strings.Trim(q.Key, "0123456789") == "" {
		if _, e := ParsePortCount(q.Key, 1<<32-2); e != nil {
			return errors.New("LOOKUP_KEY")
		}
	} else if !portAccount(q.Key) {
		return errors.New("LOOKUP_KEY")
	}

	return nil
}

// PortLookupOps is TODO(E2 UserExact, GroupExact): a getent typed wrapper.
type PortLookupOps interface {
	Lookup(*Ctx, PortLookup) (Result, error)
}
type PortNamedID struct {
	Name string
	ID   uint32
}

// PortGroupReader is TODO(E2 UserExact): read a user's complete group set.
type PortGroupReader interface {
	Groups(*Ctx, string) ([]PortNamedID, error)
}
type portAccountRecord struct {
	Name        string
	ID, Primary uint32
	Fields      []string
}

func lookupPort(c *Ctx, ops PortLookupOps, q PortLookup) (*portAccountRecord, error) {
	if e := q.Validate(); e != nil {
		return nil, e
	}
	r, e := ops.Lookup(c, q)
	if e != nil {
		return nil, errors.New("LOOKUP_READ")
	}
	if r.RC == 2 && len(r.Stdout) == 0 {
		return nil, nil
	}
	if r.RC != 0 {
		return nil, errors.New("LOOKUP_STATUS")
	}
	raw := strings.TrimSuffix(string(r.Stdout), "\n")
	if len(raw) > 1<<16 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("LOOKUP_RECORD_COUNT")
	}
	fields := strings.Split(raw, ":")
	want := 7
	if q.Database == PortGroup {
		want = 4
	}
	if len(fields) != want || !portAccount(fields[0]) {
		return nil, errors.New("LOOKUP_SHAPE")
	}
	id, e := ParsePortCount(fields[2], 1<<32-2)
	if e != nil {
		return nil, errors.New("LOOKUP_ID")
	}
	if fields[0] != q.Key && strconv.FormatUint(id, 10) != q.Key {
		return nil, errors.New("LOOKUP_KEY_MISMATCH")
	}
	rec := &portAccountRecord{Name: fields[0], ID: uint32(id), Fields: fields}
	if q.Database == PortPasswd {
		n, e := ParsePortCount(fields[3], 1<<32-2)
		if e != nil {
			return nil, errors.New("LOOKUP_GID")
		}
		rec.Primary = uint32(n)
	}
	return rec, nil
}
func portGroups(c *Ctx, ops PortGroupReader, user string) ([]PortNamedID, error) {
	groups, e := ops.Groups(c, user)
	if e != nil || len(groups) == 0 || len(groups) > 1024 {
		return nil, errors.New("GROUP_READ")
	}
	seen := map[uint32]bool{}
	for _, g := range groups {
		if !portAccount(g.Name) || g.ID == ^uint32(0) || seen[g.ID] {
			return nil, errors.New("GROUP_SHAPE")
		}
		seen[g.ID] = true
	}
	return groups, nil
}

// PortUnitInfo is E2's typed systemctl readback. Exec directives are evidence
// strings only: no part of them is ever executed by the ports.
type PortUnitInfo struct {
	LoadState, ActiveState, UnitFileState                     string
	MainPID                                                   uint32
	TimeoutStopUSec, KillMode, KillSignal, User, FragmentPath string
	ExecStartPre, ExecStart                                   string
}

func (s PortUnitInfo) validate() error {
	if s.LoadState == "" || s.ActiveState == "" {
		return errors.New("UNIT_STATE_MISSING")
	}
	for _, v := range []string{s.LoadState, s.ActiveState, s.UnitFileState, s.TimeoutStopUSec, s.KillMode, s.KillSignal, s.User, s.FragmentPath, s.ExecStartPre, s.ExecStart} {
		if strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("UNIT_STATE_ENCODING")
		}
	}
	return nil
}
func (s PortUnitInfo) baseline() []byte {
	return []byte(fmt.Sprintf("LoadState=%s\nActiveState=%s\nUnitFileState=%s\nMainPID=%d\nTimeoutStopUSec=%s\nKillMode=%s\nKillSignal=%s\n", s.LoadState, s.ActiveState, s.UnitFileState, s.MainPID, s.TimeoutStopUSec, s.KillMode, s.KillSignal))
}

// PortUnitReader is TODO(E2 UnitProperty): fixed property queries.
type PortUnitReader interface {
	UnitInfo(*Ctx, string) (PortUnitInfo, error)
}

// PortUnitControl is TODO(E2 Systemctl): start, stop and daemon-reload only.
type PortUnitControl interface {
	PortUnitReader
	Start(*Ctx, string) error
	Stop(*Ctx, string) error
	Reload(*Ctx) error
}

func portUnitInfo(c *Ctx, ops PortUnitReader, unit string) (PortUnitInfo, error) {
	if !portUnit(unit) {
		return PortUnitInfo{}, errors.New("UNIT_NAME")
	}
	s, e := ops.UnitInfo(c, unit)
	if e != nil {
		return s, errors.New("UNIT_READ")
	}
	return s, s.validate()
}

type PortUnitRow struct{ Name, Line string }

// PortInventory is TODO(E2 ListenSetEqual, Systemctl inventory and process UID
// inventory): adapters must return actual host observations, never placeholders.
type PortInventory interface {
	Listeners(*Ctx) ([]string, error)
	Units(*Ctx) ([]PortUnitRow, error)
	ProcessUIDs(*Ctx) ([]uint32, error)
}

func portUnits(c *Ctx, ops PortInventory) ([]PortUnitRow, error) {
	rows, e := ops.Units(c)
	if e != nil || len(rows) > 1<<20 {
		return nil, errors.New("UNIT_INVENTORY")
	}
	for _, r := range rows {
		if r.Name == "" || !ValidOperand(r.Name) || strings.ContainsAny(r.Line, "\x00\r\n") || len(strings.Fields(r.Line)) == 0 || strings.Fields(r.Line)[0] != r.Name {
			return nil, errors.New("UNIT_INVENTORY_SHAPE")
		}
	}
	return rows, nil
}

// PortLedgerChange is the exact subset of E2 Ledger used by activation.
// Sources are workspace files; targets and retention belong to the sealed scope.
type PortLedgerChange struct {
	Kind                   string
	Path, Source           string
	UID, GID, Mode         uint32
	Retention, User, Group string
}

func (v PortLedgerChange) Validate() error {
	if v.Kind == "add-member" {
		if !portAccount(v.User) || !portAccount(v.Group) {
			return errors.New("LEDGER_MEMBER")
		}
		return nil
	}
	if v.Kind != "create-file" && v.Kind != "create-dir" {
		return errors.New("LEDGER_KIND")
	}
	if !portAbs(v.Path) || v.Kind == "create-file" && !portAbs(v.Source) || v.Mode > 0777 || v.UID == ^uint32(0) || v.GID == ^uint32(0) {
		return errors.New("LEDGER_FIELDS")
	}
	if v.Retention != "remove" && v.Retention != "d6" && v.Retention != "rehearsal" {
		return errors.New("LEDGER_RETENTION")
	}
	return nil
}

// PortLedgerWriter is TODO(E2 Ledger): in-process g2ledger, with its System
// adapter routed through Ctx.Exec; never invoke deploy-kit as another process.
type PortLedgerWriter interface {
	Apply(*Ctx, string, PortLedgerChange) error
}

// PortLedgerVerifier is TODO(E2 Ledger): only verified statuses 0 and 3 may be
// returned without an execution/read error. Other statuses prohibit unit stops.
type PortLedgerVerifier interface {
	Verify(*Ctx, string) (int, error)
}

// PortRollbackEngine is TODO(E2 Ledger/g2-rollback): in-process RunRollback with
// the E2 System/NodeController adapter; output is opened by Go before invocation.
// PortEngineStatusError preserves the in-process engine's nonzero status.
type PortEngineStatusError struct{ Code int }

func (e *PortEngineStatusError) Error() string {
	return fmt.Sprintf("ROLLBACK_ENGINE_STATUS_%d", e.Code)
}

type PortRollbackEngine interface {
	Rollback(*Ctx, string, string, io.Writer) (int, error)
}
type PortStatExpectation struct {
	Path           string
	UID, GID, Mode uint32
	Directory      bool
	Links          uint64
	NonEmpty       bool
}

// PortStateChecker is TODO(E2 ExpectStat, ExpectNonEmpty).
type PortStateChecker interface {
	Expect(*Ctx, PortStatExpectation) error
}

// PortTmpfiles is TODO(E2 typed systemd-tmpfiles --create wrapper).
type PortTmpfiles interface{ Create(*Ctx, string) error }
type PortInstalledCheck struct {
	Binary, Output string
	Credential     Cred
}

// PortInstalledChecker is TODO(E2 run-as check): Args must be the constant
// {"--check-installed"}; kernel credentials replace systemd-run. Output must be
// opened before execution through E1, with its path relative to Ctx.State.
type PortInstalledChecker interface {
	CheckInstalled(*Ctx, PortInstalledCheck) error
}

func (fs PortFS) stat(p string) (os.FileInfo, error) {
	if !fs.allowed(p) {
		return nil, errors.New("PORT_PATH_OUTSIDE_ROOTS")
	}
	f, e := portOpenAbsolute(p, unix.O_PATH)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return f.Stat()
}
func (fs PortFS) mkdir(p string) error {
	parent, name, e := fs.parent(p)
	if e != nil {
		return e
	}
	defer parent.Close()
	if e = unix.Mkdirat(int(parent.Fd()), name, 0700); e != nil {
		return e
	}
	fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	dir := os.NewFile(uintptr(fd), name)
	defer dir.Close()
	if e = dir.Chmod(0700); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return e
	}
	return parent.Sync()
}
func portPaths(fs PortFS, paths ...string) error {
	for _, p := range paths {
		if !fs.allowed(p) {
			return errors.New("PORT_PATH_OUTSIDE_ROOTS")
		}
	}
	return nil
}
func portWithin(a, b string) bool { return a == b || strings.HasPrefix(a, b+"/") }
