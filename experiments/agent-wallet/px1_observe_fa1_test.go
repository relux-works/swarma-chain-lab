package wallet

// PX1 stream S3 tests for the freeze amendment 1 migration, step A (A8: the
// operator status socket in its own directory). Owner S3.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// px1oAgentSocketPath is the W2 agent socket of the deploy templates: the only
// socket in /run/swarma-wallet, the directory bound into an agent slot.
const px1oAgentSocketPath = "/run/swarma-wallet/wallet.sock"

// px1oPrepStatusDir gives dir the A8 status directory shape that this
// unprivileged test can make: owner this UID, group this GID, mode 0750.
func px1oPrepStatusDir(t *testing.T, dir string) {
	t.Helper()
	if e := os.Chown(dir, -1, os.Getgid()); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, StatusSocketDirMode); e != nil {
		t.Fatal(e)
	}
}

// px1oStatusTestDir is a short private directory in the A8 status shape.
func px1oStatusTestDir(t *testing.T) string {
	t.Helper()
	dir := px1oShortDir(t)
	px1oPrepStatusDir(t, dir)
	return dir
}

// px1oMkStatusDir creates dir (and its parents) in the A8 status shape.
func px1oMkStatusDir(t *testing.T, dir string) string {
	t.Helper()
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	px1oPrepStatusDir(t, dir)
	return dir
}

// Claim (A8): the listener binds only in the status socket's own directory: a
// real directory reached without a symlink, mode 0750, with the operator
// group, that neither is, contains, nor lies inside the agent socket's
// directory. Every other shape refuses STATUS_SOCKET_DIR and leaves no socket
// behind. Valid neighbours: the same directories in the right shape bind a
// 0660 socket with the operator group, including a "-status" sibling of the
// agent directory. Limit: this unprivileged test cannot make a directory owned
// by another UID, so the owner branch is not exercised here.
func TestPX1oStatusSocketDir(t *testing.T) {
	saved := px1oAgentGroups
	t.Cleanup(func() { px1oAgentGroups = saved })
	px1oAgentGroups = func(uint32) ([]string, error) { return nil, nil }
	gid := uint32(os.Getgid())
	access := func(operatorGID uint32, agentSocket string) px1oStatusAccess {
		return px1oStatusAccess{operatorGID: operatorGID, agentGID: operatorGID + 1, agentUID: 65534, agentSocket: agentSocket}
	}
	type layout struct {
		path   string
		access px1oStatusAccess
	}
	valid := map[string]func() layout{
		"own-directory": func() layout {
			return layout{filepath.Join(px1oStatusTestDir(t), "status.sock"), access(gid, px1oAgentSocketPath)}
		},
		"status-sibling": func() layout {
			base := px1oShortDir(t)
			px1oMkStatusDir(t, filepath.Join(base, "w"))
			dir := px1oMkStatusDir(t, filepath.Join(base, "w-status"))
			return layout{filepath.Join(dir, "status.sock"), access(gid, filepath.Join(base, "w", "wallet.sock"))}
		},
	}
	for name, mk := range valid {
		l := mk()
		ln, e := px1oListenStatus(l.path, l.access)
		if e != nil {
			t.Fatalf("STATUS_DIR_VALID_REFUSED %s: %v", name, e)
		}
		i, e := os.Lstat(l.path)
		st, ok := i.Sys().(*syscall.Stat_t)
		if e != nil || i.Mode().Perm() != StatusSocketMode || !ok || st.Gid != gid {
			t.Fatalf("STATUS_DIR_VALID_REFUSED %s: socket shape %v", name, e)
		}
		ln.Close()
	}
	chmod := func(mode os.FileMode) func() layout {
		return func() layout {
			dir := px1oStatusTestDir(t)
			if e := os.Chmod(dir, mode); e != nil {
				t.Fatal(e)
			}
			return layout{filepath.Join(dir, "status.sock"), access(gid, px1oAgentSocketPath)}
		}
	}
	refused := map[string]func() layout{
		"mode-0700": chmod(0o700),
		"mode-0751": chmod(0o751),
		"mode-0755": chmod(0o755),
		"mode-0770": chmod(0o770),
		"foreign-group": func() layout {
			return layout{filepath.Join(px1oStatusTestDir(t), "status.sock"), access(3999998, px1oAgentSocketPath)}
		},
		"missing": func() layout {
			return layout{filepath.Join(px1oShortDir(t), "absent", "status.sock"), access(gid, px1oAgentSocketPath)}
		},
		"not-a-directory": func() layout {
			file := filepath.Join(px1oShortDir(t), "f")
			if e := os.WriteFile(file, nil, 0600); e != nil {
				t.Fatal(e)
			}
			return layout{filepath.Join(file, "status.sock"), access(gid, px1oAgentSocketPath)}
		},
		"final-symlink": func() layout {
			base := px1oShortDir(t)
			real := px1oMkStatusDir(t, filepath.Join(base, "real"))
			if e := os.Symlink(real, filepath.Join(base, "link")); e != nil {
				t.Fatal(e)
			}
			return layout{filepath.Join(base, "link", "status.sock"), access(gid, px1oAgentSocketPath)}
		},
		"ancestor-symlink": func() layout {
			base := px1oShortDir(t)
			px1oMkStatusDir(t, filepath.Join(base, "real", "sub"))
			if e := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "alink")); e != nil {
				t.Fatal(e)
			}
			return layout{filepath.Join(base, "alink", "sub", "status.sock"), access(gid, px1oAgentSocketPath)}
		},
		"agent-same-dir": func() layout {
			dir := px1oStatusTestDir(t)
			return layout{filepath.Join(dir, "status.sock"), access(gid, filepath.Join(dir, "wallet.sock"))}
		},
		"status-inside-agent-dir": func() layout {
			base := px1oStatusTestDir(t)
			dir := px1oMkStatusDir(t, filepath.Join(base, "s"))
			return layout{filepath.Join(dir, "status.sock"), access(gid, filepath.Join(base, "wallet.sock"))}
		},
		"agent-inside-status-dir": func() layout {
			dir := px1oStatusTestDir(t)
			return layout{filepath.Join(dir, "status.sock"), access(gid, filepath.Join(dir, "slot", "wallet.sock"))}
		},
	}
	for name, mk := range refused {
		l := mk()
		ln, e := px1oListenStatus(l.path, l.access)
		if e == nil {
			ln.Close()
		}
		if e == nil || e.Error() != "STATUS_SOCKET_DIR" {
			t.Errorf("STATUS_DIR_ACCEPTED %s: got %v, want STATUS_SOCKET_DIR", name, e)
		}
		if _, le := os.Lstat(l.path); le == nil && e != nil {
			t.Errorf("STATUS_DIR_ACCEPTED %s: a refused start left a socket behind", name)
		}
	}
}

// Claim (A8): RunPX1Observers binds only the frozen StatusSocketPath. The old
// /run/swarma-wallet/status.sock, another name in the status directory, a
// non-clean spelling, a relative path and the directory itself refuse
// STATUS_SOCKET_CONFIG before the profile check and the startup pass. Valid
// neighbours: no socket ("") and StatusSocketPath itself pass the path check
// and stop at SERVICE_PROFILE on a service without a G2 profile. Limit: the
// bind at StatusSocketPath itself needs /run and is T18 host work.
func TestPX1oRunObserversStatusPath(t *testing.T) {
	s := &ActionService{}
	for _, p := range []string{"/run/swarma-wallet/status.sock", "/run/swarma-wallet-status/other.sock", "/run/swarma-wallet-status/../swarma-wallet-status/status.sock", "run/swarma-wallet-status/status.sock", StatusSocketDir} {
		if _, e := s.RunPX1Observers(context.Background(), p, 1000, time.Second, nil); e == nil || e.Error() != "STATUS_SOCKET_CONFIG" {
			t.Errorf("STATUS_PATH_NOT_FROZEN %s accepted: %v", p, e)
		}
	}
	for _, p := range []string{"", StatusSocketPath} {
		if _, e := s.RunPX1Observers(context.Background(), p, 1000, time.Second, nil); e == nil || e.Error() != "SERVICE_PROFILE" {
			t.Errorf("STATUS_PATH_FROZEN_REFUSED %q: %v", p, e)
		}
	}
}

// Claim (A8): when its context ends, the status listener returns only after
// its socket path is unlinked, so a clean stop leaves no stale status.sock in
// the tmpfiles directory (which is not removed on stop) and the next start
// binds again. Valid neighbour: while it runs, the socket exists and serves.
// Limit: the daemon's wait for this return (cmd/agent-walletd) is not
// exercised by a unit test.
func TestPX1oStatusListenerUnlinksOnStop(t *testing.T) {
	saved := px1oAgentGroups
	t.Cleanup(func() { px1oAgentGroups = saved })
	px1oAgentGroups = func(uint32) ([]string, error) { return nil, nil }
	gid := uint32(os.Getgid())
	path := filepath.Join(px1oStatusTestDir(t), "status.sock")
	a := px1oStatusAccess{operatorGID: gid, agentGID: gid + 1, agentUID: 65534, agentSocket: px1oAgentSocketPath}
	for round := 0; round < 2; round++ {
		l, e := px1oListenStatus(path, a)
		if e != nil {
			t.Fatalf("STALE_STATUS_SOCKET: start %d refused: %v", round, e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- px1oServeStatusListener(ctx, l, 65534, func() (StatusProjectionV1, error) { return px1StatusFixture(), nil })
		}()
		if _, e := ReadPX1Status(context.Background(), path); e != nil {
			t.Fatalf("running listener did not serve: %v", e)
		}
		cancel()
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatalf("STALE_STATUS_SOCKET: the socket survived the stop of round %d: %v", round, e)
		}
	}
}

// px1oDocA8Problems lists the A8 violations in the S3 docs: the old status
// path anywhere; in the SERVICE.md G2 section, a missing drop-in or directory
// line, any sysusers member line of swarma-wallet-peer for an account other
// than the service or the agent, an agent member line of
// swarma-wallet-status, and an access table that puts the operator into
// swarma-wallet-peer or the agent into the operator group; and a STATUS.md
// that does not name StatusSocketPath.
func px1oDocA8Problems(service, status string) []string {
	var out []string
	if strings.Contains(service, "/run/swarma-wallet/status.sock") || strings.Contains(status, "/run/swarma-wallet/status.sock") {
		out = append(out, "OLD_STATUS_PATH")
	}
	if !strings.Contains(status, StatusSocketPath) {
		out = append(out, "STATUS_DOC_PATH")
	}
	start := strings.Index(service, "## G2 operations (PX1)")
	if start < 0 {
		return append(out, "DROPIN_MISSING G2 section")
	}
	g2 := service[start:]
	if end := strings.Index(g2[1:], "\n## "); end >= 0 {
		g2 = g2[:end+1]
	}
	for _, want := range []string{
		"\nSupplementaryGroups=swarma-wallet swarma-wallet-status\n",
		"\nReadWritePaths=" + StatusSocketDir + "\n",
		" -status-socket " + StatusSocketPath + " -status-gid @OPERATOR_GID@\n",
		"\nd " + StatusSocketDir + " 0750 swarma-wallet swarma-wallet-status -\n",
		"\nm @OPERATOR_USER@ swarma-wallet-status\n",
	} {
		if !strings.Contains(g2, want) {
			out = append(out, "DROPIN_MISSING "+strings.TrimSpace(want))
		}
	}
	operatorRows := 0
	for _, line := range strings.Split(g2, "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "m" {
			if f[2] == "swarma-wallet-peer" && f[1] != "swarma-wallet" && f[1] != "<agent_user>" && f[1] != "@AGENT_USER@" {
				out = append(out, "OPERATOR_PEER_MEMBER line "+line)
			}
			if f[2] == "swarma-wallet-status" && (f[1] == "<agent_user>" || f[1] == "@AGENT_USER@") {
				out = append(out, "AGENT_STATUS_MEMBER line "+line)
			}
		}
		cells := strings.Split(line, "|")
		if len(cells) < 5 {
			continue
		}
		who, peer, status := strings.TrimSpace(cells[1]), strings.Trim(strings.TrimSpace(cells[2]), "*"), strings.Trim(strings.TrimSpace(cells[3]), "*")
		switch {
		case who == "operator user":
			operatorRows++
			if peer != "never" || status != "member" {
				out = append(out, "OPERATOR_PEER_MEMBER table "+line)
			}
		case strings.HasPrefix(who, "agent") && status != "never":
			out = append(out, "AGENT_STATUS_MEMBER table "+line)
		}
	}
	if operatorRows != 1 {
		out = append(out, "OPERATOR_PEER_MEMBER table rows")
	}
	return out
}

// Claim (A8): the SERVICE.md G2 section and STATUS.md follow the amendment:
// the drop-in keeps the operator group as a supplementary group, makes the
// status directory writable and binds the frozen StatusSocketPath; the status
// directory line is 0750 with the operator group; no documented sysusers line
// or access-table row puts the operator into swarma-wallet-peer (the operator
// is a member of swarma-wallet-status only) or the agent into the operator
// group; neither doc names the old status path; STATUS.md names the new one.
// The checker is controlled on a minimal good text (no finding) and on one
// mutation per rule, each of which it must flag.
func TestPX1oServiceDocDropIn(t *testing.T) {
	service, e := os.ReadFile("SERVICE.md")
	if e != nil {
		t.Fatal(e)
	}
	status, e := os.ReadFile("STATUS.md")
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range px1oDocA8Problems(string(service), string(status)) {
		t.Errorf("SERVICE_DOC_A8 %s", p)
	}
	good := "## G2 operations (PX1)\n" + strings.Join([]string{
		"| agent (`peer_uid`) | member | never | `wallet.sock` only |",
		"| operator user | never | member | `status.sock` only |",
		"g swarma-wallet-status @OPERATOR_GID@",
		"m @OPERATOR_USER@ swarma-wallet-status",
		"d /run/swarma-wallet-status 0750 swarma-wallet swarma-wallet-status -",
		"SupplementaryGroups=swarma-wallet swarma-wallet-status",
		"ReadWritePaths=/run/swarma-wallet-status",
		"ExecStart=agent-walletd -status-socket /run/swarma-wallet-status/status.sock -status-gid @OPERATOR_GID@",
	}, "\n") + "\n\n## Next\n"
	goodStatus := "`/run/swarma-wallet-status/status.sock`"
	if p := px1oDocA8Problems(good, goodStatus); len(p) != 0 {
		t.Fatalf("doc checker refuses a good text: %v", p)
	}
	for _, c := range []struct{ old, new, status, want string }{
		{"| operator user | never | member |", "| operator user | member | member |", goodStatus, "OPERATOR_PEER_MEMBER"},
		{"m @OPERATOR_USER@ swarma-wallet-status\n", "m @OPERATOR_USER@ swarma-wallet-status\nm @OPERATOR_USER@ swarma-wallet-peer\n", goodStatus, "OPERATOR_PEER_MEMBER"},
		{"| agent (`peer_uid`) | member | never |", "| agent (`peer_uid`) | member | member |", goodStatus, "AGENT_STATUS_MEMBER"},
		{"g swarma-wallet-status @OPERATOR_GID@\n", "g swarma-wallet-status @OPERATOR_GID@\nm <agent_user> swarma-wallet-status\n", goodStatus, "AGENT_STATUS_MEMBER"},
		{"-status-socket /run/swarma-wallet-status/status.sock", "-status-socket /run/swarma-wallet/status.sock", goodStatus, "OLD_STATUS_PATH"},
		{"ReadWritePaths=/run/swarma-wallet-status\n", "", goodStatus, "DROPIN_MISSING"},
		{"SupplementaryGroups=swarma-wallet swarma-wallet-status\n", "SupplementaryGroups=swarma-wallet\n", goodStatus, "DROPIN_MISSING"},
		{"0750 swarma-wallet swarma-wallet-status", "0750 swarma-wallet swarma-wallet-peer", goodStatus, "DROPIN_MISSING"},
		{"", "", "`/run/swarma-wallet/status.sock`", "OLD_STATUS_PATH"},
	} {
		bad := strings.Replace(good, c.old, c.new, 1)
		if c.old != "" && bad == good {
			t.Fatalf("control %q not applied", c.old)
		}
		found := false
		for _, p := range px1oDocA8Problems(bad, c.status) {
			found = found || strings.HasPrefix(p, c.want)
		}
		if !found {
			t.Errorf("doc checker missed %s for %q", c.want, c.new+c.status)
		}
	}
}
