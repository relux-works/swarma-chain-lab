//go:build linux

package g2run

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeExec records every command and answers from a script; it stands in for ExecFixed in op tests.
type fakeExec struct {
	calls []Cmd
	reply func(Cmd) (Result, error)
}

func (f *fakeExec) Run(c Cmd) (Result, error) { f.calls = append(f.calls, c); return f.reply(c) }

func ctxWith(t *testing.T, f *fakeExec) *Ctx {
	t.Helper()
	state := t.TempDir()
	os.Mkdir(filepath.Join(state, "log"), 0700)
	return &Ctx{State: state, Step: "T", Purpose: "station", Exec: f, Out: io.Discard}
}

// getentFake answers getent like a host with these passwd and group lines (exit 2 for an unknown name).
func getentFake(passwd, group map[string]string) func(Cmd) (Result, error) {
	return func(c Cmd) (Result, error) {
		if c.Program != "getent" || len(c.Args) != 1 || len(c.Operands) != 1 {
			return Result{}, fmt.Errorf("unexpected %v", c)
		}
		db := map[string]map[string]string{"passwd": passwd, "group": group}[c.Args[0]]
		if l, ok := db[c.Operands[0]]; ok {
			return Result{RC: 0, Stdout: []byte(l + "\n")}, nil
		}
		return Result{RC: 2}, nil
	}
}

// Claim: typed values are parsed once and refused by name; the Opus d30 mode witness and octal-count spellings are
// refused at decode, beside the valid forms.
func TestTypedValues(t *testing.T) {
	for _, ok := range []string{"0755", "755", "0640", "4755", "0000"} {
		if _, e := ParseMode(ok); e != nil {
			t.Fatalf("mode %q refused: %v", ok, e)
		}
	}
	for _, bad := range []string{"700+0*OPTIND[$(cat /x || printf 0)]", "8#700", "0x1ff", "0758", "77777", "", " 755", "-755", "0o755"} {
		if _, e := ParseMode(bad); e == nil || !strings.Contains(e.Error(), "MODE_REFUSED") {
			t.Fatalf("mode %q: e=%v", bad, e)
		}
	}
	if m, _ := ParseMode("0640"); m != 0o640 || m.String() != "0640" {
		t.Fatalf("0640 parsed as %o", m)
	}
	for _, bad := range []string{"010", "08", "1e3", "-1", "", "4294967295", " 5"} {
		if _, e := ParseID(bad); e == nil {
			t.Fatalf("id %q accepted", bad)
		}
	}
	if i, e := ParseID("210201"); e != nil || i != 210201 {
		t.Fatalf("210201: %v %v", i, e)
	}
	for _, bad := range []Path{"rel/x", "/a/../b", "/a//b", "/", "/a\nb"} {
		if bad.Validate() == nil {
			t.Fatalf("path %q accepted", bad)
		}
	}
	for _, bad := range []Name{"-rf", "Root", "a b", "", "a:b"} {
		if bad.Validate() == nil {
			t.Fatalf("name %q accepted", bad)
		}
	}
	for _, bad := range []Unit{"-x.service", "x", "a b.service", "x.service;y"} {
		if bad.Validate() == nil {
			t.Fatalf("unit %q accepted", bad)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("flagValue accepted a value that reads as an option")
		}
	}()
	flagValue("--since", "-1 day")
}

// Claim: account checks pass only on the exact entry (uid, gid, home, gecos, shell; gid and the member SET), refuse
// any difference and an absent account, and pass names only as operands.
func TestAccountOps(t *testing.T) {
	f := &fakeExec{reply: getentFake(
		map[string]string{"swarma-wallet": "swarma-wallet:x:210201:210201:Swarma G2 pay executor:/var/lib/swarma-wallet:/usr/sbin/nologin"},
		map[string]string{"swarma-wallet-peer": "swarma-wallet-peer:x:210101:g2-agent,swarma-wallet"})}
	c := ctxWith(t, f)
	ok := UserExact{Name: "swarma-wallet", UID: 210201, GID: 210201, Home: "/var/lib/swarma-wallet", Gecos: "Swarma G2 pay executor", Shell: "/usr/sbin/nologin"}
	if e := ok.Do(c); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []UserExact{
		{Name: "swarma-wallet", UID: 210202, GID: 210201, Home: "/var/lib/swarma-wallet", Gecos: "Swarma G2 pay executor", Shell: "/usr/sbin/nologin"},
		{Name: "swarma-wallet", UID: 210201, GID: 210201, Home: "/var/lib/swarma-wallet", Gecos: "other", Shell: "/usr/sbin/nologin"},
		{Name: "absent-user", UID: 1, GID: 1, Home: "/", Gecos: "", Shell: "/usr/sbin/nologin"},
	} {
		if bad.Do(c) == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
	if e := (GroupExact{Name: "swarma-wallet-peer", GID: 210101, Members: []Name{"swarma-wallet", "g2-agent"}}).Do(c); e != nil {
		t.Fatal(e)
	}
	if (GroupExact{Name: "swarma-wallet-peer", GID: 210101, Members: []Name{"swarma-wallet"}}).Do(c) == nil {
		t.Fatal("a missing member accepted")
	}
	if (UserExact{Name: "x", Home: "/", Gecos: "a:b", Shell: "/bin/false"}).Validate() == nil {
		t.Fatal("a gecos with ':' accepted")
	}
	for _, call := range f.calls {
		if len(call.Args) != 1 || call.Operands[0] == "" {
			t.Fatalf("name not passed as an operand: %+v", call)
		}
	}
}

// Claim: unit ops send only the enum verb/property as Args and the unit as an operand, and compare the answer exactly.
func TestUnitOps(t *testing.T) {
	f := &fakeExec{reply: func(c Cmd) (Result, error) {
		if c.Args[0] == "show" {
			return Result{Stdout: []byte("0\n")}, nil
		}
		if c.Args[0] == "is-enabled" {
			return Result{Stdout: []byte("disabled\n"), RC: 1}, nil
		}
		return Result{}, nil
	}}
	c := ctxWith(t, f)
	if e := (UnitProperty{"namecoind.service", "MainPID", "0"}).Do(c); e != nil {
		t.Fatal(e)
	}
	if (UnitProperty{"swarma-wallet.service", "is-enabled", "enabled"}).Do(c) == nil {
		t.Fatal("disabled read as enabled")
	}
	if (Systemctl{"restart", "x.service"}).Validate() == nil || (UnitProperty{"x.service", "ExecStart", "y"}).Validate() == nil {
		t.Fatal("an unlisted verb or property accepted")
	}
	if e := (Systemctl{"stop", "namecoind.service"}).Do(c); e != nil {
		t.Fatal(e)
	}
	last := f.calls[len(f.calls)-1]
	if strings.Join(last.Args, " ") != "stop" || strings.Join(last.Operands, " ") != "namecoind.service" {
		t.Fatalf("argv %+v", last)
	}
}

// Claim: a clean node stop is proved from the log written AFTER the stop began (counted by Go, no text count), the
// MainPID and the journal; a log without "Shutdown: done", a SIGKILL in the journal, or a rewritten log each refuse.
func TestStopNodeCleanly(t *testing.T) {
	for _, tc := range []struct {
		name, appended, journal string
		rewrite, ok             bool
	}{
		{"clean", "Shutdown: done\n", "stopped\n", false, true},
		{"no-shutdown-line", "bye\n", "stopped\n", false, false},
		{"sigkill", "Shutdown: done\n", "killed with SIGKILL\n", false, false},
		{"rewritten-log", "Shutdown: done\n", "stopped\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "debug.log")
			os.WriteFile(log, []byte("old Shutdown: done\nrunning\n"), 0600)
			f := &fakeExec{reply: func(c Cmd) (Result, error) {
				switch {
				case c.Program == "systemctl" && c.Args[0] == "stop":
					if tc.rewrite {
						os.WriteFile(log, []byte(tc.appended), 0600)
					} else {
						fh, _ := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
						fh.WriteString(tc.appended)
						fh.Close()
					}
					return Result{}, nil
				case c.Program == "systemctl":
					return Result{Stdout: []byte("0\n")}, nil
				case c.Program == "journalctl":
					return Result{Stdout: []byte(tc.journal)}, nil
				}
				return Result{}, errors.New("unexpected")
			}}
			c := ctxWith(t, f)
			e := (StopNodeCleanly{Unit: "namecoind.service", DebugLog: Path(log), TailOut: "log/tail", JournOut: "log/journal"}).Do(c)
			if (e == nil) != tc.ok {
				t.Fatalf("e=%v want ok=%v", e, tc.ok)
			}
		})
	}
}

// Claim: node RPCs run the pinned CLI under the node's uid/gid with only constant or validated flag Args; the wait
// retries ONLY on exit 28 or synced:false and refuses any other status or a malformed answer at once.
func TestNodeOps(t *testing.T) {
	n := Node{CLI: "/usr/bin/namecoin-cli", UID: 105, GID: 108, Conf: "/etc/namecoin/namecoin.conf", Datadir: "/var/lib/namecoind"}
	answers := []Result{{RC: 28}, {Stdout: []byte(`{"txindex":{"synced":false}}`)}, {Stdout: []byte(`{"txindex":{"synced":true}}`)}}
	f := &fakeExec{reply: func(c Cmd) (Result, error) { r := answers[0]; answers = answers[1:]; return r, nil }}
	c := ctxWith(t, f)
	if e := (NodeSynced{Node: n, Tries: 5}).Do(c); e != nil || len(f.calls) != 3 {
		t.Fatalf("e=%v calls=%d", e, len(f.calls))
	}
	call := f.calls[0]
	if call.Program != "namecoin-cli" || call.Cred == nil || call.Cred.UID != 105 || call.Cred.GID != 108 || !call.NoDoubleDash ||
		call.Args[0] != "-conf=/etc/namecoin/namecoin.conf" || strings.Join(call.Operands, " ") != "getindexinfo txindex" {
		t.Fatalf("argv %+v", call)
	}
	for _, bad := range []Result{{RC: 1}, {Stdout: []byte(`{"txindex":{}}`)}, {Stdout: []byte(`not json`)}} {
		b := bad
		f2 := &fakeExec{reply: func(Cmd) (Result, error) { return b, nil }}
		if (NodeSynced{Node: n, Tries: 5}).Do(ctxWith(t, f2)) == nil || len(f2.calls) != 1 {
			t.Fatalf("%+v was retried or accepted (calls %d)", b, len(f2.calls))
		}
	}
	if (NodeRPC{Node: n, Method: "sendtoaddress", Out: "log/x"}).Validate() == nil {
		t.Fatal("a wallet RPC accepted")
	}
	if (NodeRPC{Node: n, Method: "name_show", Args: []string{"-rpcconnect=1.2.3.4"}, Out: "log/x"}).Validate() == nil {
		t.Fatal("an option-looking RPC argument accepted")
	}
}

// Claim: the route check reads the credential from the wallet config in Go (never a file or a pipe), sends it only to
// 127.0.0.1, and compares the HTTP status exactly; a non-loopback host or an extra member refuses.
func TestRouteCode(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "obs" || p != "secret" || r.Header.Get("content-type") != "text/plain" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(403)
	}))
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	port := l.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	cfg := filepath.Join(dir, "wallet.json")
	os.WriteFile(cfg, []byte(`{"observer":{"host":"127.0.0.1","port":`+strconv.Itoa(port)+`,"username":"obs","password":"secret"}}`), 0600)
	c := ctxWith(t, &fakeExec{})
	if e := (RouteCode{WalletConfig: Path(cfg), Route: "observer", Method: "uptime", Want: 403}).Do(c); e != nil {
		t.Fatal(e)
	}
	if (RouteCode{WalletConfig: Path(cfg), Route: "observer", Method: "uptime", Want: 200}).Do(c) == nil {
		t.Fatal("a different status accepted")
	}
	os.WriteFile(cfg, []byte(`{"observer":{"host":"10.0.0.1","port":1,"username":"obs","password":"secret"}}`), 0600)
	if (RouteCode{WalletConfig: Path(cfg), Route: "observer", Method: "uptime", Want: 403}).Do(c) == nil {
		t.Fatal("a non-loopback route accepted")
	}
	os.WriteFile(cfg, []byte(`{"observer":{"host":"127.0.0.1","port":1,"username":"obs","password":"secret","extra":1}}`), 0600)
	if (RouteCode{WalletConfig: Path(cfg), Route: "observer", Method: "uptime", Want: 403}).Do(c) == nil {
		t.Fatal("an extra route member accepted")
	}
}

// Claim: the file ops compare exactly and refuse symlinks or non-regular files where the step requires a file.
func TestFileOps(t *testing.T) {
	dir := t.TempDir()
	c := ctxWith(t, &fakeExec{reply: getentFake(map[string]string{"me": fmt.Sprintf("me:x:%d:%d::/:/bin/false", os.Getuid(), os.Getgid())},
		map[string]string{"me": fmt.Sprintf("me:x:%d:", os.Getgid())})})
	p := filepath.Join(dir, "f")
	os.WriteFile(p, []byte("x"), 0640)
	if e := (CheckSHA256{Path(p), "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}).Do(c); e != nil {
		t.Fatal(e)
	}
	if (CheckSHA256{Path(p), Hex64(strings.Repeat("0", 64))}).Do(c) == nil {
		t.Fatal("a wrong digest accepted")
	}
	os.Symlink(p, filepath.Join(dir, "link"))
	if (CheckSHA256{Path(filepath.Join(dir, "link")), "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}).Do(c) == nil {
		t.Fatal("a symlink was followed")
	}
	if e := (ExpectStat{Path(p), "me", "me", 0o640, 1, 1}).Do(c); e != nil {
		t.Fatal(e)
	}
	if (ExpectStat{Path(p), "me", "me", 0o600, 1, 1}).Do(c) == nil {
		t.Fatal("a wrong mode accepted")
	}
	if e := (ExpectPath{Path(filepath.Join(dir, "none")), "absent"}).Do(c); e != nil {
		t.Fatal(e)
	}
	if (ExpectPath{Path(filepath.Join(dir, "link")), "absent"}).Do(c) == nil {
		t.Fatal("a symlink read as absent")
	}
	os.WriteFile(filepath.Join(dir, "h"), []byte("#!/usr/bin/python3.14 -I\nrest\n"), 0600)
	if e := (ExpectFirstLine{Path(filepath.Join(dir, "h")), "#!/usr/bin/python3.14 -I"}).Do(c); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "acc"), []byte("passwd 210001: \ngroup 210101: \n"), 0600)
	re := regexp.MustCompile(`^(passwd|group|user) [^:]+: .`)
	if e := (ExpectNoMatch{Path(filepath.Join(dir, "acc")), re}).Do(c); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "acc2"), []byte("passwd 210001: g2-agent\n"), 0600)
	if (ExpectNoMatch{Path(filepath.Join(dir, "acc2")), re}).Do(c) == nil {
		t.Fatal("a present reserved id accepted")
	}
	os.WriteFile(filepath.Join(dir, "unit.in"), []byte("ExecStart=/opt/x/@VERSION@/bin\n"), 0600)
	if e := (RenderVersion{"0123456789ab", Path(filepath.Join(dir, "unit.in")), Path(filepath.Join(dir, "unit"))}).Do(c); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "unit")); string(b) != "ExecStart=/opt/x/0123456789ab/bin\n" {
		t.Fatalf("render = %q", b)
	}
	if (RenderVersion{"0/e touch x", Path(filepath.Join(dir, "unit.in")), Path(filepath.Join(dir, "u2"))}).Validate() == nil {
		t.Fatal("a non-hex version accepted")
	}
	tree := filepath.Join(dir, "tree")
	os.MkdirAll(filepath.Join(tree, "a"), 0700)
	os.WriteFile(filepath.Join(tree, "x"), []byte("1"), 0600)
	os.WriteFile(filepath.Join(tree, "a", "y"), []byte("2"), 0600)
	if e := (TreeSHA256{Path(tree), Path(filepath.Join(dir, "tree.sha")), 2}).Do(c); e != nil {
		t.Fatal(e)
	}
	if (TreeSHA256{Path(tree), Path(filepath.Join(dir, "tree.sha2")), 3}).Do(c) == nil {
		t.Fatal("a wrong count accepted")
	}
	os.Symlink("/etc/passwd", filepath.Join(tree, "a", "z"))
	if (TreeSHA256{Path(tree), Path(filepath.Join(dir, "tree.sha3")), 2}).Do(c) == nil {
		t.Fatal("a symlink in the tree accepted")
	}
}

// Claim: the ledger ops call the ledger in-process with exactly "-flag=value" arguments built from typed fields
// (no process started), and refuse malformed fields before the call.
func TestLedgerOps(t *testing.T) {
	var got [][]string
	old := ledgerRun
	ledgerRun = func(args []string, out *bytes.Buffer) error { got = append(got, args); return nil }
	defer func() { ledgerRun = old }()
	c := ctxWith(t, &fakeExec{reply: func(Cmd) (Result, error) { t.Fatal("a ledger op started a process"); return Result{}, nil }})
	ops := []Op{
		CreateGroup{"swarma-wallet", 210201, "d6"},
		CreateUser{"g2-agent", 210001, 210001, "/", "", "/usr/sbin/nologin", "service", "d6"},
		CreateDir{"/etc/swarma/wallet", "root", "swarma-wallet", 0o750, "d6"},
		CreateKey{"/root/g2/release/bin/deploy-kit", "/etc/swarma/wallet/receipt.key", "root", "swarma-wallet", 0o640, "d6"},
		Enable{"swarma-wallet.service"},
	}
	for _, op := range ops {
		if e := op.Validate(); e != nil {
			t.Fatalf("%s: %v", op.Kind(), e)
		}
		if e := op.Do(c); e != nil {
			t.Fatal(e)
		}
	}
	ld := "-dir=" + filepath.Join(c.State, "ledger")
	want := []string{
		"create-group " + ld + " -name=swarma-wallet -gid=210201 -ret=d6",
		"create-user " + ld + " -name=g2-agent -uid=210001 -gid=210001 -home=/ -gecos= -shell=/usr/sbin/nologin -role=service -ret=d6",
		"create-dir " + ld + " -path=/etc/swarma/wallet -owner=root -group=swarma-wallet -mode=0750 -ret=d6",
		"exec-create " + ld + " -kind=secret -ret=d6 -path=/etc/swarma/wallet/receipt.key -- /root/g2/release/bin/deploy-kit g2-keygen -out=/etc/swarma/wallet/receipt.key -mode=0640 -owner=root -group=swarma-wallet",
		"enable " + ld + " -unit=swarma-wallet.service",
	}
	for i, w := range want {
		if strings.Join(got[i], " ") != w {
			t.Fatalf("call %d:\n got %s\nwant %s", i, strings.Join(got[i], " "), w)
		}
	}
	for _, bad := range []Op{
		CreateGroup{"-x", 1, "d6"}, CreateGroup{"g", 1, "keep"}, CreateDir{"rel", "root", "root", 0o755, "d6"},
		CreateUser{"u", 1, 1, "/", "a:b", "/usr/sbin/nologin", "service", "d6"}, CreateUser{"u", 1, 1, "/", "", "/usr/sbin/nologin", "admin", "d6"},
		Enable{"-x.service"},
	} {
		if bad.Validate() == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
}

// Claim: Stdin streams a Go reader to the program, and Timeout kills the whole process group and reports
// EXEC_TIMEOUT within bounded time.
func TestExecFixedStdinAndTimeout(t *testing.T) {
	RegisterProgram("sleep", "test")
	state := t.TempDir()
	os.Mkdir(filepath.Join(state, "log"), 0700)
	x, e := NewExecutor(state, map[string]Program{"cat": {"/usr/bin/cat", "t"}, "sleep": {"/usr/bin/sleep", "t"}}, []string{"log"})
	if e != nil {
		t.Fatal(e)
	}
	if r, e := x.Run(Cmd{Program: "cat", Stdin: []byte("abc")}); e != nil || string(r.Stdout) != "abc" {
		t.Fatalf("stdin: %q %v", r.Stdout, e)
	}
	// A command without Stdin never inherits the runner's stdin: with data waiting on our own stdin, cat reads nothing.
	pr, pw, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	pw.Write([]byte("inherited"))
	pw.Close()
	saved, e := unix.Dup(0)
	if e != nil {
		t.Fatal(e)
	}
	unix.Dup2(int(pr.Fd()), 0) // our own fd 0 now has data waiting
	r, e := x.Run(Cmd{Program: "cat"})
	unix.Dup2(saved, 0)
	unix.Close(saved)
	pr.Close()
	if e != nil || len(r.Stdout) != 0 {
		t.Fatalf("a stdin-less command read %q (e=%v)", r.Stdout, e)
	}
	start := time.Now()
	_, e = x.Run(Cmd{Program: "sleep", Args: []string{"30"}, Timeout: time.Second})
	if e == nil || !strings.Contains(e.Error(), "EXEC_TIMEOUT") || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout: e=%v after %v", e, time.Since(start))
	}
}

// Claim: the age backup builds the archive in memory from regular files and directories only (a symlink is refused),
// passes it as bounded stdin with constant flags, refuses an existing output, and removes a partial output when age
// fails; beside a positive whose archive holds exactly the named entries.
func TestAgeBackup(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc", "k"), 0700)
	os.WriteFile(filepath.Join(dir, "etc", "k", "agent.key"), []byte("K1"), 0600)
	os.WriteFile(filepath.Join(dir, "etc", "receipt.key"), []byte("K2"), 0600)
	out := filepath.Join(t.TempDir(), "keys.age")
	rcpt := "age12d7jwv4wjxfg34fqvhcattfn4xkkscz79hfeq8ca9454x73n6u6sdvs3f6"
	var seen Cmd
	f := &fakeExec{reply: func(c Cmd) (Result, error) { seen = c; os.WriteFile(out, []byte("cipher"), 0600); return Result{}, nil }}
	op := AgeBackup{Out: Path(out), Recipient: rcpt, Dir: Path(dir), Paths: []string{"etc/k", "etc/receipt.key"}}
	if e := op.Validate(); e != nil {
		t.Fatal(e)
	}
	if e := op.Do(ctxWith(t, f)); e != nil {
		t.Fatal(e)
	}
	if seen.Program != "age" || strings.Join(seen.Args, " ") != "--recipient="+rcpt+" --output="+out || len(seen.Stdin) == 0 {
		t.Fatalf("cmd %+v", seen)
	}
	var names []string
	tr := tar.NewReader(bytes.NewReader(seen.Stdin))
	for {
		h, e := tr.Next()
		if e != nil {
			break
		}
		names = append(names, h.Name)
	}
	if strings.Join(names, ",") != "etc/k/,etc/k/agent.key,etc/receipt.key" {
		t.Fatalf("archive entries %v", names)
	}
	if op.Do(ctxWith(t, f)) == nil {
		t.Fatal("an existing output was overwritten")
	}
	os.Remove(out)
	fail := &fakeExec{reply: func(Cmd) (Result, error) {
		os.WriteFile(out, []byte("partial"), 0600)
		return Result{}, errors.New("age failed")
	}}
	if op.Do(ctxWith(t, fail)) == nil {
		t.Fatal("a failed age run accepted")
	}
	if _, e := os.Lstat(out); e == nil {
		t.Fatal("a partial output was left behind")
	}
	os.Symlink("/etc/passwd", filepath.Join(dir, "etc", "k", "link"))
	if (AgeBackup{Out: Path(out + "2"), Recipient: rcpt, Dir: Path(dir), Paths: []string{"etc/k"}}).Do(ctxWith(t, f)) == nil {
		t.Fatal("a symlink was archived")
	}
	for _, bad := range []AgeBackup{
		{Out: Path(out), Recipient: "age1short", Dir: Path(dir), Paths: []string{"etc"}},
		{Out: Path(out), Recipient: rcpt, Dir: Path(dir), Paths: []string{"../etc"}},
		{Out: Path(out), Recipient: rcpt, Dir: Path(dir), Paths: nil},
	} {
		if bad.Validate() == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
}
