//go:build linux

package g2run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testExecutor(t *testing.T) *Executor {
	t.Helper()
	x, e := NewExecutor(testPlan().Programs)
	if e != nil {
		t.Fatal(e)
	}
	return x
}

// Claim: a program's non-zero status is returned as its RC, not as an error (the typed operation decides), beside a
// zero-status positive; an argument is passed to the program as one argv element and is never evaluated (a text with
// shell metacharacters comes back verbatim).
func TestExecFixedStatusAndArgv(t *testing.T) {
	x := testExecutor(t)
	if r, e := x.Run(Cmd{Program: "true"}); e != nil || r.RC != 0 {
		t.Fatalf("true: rc=%d e=%v", r.RC, e)
	}
	if r, e := x.Run(Cmd{Program: "false"}); e != nil || r.RC != 1 {
		t.Fatalf("false: rc=%d e=%v", r.RC, e)
	}
	payload := `$(touch /tmp/g2run-never) ; ${x:e} ` + "`id`" + ` a[$(false)] *`
	r, e := x.Run(Cmd{Program: "printf", Args: []string{"%s", payload}})
	if e != nil || r.RC != 0 || string(r.Stdout) != payload {
		t.Fatalf("argv not verbatim: rc=%d out=%q e=%v", r.RC, r.Stdout, e)
	}
	if _, err := os.Stat("/tmp/g2run-never"); err == nil {
		t.Fatal("a substitution in an argument ran")
	}
}

// Claim: the environment is exactly FixedEnv (nothing inherited from the runner) and stdin is /dev/null.
func TestExecFixedEnvAndStdin(t *testing.T) {
	t.Setenv("G2RUN_LEAK", "1")
	x := testExecutor(t)
	r, e := x.Run(Cmd{Program: "printenv"})
	got := strings.Split(strings.TrimSuffix(string(r.Stdout), "\n"), "\n")
	if e != nil || strings.Join(got, "|") != strings.Join(FixedEnv, "|") {
		t.Fatalf("env = %q e=%v", got, e)
	}
	r, e = x.Run(Cmd{Program: "cat"})
	if e != nil || r.RC != 0 || len(r.Stdout) != 0 {
		t.Fatalf("stdin not /dev/null: rc=%d out=%q e=%v", r.RC, r.Stdout, e)
	}
}

// Claim: the output file is opened BEFORE the program starts; a failed open is an error and the program never runs
// (the D28-1 class), beside a positive where the output lands in the file.
func TestExecFixedOutputOpenedFirst(t *testing.T) {
	x := testExecutor(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	_, e := x.Run(Cmd{Program: "touch", Args: []string{marker}, Stdout: filepath.Join(dir, "no-such-dir", "out")})
	if e == nil || !strings.Contains(e.Error(), "EXEC_OUTPUT_OPEN") {
		t.Fatalf("e=%v, want EXEC_OUTPUT_OPEN", e)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program ran although its output could not be opened")
	}
	out := filepath.Join(dir, "out")
	if r, e := x.Run(Cmd{Program: "printf", Args: []string{"%s", "hello"}, Stdout: out}); e != nil || r.RC != 0 {
		t.Fatalf("rc=%d e=%v", r.RC, e)
	}
	if b, _ := os.ReadFile(out); string(b) != "hello" {
		t.Fatalf("out = %q", b)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(out, link)
	if _, e := x.Run(Cmd{Program: "true", Stdout: link}); e == nil {
		t.Fatal("an output path that is a symlink was followed")
	}
}

// Claim: a program outside the table is refused before anything starts, and the table itself refuses interpreters
// and relative paths at construction.
func TestExecFixedTable(t *testing.T) {
	x := testExecutor(t)
	if _, e := x.Run(Cmd{Program: "sh", Args: []string{"-c", "true"}}); e == nil || !strings.Contains(e.Error(), "EXEC_UNKNOWN_PROGRAM") {
		t.Fatalf("e=%v", e)
	}
	for _, bad := range []map[string]string{{"sh": "/bin/sh"}, {"bash": "/usr/bin/bash"}, {"true": "true"}, {"python3": "/usr/bin/python3"}, {"setpriv": "/usr/bin/setpriv"}} {
		if _, e := NewExecutor(bad); e == nil {
			t.Fatalf("table %v accepted", bad)
		}
	}
}

// Claim: Cred runs the program under the given uid and gid with exactly the given groups (kernel setgroups, setgid,
// setuid in the child). Limit: needs root; skipped otherwise.
func TestExecFixedCred(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	x, e := NewExecutor(map[string]string{"id": "/usr/bin/id"})
	if e != nil {
		t.Fatal(e)
	}
	r, e := x.Run(Cmd{Program: "id", Cred: &Cred{UID: 65534, GID: 65534, Groups: []uint32{65534}}})
	if e != nil || r.RC != 0 || !strings.HasPrefix(string(r.Stdout), "uid=65534") {
		t.Fatalf("id: rc=%d out=%q e=%v", r.RC, r.Stdout, e)
	}
}
