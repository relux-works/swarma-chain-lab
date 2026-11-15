//go:build linux

package g2run

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func init() {
	// Test-only registrations: these coreutils stand in for the reviewed wrappers that E2 adds.
	for _, n := range []string{"true", "false", "printf", "printenv", "cat", "touch", "echo", "head", "ls", "yes", "id"} {
		RegisterProgram(n, "test")
	}
}

func testExecutor(t *testing.T) (*Executor, string) {
	t.Helper()
	state := t.TempDir()
	if e := os.Mkdir(filepath.Join(state, "log"), 0700); e != nil {
		t.Fatal(e)
	}
	x, e := NewExecutor(state, testPlan().Programs, []string{"log"})
	if e != nil {
		t.Fatal(e)
	}
	return x, state
}

// Claim: a status outside WantRC is an ERROR by default (fail closed: an op that ignores the result still stops),
// an expected non-zero status is returned as its RC, and an argument reaches the program as one argv element that is
// never evaluated (shell metacharacters come back verbatim).
func TestExecFixedStatusAndArgv(t *testing.T) {
	x, _ := testExecutor(t)
	if r, e := x.Run(Cmd{Program: "true"}); e != nil || r.RC != 0 {
		t.Fatalf("true: rc=%d e=%v", r.RC, e)
	}
	if _, e := x.Run(Cmd{Program: "false"}); e == nil || !strings.Contains(e.Error(), "EXEC_STATUS") {
		t.Fatalf("false without WantRC: e=%v, want EXEC_STATUS", e)
	}
	if r, e := x.Run(Cmd{Program: "false", WantRC: []int{1}}); e != nil || r.RC != 1 {
		t.Fatalf("false with WantRC {1}: rc=%d e=%v", r.RC, e)
	}
	if _, e := x.Run(Cmd{Program: "true", WantRC: []int{1}}); e == nil {
		t.Fatal("true with WantRC {1} was accepted")
	}
	payload := `$(touch /tmp/g2run-never) ; ${x:e} ` + "`id`" + ` a[$(false)] *`
	r, e := x.Run(Cmd{Program: "printf", Args: []string{"%s", payload}})
	if e != nil || string(r.Stdout) != payload {
		t.Fatalf("argv not verbatim: out=%q e=%v", r.Stdout, e)
	}
	if _, err := os.Stat("/tmp/g2run-never"); err == nil {
		t.Fatal("a substitution in an argument ran")
	}
}

// Claim: an operand that could read as an option is refused before anything starts; valid operands follow "--"
// (unless the program takes none), beside the positives.
func TestExecFixedOperands(t *testing.T) {
	x, state := testExecutor(t)
	marker := filepath.Join(state, "ran")
	for _, bad := range []string{"-rf", "--to-command=x", "", "a\nb", "a\x00b"} {
		if _, e := x.Run(Cmd{Program: "touch", Args: []string{marker}, Operands: []string{bad}}); e == nil || !strings.Contains(e.Error(), "EXEC_OPERAND") {
			t.Fatalf("operand %q: e=%v", bad, e)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a program ran although an operand was refused")
	}
	if r, e := x.Run(Cmd{Program: "echo", Operands: []string{"a b"}}); e != nil || string(r.Stdout) != "-- a b\n" {
		t.Fatalf("echo operands: %q %v", r.Stdout, e)
	}
	if r, e := x.Run(Cmd{Program: "echo", Operands: []string{"a b"}, NoDoubleDash: true}); e != nil || string(r.Stdout) != "a b\n" {
		t.Fatalf("echo operands without --: %q %v", r.Stdout, e)
	}
}

// Claim: the environment is exactly FixedEnv (nothing inherited) and stdin is /dev/null.
func TestExecFixedEnvAndStdin(t *testing.T) {
	t.Setenv("G2RUN_LEAK", "1")
	x, _ := testExecutor(t)
	r, e := x.Run(Cmd{Program: "printenv"})
	got := strings.Split(strings.TrimSuffix(string(r.Stdout), "\n"), "\n")
	if e != nil || strings.Join(got, "|") != strings.Join(FixedEnv, "|") {
		t.Fatalf("env = %q e=%v", got, e)
	}
	if r, e = x.Run(Cmd{Program: "cat"}); e != nil || len(r.Stdout) != 0 {
		t.Fatalf("stdin not /dev/null: out=%q e=%v", r.Stdout, e)
	}
}

// Claim: no descriptor of the runner (an open file, as the run.lock flock is) is inherited by a child: the child sees
// only 0, 1, 2 and the descriptor ls opens for the listing itself.
func TestExecFixedNoDescriptorLeak(t *testing.T) {
	x, state := testExecutor(t)
	f, e := os.Create(filepath.Join(state, "held"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	r, e := x.Run(Cmd{Program: "ls", Args: []string{"/proc/self/fd"}})
	if e != nil {
		t.Fatal(e)
	}
	var fds []int
	for _, s := range strings.Fields(string(r.Stdout)) {
		n, _ := strconv.Atoi(s)
		fds = append(fds, n)
	}
	sort.Ints(fds)
	if len(fds) > 4 || fds[len(fds)-1] > 3 {
		t.Fatalf("child descriptors %v (runner held fd %d)", fds, f.Fd())
	}
}

// Claim: output is opened BEFORE the program starts, only beneath a declared root, with no symlink on the way, as a
// private 0600 regular file; every refused target is an error and the program never runs (the D28-1 class and the
// runner-file class), beside a positive.
func TestExecFixedOutput(t *testing.T) {
	x, state := testExecutor(t)
	marker := filepath.Join(state, "ran")
	refused := []string{
		"log/no-such-dir/out", // missing directory
		"/tmp/out",            // absolute
		"log//out",            // not clean
		"log/../DONE",         // escape to a runner file
		"DONE",                // no declared root
		"other/out",           // undeclared root
		"log",                 // the root itself
	}
	for _, out := range refused {
		if _, e := x.Run(Cmd{Program: "touch", Args: []string{marker}, Stdout: out}); e == nil {
			t.Fatalf("output %q accepted", out)
		}
	}
	os.Symlink(filepath.Join(state, "elsewhere"), filepath.Join(state, "log", "link"))
	if _, e := x.Run(Cmd{Program: "touch", Args: []string{marker}, Stdout: "log/link"}); e == nil {
		t.Fatal("a symlinked output was followed")
	}
	os.Mkdir(filepath.Join(state, "real"), 0700)
	os.Rename(filepath.Join(state, "log"), filepath.Join(state, "log.old"))
	os.Symlink(filepath.Join(state, "real"), filepath.Join(state, "log"))
	if _, e := x.Run(Cmd{Program: "touch", Args: []string{marker}, Stdout: "log/out"}); e == nil {
		t.Fatal("a symlinked output root was followed")
	}
	os.Remove(filepath.Join(state, "log"))
	os.Rename(filepath.Join(state, "log.old"), filepath.Join(state, "log"))
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program ran although its output was refused")
	}
	pre := filepath.Join(state, "log", "out")
	os.WriteFile(pre, []byte("old content that is longer"), 0644)
	if _, e := x.Run(Cmd{Program: "printf", Args: []string{"%s", "hello"}, Stdout: "log/out"}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(pre)
	fi, _ := os.Stat(pre)
	if string(b) != "hello" || fi.Mode().Perm() != 0600 {
		t.Fatalf("out = %q mode %v, want hello 0600", b, fi.Mode().Perm())
	}
}

// Claim: a capture over MaxCapture is an error, and an endless producer is stopped (it is not drained forever); the
// run returns within bounded time.
func TestExecFixedCaptureBounded(t *testing.T) {
	x, _ := testExecutor(t)
	if _, e := x.Run(Cmd{Program: "head", Args: []string{"-c", strconv.Itoa(MaxCapture + 1), "/dev/zero"}}); e == nil || !strings.Contains(e.Error(), "EXEC_OUTPUT_TOO_LARGE") {
		t.Fatalf("e=%v", e)
	}
	if r, e := x.Run(Cmd{Program: "head", Args: []string{"-c", strconv.Itoa(MaxCapture), "/dev/zero"}}); e != nil || len(r.Stdout) != MaxCapture {
		t.Fatalf("exactly MaxCapture: len=%d e=%v", len(r.Stdout), e)
	}
	done := make(chan error, 1)
	go func() { _, e := x.Run(Cmd{Program: "yes"}); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("an endless producer was accepted")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("an endless producer was drained without bound")
	}
}

// Claim: the table refuses, at construction, unregistered programs, interpreters, relative paths, links or files
// outside root-owned closed directories, and non-root-owned, set-id or writable files (Limit: as non-root, the owner
// check fires before the set-id one; a root fixture is needed for that branch); and a validated executor cannot be changed through the
// caller's map afterwards.
func TestExecFixedTable(t *testing.T) {
	state := t.TempDir()
	for _, bad := range []map[string]Program{
		{"sh": {"/bin/sh", "x"}}, {"bash": {"/usr/bin/bash", "x"}}, {"true": {"true", "x"}},
		{"python3": {"/usr/bin/python3", "x"}}, {"setpriv": {"/usr/bin/setpriv", "x"}},
		{"dash": {"/usr/bin/dash", "x"}}, {"cp": {"/usr/bin/cp", "x"}}, {"true": {"/usr/bin/true", ""}},
	} {
		if _, e := NewExecutor(state, bad, nil); e == nil {
			t.Fatalf("table %v accepted", bad)
		}
	}
	dir := t.TempDir()
	for name, mode := range map[string]os.FileMode{"suid": 04755, "gwrite": 0775, "mine": 0755} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/true\n"), 0700)
		os.Chmod(p, mode)
		RegisterProgram(name, "test")
		if _, e := NewExecutor(state, map[string]Program{name: {p, "x"}}, nil); e == nil {
			t.Fatalf("%s (%v, owned by uid %d) accepted", name, mode, os.Geteuid())
		}
	}
	link := filepath.Join(dir, "true")
	os.Symlink("/usr/bin/true", link)
	if _, e := NewExecutor(state, map[string]Program{"true": {link, "x"}}, nil); e == nil {
		t.Fatal("a symlinked program accepted")
	}
	table := map[string]Program{"true": {"/usr/bin/true", "x"}}
	x, e := NewExecutor(state, table, nil)
	if e != nil {
		t.Fatal(e)
	}
	table["true"] = Program{"/usr/bin/false", "x"}
	if r, e := x.Run(Cmd{Program: "true"}); e != nil || r.RC != 0 {
		t.Fatalf("the caller's map changed the executor: rc=%d e=%v", r.RC, e)
	}
	if _, e := x.Run(Cmd{Program: "sh", Args: []string{"-c", "true"}}); e == nil || !strings.Contains(e.Error(), "EXEC_UNKNOWN_PROGRAM") {
		t.Fatalf("e=%v", e)
	}
}

// Claim: Cred runs the program under the given uid and gid with exactly the given groups. Limit: needs root; skipped
// otherwise.
func TestExecFixedCred(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	x, e := NewExecutor(t.TempDir(), map[string]Program{"id": {"/usr/bin/id", "x"}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	r, e := x.Run(Cmd{Program: "id", Cred: &Cred{UID: 65534, GID: 65534, Groups: []uint32{65534}}})
	if e != nil || !strings.HasPrefix(string(r.Stdout), "uid=65534") {
		t.Fatalf("id: out=%q e=%v", r.Stdout, e)
	}
}
