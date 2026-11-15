//go:build linux

package g2run

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// ---- a small compiled plan for the tests -----------------------------------------------------------------------------

type testParams struct {
	Name string `json:"name"`
}

// markOp writes STATE/marks/<name>; failOp fails; panicOp panics; badOp fails its validation.
type markOp struct{ name string }

func (o markOp) Kind() string    { return "mark" }
func (o markOp) Validate() error { return nil }
func (o markOp) Do(c *Ctx) error {
	return os.WriteFile(filepath.Join(c.State, "marks", o.name), nil, 0600)
}

type failOp struct{}

func (failOp) Kind() string    { return "fail" }
func (failOp) Validate() error { return nil }
func (failOp) Do(*Ctx) error   { return errors.New("planted failure") }

type panicOp struct{}

func (panicOp) Kind() string    { return "panic" }
func (panicOp) Validate() error { return nil }
func (panicOp) Do(*Ctx) error   { panic("planted panic") }

type badOp struct{}

func (badOp) Kind() string    { return "bad" }
func (badOp) Validate() error { return errors.New("MODE_REFUSED") }
func (badOp) Do(*Ctx) error   { return nil }

func marks(names ...string) func(testParams) []Op {
	return func(testParams) []Op {
		var ops []Op
		for _, n := range names {
			ops = append(ops, markOp{n})
		}
		return ops
	}
}

func testPlan() Plan[testParams] {
	return Plan[testParams]{
		BootstrapLine: "OK B.1",
		Sequences: map[string][]string{
			"station":   {"A1", "A2", "A3"},
			"rehearsal": {"A1", "R2"},
		},
		Recovery: []RecoveryRule{
			{Step: "ABORT", AfterStop: true},
			{Step: "ROLLBACK", Purpose: "station", AfterStop: true, AfterLast: []string{"A3", "ROLLBACK"}},
			{Step: "R", Purpose: "station", AfterLast: []string{"ROLLBACK"}},
		},
		Steps: map[string]func(testParams) []Op{
			"A1": marks("A1"), "A2": marks("A2"), "A3": marks("A3"), "R2": marks("R2"),
			"ABORT": marks("ABORT"), "ROLLBACK": marks("ROLLBACK"), "R": marks("R"),
		},
		Programs:     map[string]string{"true": "/usr/bin/true", "false": "/usr/bin/false", "printf": "/usr/bin/printf", "printenv": "/usr/bin/printenv", "cat": "/usr/bin/cat", "touch": "/usr/bin/touch"},
		PackageFiles: []string{"params.json"},
		ParamsFile:   "params.json",
		Decode: func(raw []byte) (testParams, error) {
			var p testParams
			if e := StrictJSON(raw, &p); e != nil {
				return p, e
			}
			if p.Name == "" {
				return p, errors.New("NAME_EMPTY")
			}
			return p, nil
		},
	}
}

// ---- the fixture: a state directory as the bootstrap leaves it --------------------------------------------------------

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func buildPackage(t *testing.T, state string, files map[string]string) {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, n := range names {
		fmt.Fprintf(&sums, "%s  %s\n", sha([]byte(files[n])), n)
	}
	var tb bytes.Buffer
	gz := gzip.NewWriter(&tb)
	tw := tar.NewWriter(gz)
	add := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	add("SHA256SUMS", sums.String())
	for _, n := range names {
		add(n, files[n])
	}
	tw.Close()
	gz.Close()
	must(t, os.MkdirAll(filepath.Join(state, "pkg"), 0700))
	for _, n := range names {
		must(t, os.WriteFile(filepath.Join(state, "pkg", n), []byte(files[n]), 0600))
	}
	must(t, os.WriteFile(filepath.Join(state, "pkg", "SHA256SUMS"), []byte(sums.String()), 0600))
	must(t, os.WriteFile(filepath.Join(state, "package.tar.gz"), tb.Bytes(), 0600))
	must(t, os.WriteFile(filepath.Join(state, "PKG_SHA256"), []byte(sha(tb.Bytes())+"\n"), 0600))
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

func fixture(t *testing.T) string {
	t.Helper()
	state := filepath.Join(t.TempDir(), "g2")
	must(t, os.MkdirAll(filepath.Join(state, "marks"), 0700))
	must(t, os.WriteFile(filepath.Join(state, "run.lock"), nil, 0600))
	must(t, os.WriteFile(filepath.Join(state, "DONE"), []byte("OK B.1\n"), 0600))
	buildPackage(t, state, map[string]string{"params.json": `{"name":"x"}`})
	return state
}

func runStep(t *testing.T, plan Plan[testParams], state, step string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := Main(plan, []string{"-state", state, step}, &out, &errb)
	return rc, out.String() + errb.String()
}

// snapshot is every name, type, mode, size and content digest under the state directory.
func snapshot(t *testing.T, state string) string {
	t.Helper()
	var b strings.Builder
	filepath.Walk(state, func(p string, fi os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		fmt.Fprintf(&b, "%s %v %d", strings.TrimPrefix(p, state), fi.Mode(), fi.Size())
		if fi.Mode().IsRegular() {
			c, _ := os.ReadFile(p)
			b.WriteString(" " + sha(c)[:12])
		}
		b.WriteString("\n")
		return nil
	})
	return b.String()
}

func setState(t *testing.T, state, purpose string, done ...string) {
	t.Helper()
	for _, n := range []string{"STOPPED", "CLOSED", "PURPOSE"} {
		os.Remove(filepath.Join(state, n))
	}
	os.RemoveAll(filepath.Join(state, "INFLIGHT"))
	content := "OK B.1\n"
	for _, d := range done {
		content += "OK " + d + "\n"
	}
	must(t, os.WriteFile(filepath.Join(state, "DONE"), []byte(content), 0600))
	if purpose != "" {
		must(t, os.WriteFile(filepath.Join(state, "PURPOSE"), []byte(purpose+"\n"), 0600))
	}
}

// Claim: the compiled test plan is valid, and INIT then every step of the sequence runs in order, each recorded once,
// with no STOP and no INFLIGHT left (the sequence positive every refusal below is set against).
func TestSequencePositive(t *testing.T) {
	plan := testPlan()
	must(t, plan.Validate())
	state := fixture(t)
	for _, s := range []string{"INIT-station", "A1", "A2", "A3"} {
		if rc, out := runStep(t, plan, state, s); rc != 0 {
			t.Fatalf("%s rc=%d %s", s, rc, out)
		}
	}
	done, _ := os.ReadFile(filepath.Join(state, "DONE"))
	if string(done) != "OK B.1\nOK INIT-station\nOK A1\nOK A2\nOK A3\n" {
		t.Fatalf("DONE = %q", done)
	}
	purpose, _ := os.ReadFile(filepath.Join(state, "PURPOSE"))
	if string(purpose) != "station\n" || exists(filepath.Join(state, "STOPPED")) || exists(filepath.Join(state, "INFLIGHT")) {
		t.Fatalf("end state: purpose=%q stopped=%v inflight=%v", purpose, exists(filepath.Join(state, "STOPPED")), exists(filepath.Join(state, "INFLIGHT")))
	}
	for _, m := range []string{"A1", "A2", "A3"} {
		if !exists(filepath.Join(state, "marks", m)) {
			t.Fatalf("mark %s missing", m)
		}
	}
}

// Claim: every refusal before admission returns its own code and leaves the state directory byte-identical (nothing
// ran, nothing recorded). Each case sets up exactly one defect beside the positive above.
func TestRefusalsChangeNothing(t *testing.T) {
	plan := testPlan()
	cases := []struct {
		name string
		want int
		prep func(t *testing.T, state string) (args []string)
	}{
		{"arity", 64, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			return []string{"-state", s}
		}},
		{"relative-state", 64, func(t *testing.T, s string) []string { return []string{"-state", "g2", "A1"} }},
		{"unknown-step", 65, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			return []string{"-state", s, "A9"}
		}},
		{"init-unknown-purpose", 65, func(t *testing.T, s string) []string { setState(t, s, ""); return []string{"-state", s, "INIT-other"} }},
		{"lock-missing", 66, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			os.Remove(filepath.Join(s, "run.lock"))
			return []string{"-state", s, "A1"}
		}},
		{"lock-symlink", 66, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			os.Remove(filepath.Join(s, "run.lock"))
			os.Symlink(filepath.Join(s, "DONE"), filepath.Join(s, "run.lock"))
			return []string{"-state", s, "A1"}
		}},
		{"bootstrap-missing", 69, func(t *testing.T, s string) []string {
			setState(t, s, "station")
			os.WriteFile(filepath.Join(s, "DONE"), []byte("OK B.0\n"), 0600)
			return []string{"-state", s, "A1"}
		}},
		{"stopped", 70, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			os.WriteFile(filepath.Join(s, "STOPPED"), []byte("epoch-0 STOP X rc=1\n"), 0600)
			return []string{"-state", s, "A1"}
		}},
		{"stopped-dangling-symlink", 70, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			os.Symlink("/nonexistent-g2run", filepath.Join(s, "STOPPED"))
			return []string{"-state", s, "A1"}
		}},
		{"closed", 71, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			os.WriteFile(filepath.Join(s, "CLOSED"), []byte("epoch-0 ROLLBACK\n"), 0600)
			return []string{"-state", s, "A1"}
		}},
		{"inflight", 72, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			os.Mkdir(filepath.Join(s, "INFLIGHT"), 0700)
			return []string{"-state", s, "A1"}
		}},
		{"init-twice", 73, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			return []string{"-state", s, "INIT-station"}
		}},
		{"bad-purpose", 74, func(t *testing.T, s string) []string {
			setState(t, s, "other", "INIT-other")
			return []string{"-state", s, "A1"}
		}},
		{"skip", 75, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			return []string{"-state", s, "A2"}
		}},
		{"repeat", 75, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station", "A1")
			return []string{"-state", s, "A1"}
		}},
		{"other-purpose-step", 75, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station", "A1")
			return []string{"-state", s, "R2"}
		}},
		{"recovery-wrong-purpose", 76, func(t *testing.T, s string) []string {
			setState(t, s, "rehearsal", "INIT-rehearsal")
			os.WriteFile(filepath.Join(s, "STOPPED"), []byte("x\n"), 0600)
			return []string{"-state", s, "ROLLBACK"}
		}},
		{"recovery-not-eligible", 77, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station", "A1")
			return []string{"-state", s, "R"}
		}},
		{"abort-without-stop", 77, func(t *testing.T, s string) []string {
			setState(t, s, "station", "INIT-station")
			return []string{"-state", s, "ABORT"}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := fixture(t)
			args := c.prep(t, state)
			before := snapshot(t, state)
			var out, errb bytes.Buffer
			rc := Main(plan, args, &out, &errb)
			if rc != c.want {
				t.Fatalf("rc=%d want %d: %s", rc, c.want, errb.String())
			}
			if after := snapshot(t, state); after != before {
				t.Fatalf("state changed by a refusal:\n%s\n---\n%s", before, after)
			}
		})
	}
}

// Claim: a held lock refuses (rc 67) with the state unchanged; a second runner never overlaps the first.
func TestLockHeldRefuses(t *testing.T) {
	plan := testPlan()
	state := fixture(t)
	setState(t, state, "station", "INIT-station")
	f, e := os.Open(filepath.Join(state, "run.lock"))
	must(t, e)
	defer f.Close()
	must(t, unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	before := snapshot(t, state)
	if rc, out := runStep(t, plan, state, "A1"); rc != 67 || snapshot(t, state) != before {
		t.Fatalf("rc=%d %s", rc, out)
	}
}

// Claim: after admission, a failing operation, a panic, or a malformed operation ends the step as a recorded STOP:
// INFLIGHT stays, no OK is recorded, and an operation that fails validation stops the step before ANY operation runs.
func TestStops(t *testing.T) {
	cases := []struct {
		name string
		ops  []Op
		want int
		ran  []string
	}{
		{"op-failure", []Op{markOp{"before"}, failOp{}, markOp{"after"}}, 1, []string{"before"}},
		{"panic", []Op{markOp{"before"}, panicOp{}, markOp{"after"}}, 1, []string{"before"}},
		{"invalid-op-runs-nothing", []Op{markOp{"before"}, badOp{}, markOp{"after"}}, 86, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := testPlan()
			ops := c.ops
			plan.Steps["A1"] = func(testParams) []Op { return ops }
			state := fixture(t)
			setState(t, state, "station", "INIT-station")
			rc, out := runStep(t, plan, state, "A1")
			if rc != c.want {
				t.Fatalf("rc=%d want %d: %s", rc, c.want, out)
			}
			stopped, _ := os.ReadFile(filepath.Join(state, "STOPPED"))
			done, _ := os.ReadFile(filepath.Join(state, "DONE"))
			if !strings.Contains(string(stopped), fmt.Sprintf("STOP A1 rc=%d", c.want)) || strings.Contains(string(done), "OK A1") || !exists(filepath.Join(state, "INFLIGHT")) {
				t.Fatalf("stopped=%q done=%q inflight=%v", stopped, done, exists(filepath.Join(state, "INFLIGHT")))
			}
			for _, m := range []string{"before", "after"} {
				want := false
				for _, r := range c.ran {
					want = want || r == m
				}
				if exists(filepath.Join(state, "marks", m)) != want {
					t.Fatalf("mark %s present=%v want %v", m, !want, want)
				}
			}
		})
	}
}

// Claim: each package defect is its own named STOP after admission (80-84), and the step's operations never run;
// the parameters file is refused by name when it is not canonical (85).
func TestPackageAndParams(t *testing.T) {
	cases := []struct {
		name string
		want int
		prep func(t *testing.T, s string)
	}{
		{"pin-not-hex", 80, func(t *testing.T, s string) { os.WriteFile(filepath.Join(s, "PKG_SHA256"), []byte("XYZ\n"), 0600) }},
		{"tarball-not-pinned", 81, func(t *testing.T, s string) {
			os.WriteFile(filepath.Join(s, "PKG_SHA256"), []byte(strings.Repeat("0", 64)+"\n"), 0600)
		}},
		{"sums-edited", 82, func(t *testing.T, s string) {
			p := filepath.Join(s, "pkg", "SHA256SUMS")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, append(b, []byte(strings.Repeat("1", 64)+"  extra\n")...), 0600)
		}},
		{"params-tampered", 84, func(t *testing.T, s string) {
			os.WriteFile(filepath.Join(s, "pkg", "params.json"), []byte(`{"name":"y"}`), 0600)
		}},
		{"params-symlink", 84, func(t *testing.T, s string) {
			p := filepath.Join(s, "pkg", "params.json")
			os.Rename(p, p+".real")
			os.Symlink(p+".real", p)
		}},
		{"params-unknown-field", 85, func(t *testing.T, s string) {
			buildPackage(t, s, map[string]string{"params.json": `{"name":"x","extra":1}`})
		}},
		{"params-noncanonical", 85, func(t *testing.T, s string) { buildPackage(t, s, map[string]string{"params.json": `{ "name": "x" }`}) }},
		{"params-duplicate-key", 85, func(t *testing.T, s string) {
			buildPackage(t, s, map[string]string{"params.json": `{"name":"x","name":"y"}`})
		}},
		{"params-empty-name", 85, func(t *testing.T, s string) { buildPackage(t, s, map[string]string{"params.json": `{"name":""}`}) }},
		{"required-file-missing", 83, func(t *testing.T, s string) { buildPackage(t, s, map[string]string{"other.json": `{}`}) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := testPlan()
			state := fixture(t)
			setState(t, state, "station", "INIT-station")
			c.prep(t, state)
			rc, out := runStep(t, plan, state, "A1")
			if rc != c.want || exists(filepath.Join(state, "marks", "A1")) || !exists(filepath.Join(state, "INFLIGHT")) {
				t.Fatalf("rc=%d want %d, mark=%v: %s", rc, c.want, exists(filepath.Join(state, "marks", "A1")), out)
			}
		})
	}
}

// Claim: recovery steps run only in their eligible state, append to CLOSED, and afterwards no normal step runs.
func TestRecovery(t *testing.T) {
	plan := testPlan()
	state := fixture(t)
	setState(t, state, "station", "INIT-station", "A1")
	os.WriteFile(filepath.Join(state, "STOPPED"), []byte("epoch-0 STOP A2 rc=1\n"), 0600)
	if rc, out := runStep(t, plan, state, "ROLLBACK"); rc != 0 {
		t.Fatalf("ROLLBACK after a STOP: rc=%d %s", rc, out)
	}
	closed, _ := os.ReadFile(filepath.Join(state, "CLOSED"))
	if !strings.Contains(string(closed), " ROLLBACK\n") {
		t.Fatalf("CLOSED = %q", closed)
	}
	if rc, out := runStep(t, plan, state, "R"); rc != 0 {
		t.Fatalf("R right after OK ROLLBACK: rc=%d %s", rc, out)
	}
	os.Remove(filepath.Join(state, "STOPPED"))
	if rc, _ := runStep(t, plan, state, "A2"); rc != 70 && rc != 71 {
		t.Fatalf("a normal step after recovery: rc=%d, want a refusal", rc)
	}
	state2 := fixture(t)
	setState(t, state2, "station", "INIT-station", "A1", "A2", "A3")
	if rc, out := runStep(t, plan, state2, "ROLLBACK"); rc != 0 {
		t.Fatalf("ROLLBACK at the terminal step: rc=%d %s", rc, out)
	}
}

// Claim: a plan that names an interpreter, a relative program, a step it cannot build, or an unreachable step is
// refused before any state is read; the valid test plan passes beside them.
func TestPlanValidateRefusals(t *testing.T) {
	cases := map[string]func(p *Plan[testParams]){
		"shell-program":    func(p *Plan[testParams]) { p.Programs["sh"] = "/bin/sh" },
		"python-program":   func(p *Plan[testParams]) { p.Programs["python3"] = "/usr/bin/python3" },
		"python3.14":       func(p *Plan[testParams]) { p.Programs["python3.14"] = "/usr/bin/python3.14" },
		"env-program":      func(p *Plan[testParams]) { p.Programs["env"] = "/usr/bin/env" },
		"find-program":     func(p *Plan[testParams]) { p.Programs["find"] = "/usr/bin/find" },
		"relative-program": func(p *Plan[testParams]) { p.Programs["true"] = "true" },
		"name-mismatch":    func(p *Plan[testParams]) { p.Programs["true"] = "/bin/sh" },
		"missing-step":     func(p *Plan[testParams]) { delete(p.Steps, "A2") },
		"unreachable-step": func(p *Plan[testParams]) { p.Steps["Z9"] = marks("Z9") },
		"duplicate-in-seq": func(p *Plan[testParams]) { p.Sequences["station"] = []string{"A1", "A1"} },
		"never-eligible": func(p *Plan[testParams]) {
			p.Recovery = append(p.Recovery, RecoveryRule{Step: "Q"})
			p.Steps["Q"] = marks("Q")
		},
		"params-unlisted":  func(p *Plan[testParams]) { p.PackageFiles = []string{"other.json"} },
		"absolute-pkgfile": func(p *Plan[testParams]) { p.PackageFiles = append(p.PackageFiles, "/etc/passwd") },
	}
	if e := testPlan().Validate(); e != nil {
		t.Fatalf("the valid plan is refused: %v", e)
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			p := testPlan()
			mut(&p)
			if p.Validate() == nil {
				t.Fatal("accepted")
			}
			var errb bytes.Buffer
			if rc := Main(p, []string{"-state", "/nonexistent-g2run", "A1"}, &bytes.Buffer{}, &errb); rc != 2 {
				t.Fatalf("Main rc=%d, want 2 (plan refused before any state)", rc)
			}
		})
	}
}
