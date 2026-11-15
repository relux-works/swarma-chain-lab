//go:build linux

package g2run

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// refusal is an exit before admission: nothing ran and no state changed.
type refusal struct {
	rc     int
	reason string
}

func (r *refusal) Error() string { return r.reason }
func refuse(rc int, format string, a ...any) error {
	return &refusal{rc: rc, reason: fmt.Sprintf(format, a...)}
}

// stop is a failure after admission, recorded in STOPPED.
type stop struct {
	rc     int
	reason string
}

func (s *stop) Error() string { return s.reason }

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Main runs `g2-run -state DIR STEP` against a compiled plan and returns the process exit status.
func Main[P any](plan Plan[P], args []string, stdout, stderr io.Writer) int {
	if e := plan.Validate(); e != nil {
		fmt.Fprintf(stderr, "REFUSED: the compiled plan is invalid: %v\n", e)
		return 2
	}
	state, step, e := parseArgs(args)
	if e != nil {
		return report(stderr, "none", e)
	}
	r := &run[P]{plan: plan, state: state, step: step, out: stdout, errw: stderr}
	return r.main()
}

func parseArgs(args []string) (state, step string, e error) {
	if len(args) != 3 || args[0] != "-state" {
		return "", "", refuse(64, "usage: g2-run -state DIR STEP (exactly one step)")
	}
	state, step = args[1], args[2]
	if !filepath.IsAbs(state) || filepath.Clean(state) != state || state == "/" {
		return "", "", refuse(64, "the state directory %q is not a clean absolute path", state)
	}
	return state, step, nil
}

type run[P any] struct {
	plan     Plan[P]
	state    string
	step     string
	out      io.Writer
	errw     io.Writer
	class    string
	purpose  string
	admitted bool
	lock     *os.File
}

func (r *run[P]) p(name string) string { return filepath.Join(r.state, name) }

func (r *run[P]) main() (rc int) {
	defer func() {
		if r.lock != nil {
			r.lock.Close()
		}
	}()
	e := r.admit()
	if e != nil && !r.admitted {
		return report(r.errw, r.step, e)
	}
	if e != nil {
		return r.recordStop(&stop{rc: 1, reason: "admission record: " + e.Error()})
	}
	// From here on every end but success is a recorded STOP; a panic is one too.
	defer func() {
		if v := recover(); v != nil {
			rc = r.recordStop(&stop{rc: 1, reason: fmt.Sprintf("panic: %v", v)})
		}
	}()
	if e := r.body(); e != nil {
		var s *stop
		if !errors.As(e, &s) {
			s = &stop{rc: 1, reason: e.Error()}
		}
		return r.recordStop(s)
	}
	if e := r.succeed(); e != nil {
		return r.recordStop(&stop{rc: 1, reason: "success record: " + e.Error()})
	}
	fmt.Fprintf(r.out, "OK %s\n", r.step)
	return 0
}

func report(w io.Writer, step string, e error) int {
	var rf *refusal
	if errors.As(e, &rf) {
		fmt.Fprintf(w, "REFUSED %s before admission (rc=%d): %s: nothing ran and no state changed\n", step, rf.rc, rf.reason)
		return rf.rc
	}
	fmt.Fprintf(w, "REFUSED %s before admission (rc=1): %v: nothing ran and no state changed\n", step, e)
	return 1
}

func (r *run[P]) recordStop(s *stop) int {
	line := fmt.Sprintf("epoch-%d STOP %s rc=%d\n", time.Now().Unix(), r.step, s.rc)
	f, e := os.OpenFile(r.p("STOPPED"), os.O_WRONLY|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if e == nil {
		_, e = f.WriteString(line)
		if ce := f.Close(); e == nil {
			e = ce
		}
	}
	if e != nil {
		fmt.Fprintf(r.errw, "STOP at %s (rc=%d): %s; recording in STOPPED FAILED (%v): the admission record still refuses every later normal step\n", r.step, s.rc, s.reason, e)
	} else {
		fmt.Fprintf(r.errw, "STOP at %s (rc=%d): %s; recorded in STOPPED: only the recovery steps may run now\n", r.step, s.rc, s.reason)
	}
	return s.rc
}

// exists is true for anything at the name, a dangling symlink included.
func exists(p string) bool { _, e := os.Lstat(p); return e == nil }

func readSmall(p string) (string, error) {
	fi, e := os.Lstat(p)
	if e != nil {
		return "", e
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return "", fmt.Errorf("%s is not a small regular file", p)
	}
	b, e := os.ReadFile(p)
	return string(b), e
}

func lines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// admit runs every check before admission; it changes no state unless it returns nil.
func (r *run[P]) admit() error {
	unix.Umask(0o077)
	if got := unix.Umask(0o077); got != 0o077 {
		return refuse(90, "the umask reads back %04o, want 0077", got)
	}
	class, purpose, ok := r.plan.classify(r.step)
	if !ok {
		return refuse(65, "%s is not a step of the plan", r.step)
	}
	r.class, r.purpose = class, purpose
	// The lock: never created here, opened read-only, refused by name when missing.
	fi, e := os.Lstat(r.p("run.lock"))
	if e != nil || !fi.Mode().IsRegular() {
		return refuse(66, "%s is missing or not a regular file (the bootstrap creates it)", r.p("run.lock"))
	}
	r.lock, e = os.OpenFile(r.p("run.lock"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return refuse(66, "cannot open %s: %v", r.p("run.lock"), e)
	}
	if e = unix.Flock(int(r.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return refuse(67, "another g2-run holds %s", r.p("run.lock"))
	}
	done, e := readSmall(r.p("DONE"))
	dl := lines(done)
	if e != nil || len(dl) == 0 || dl[0] != r.plan.BootstrapLine {
		return refuse(69, "the bootstrap did not complete (DONE does not start with %q)", r.plan.BootstrapLine)
	}
	last := dl[len(dl)-1]
	if class == "recovery" {
		return r.admitRecovery(last)
	}
	if exists(r.p("STOPPED")) {
		return refuse(70, "a STOP is recorded in STOPPED; only the recovery steps may run now")
	}
	if exists(r.p("CLOSED")) {
		return refuse(71, "this attempt ran a recovery step and is closed")
	}
	if exists(r.p("INFLIGHT")) {
		return refuse(72, "INFLIGHT is present: a step started and never finished; only the recovery steps may run now")
	}
	if class == "init" {
		if done != r.plan.BootstrapLine+"\n" || exists(r.p("PURPOSE")) {
			return refuse(73, "INIT runs once, right after the bootstrap")
		}
	} else {
		pur, e := readSmall(r.p("PURPOSE"))
		pur = strings.TrimSuffix(pur, "\n")
		seq := r.plan.Sequences[pur]
		if e != nil || seq == nil {
			return refuse(74, "the recorded purpose %q is not a purpose of the plan", pur)
		}
		r.purpose = pur
		want := ""
		prev := "INIT-" + pur
		for _, s := range seq {
			if s == r.step {
				want = prev
				break
			}
			prev = s
		}
		if want == "" {
			return refuse(75, "%s is not a step of the %s sequence", r.step, pur)
		}
		if last != "OK "+want {
			return refuse(75, "%s runs only right after %s; the last completed step is %q", r.step, want, last)
		}
	}
	if e := unix.Mkdir(r.p("INFLIGHT"), 0o700); e != nil {
		return refuse(72, "cannot create INFLIGHT exclusively: %v", e)
	}
	r.admitted = true
	return writeNew(filepath.Join(r.p("INFLIGHT"), "step"), fmt.Sprintf("epoch-%d %s\n", time.Now().Unix(), r.step))
}

func (r *run[P]) admitRecovery(last string) error {
	var rule RecoveryRule
	for _, x := range r.plan.Recovery {
		if x.Step == r.step {
			rule = x
		}
	}
	stopped := exists(r.p("STOPPED")) || exists(r.p("INFLIGHT"))
	if rule.Purpose != "" {
		pur, e := readSmall(r.p("PURPOSE"))
		if e != nil || strings.TrimSuffix(pur, "\n") != rule.Purpose {
			return refuse(76, "%s belongs to the %s purpose; this attempt is %q", r.step, rule.Purpose, strings.TrimSuffix(pur, "\n"))
		}
		r.purpose = rule.Purpose
	} else if pur, e := readSmall(r.p("PURPOSE")); e == nil {
		r.purpose = strings.TrimSuffix(pur, "\n")
	}
	eligible := rule.AfterStop && stopped
	for _, a := range rule.AfterLast {
		if last == "OK "+a {
			eligible = true
		}
	}
	if !eligible {
		return refuse(77, "%s is not eligible in this state (last completed: %q; STOP recorded or INFLIGHT: %v)", r.step, last, stopped)
	}
	f, e := os.OpenFile(r.p("CLOSED"), os.O_WRONLY|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return refuse(77, "cannot record %s in CLOSED: %v", r.step, e)
	}
	_, e = fmt.Fprintf(f, "epoch-%d %s\n", time.Now().Unix(), r.step)
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return refuse(77, "cannot record %s in CLOSED: %v", r.step, e)
	}
	r.admitted = true
	return nil
}

func writeNew(p, content string) error {
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	_, e = f.WriteString(content)
	if ce := f.Close(); e == nil {
		e = ce
	}
	return e
}

// body runs after admission: the package bytes, the parameters, then the step.
func (r *run[P]) body() error {
	if e := VerifyPackage(r.state, r.plan.PackageFiles); e != nil {
		return e
	}
	if r.class == "init" {
		return writeNew(r.p("PURPOSE"), r.purpose+"\n")
	}
	raw, e := os.ReadFile(filepath.Join(r.state, "pkg", r.plan.ParamsFile))
	if e != nil {
		return &stop{rc: 85, reason: "PARAMS_READ: " + e.Error()}
	}
	params, e := r.plan.Decode(raw)
	if e != nil {
		return &stop{rc: 85, reason: "PARAMS_REFUSED: " + e.Error()}
	}
	ops := r.plan.Steps[r.step](params)
	for i, op := range ops {
		if e := op.Validate(); e != nil {
			return &stop{rc: 86, reason: fmt.Sprintf("OP_INVALID %d %s: %v", i+1, op.Kind(), e)}
		}
	}
	x, e := NewExecutor(r.plan.Programs)
	if e != nil {
		return &stop{rc: 86, reason: e.Error()}
	}
	ctx := &Ctx{State: r.state, Step: r.step, Purpose: r.purpose, Exec: x, Out: r.out}
	for i, op := range ops {
		if e := op.Do(ctx); e != nil {
			return &stop{rc: 1, reason: fmt.Sprintf("op %d %s: %v", i+1, op.Kind(), e)}
		}
	}
	return nil
}

func (r *run[P]) succeed() error {
	f, e := os.OpenFile(r.p("DONE"), os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(f, "OK %s\n", r.step)
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if r.class == "recovery" {
		return nil
	}
	if e := os.Remove(filepath.Join(r.p("INFLIGHT"), "step")); e != nil {
		return e
	}
	return unix.Rmdir(r.p("INFLIGHT"))
}

// VerifyPackage checks the install package against the operator's pin, first error wins, each with its own code:
// the pin is 64 lowercase hex (80); the kept tarball has that sha256 (81); its SHA256SUMS member equals
// pkg/SHA256SUMS (82); that file lists every required file exactly once (83); every listed file under pkg/ is a
// regular file with its listed digest, in strict sha256sum format (84).
func VerifyPackage(state string, required []string) error {
	pin, e := readSmall(filepath.Join(state, "PKG_SHA256"))
	pin = strings.TrimSuffix(pin, "\n")
	if e != nil || !hex64.MatchString(pin) {
		return &stop{rc: 80, reason: "the package pin is not 64 lowercase hex"}
	}
	tarPath := filepath.Join(state, "package.tar.gz")
	sum, e := fileSHA256(tarPath)
	if e != nil || sum != pin {
		return &stop{rc: 81, reason: "the kept package tarball does not match the pin"}
	}
	member, e := tarMember(tarPath, "SHA256SUMS")
	live, le := readSmall(filepath.Join(state, "pkg", "SHA256SUMS"))
	if e != nil || le != nil || !bytes.Equal(member, []byte(live)) {
		return &stop{rc: 82, reason: "pkg/SHA256SUMS differs from the pinned package's"}
	}
	listed := map[string]string{}
	count := map[string]int{}
	for _, l := range lines(live) {
		f := strings.SplitN(l, "  ", 2)
		if len(f) != 2 || !hex64.MatchString(f[0]) || !validPackagePath(f[1]) {
			return &stop{rc: 84, reason: fmt.Sprintf("SHA256SUMS line is not strict: %q", l)}
		}
		listed[f[1]] = f[0]
		count[f[1]]++
	}
	for _, f := range required {
		if count[f] != 1 {
			return &stop{rc: 83, reason: fmt.Sprintf("SHA256SUMS lists %s %d times", f, count[f])}
		}
	}
	for f, want := range listed {
		if count[f] != 1 {
			return &stop{rc: 84, reason: fmt.Sprintf("SHA256SUMS lists %s %d times", f, count[f])}
		}
		p := filepath.Join(state, "pkg", f)
		fi, e := os.Lstat(p)
		if e != nil || !fi.Mode().IsRegular() {
			return &stop{rc: 84, reason: fmt.Sprintf("pkg/%s is not a regular file", f)}
		}
		got, e := fileSHA256(p)
		if e != nil || got != want {
			return &stop{rc: 84, reason: fmt.Sprintf("pkg/%s does not match SHA256SUMS", f)}
		}
	}
	return nil
}

func fileSHA256(p string) (string, error) {
	f, e := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e := io.Copy(h, bufio.NewReader(f)); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func tarMember(tarPath, name string) ([]byte, error) {
	f, e := os.OpenFile(tarPath, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return nil, e
	}
	tr := tar.NewReader(gz)
	var found []byte
	n := 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if strings.TrimPrefix(h.Name, "./") == name {
			if h.Typeflag != tar.TypeReg || h.Size > 1<<20 {
				return nil, errors.New("member is not a small regular file")
			}
			b, e := io.ReadAll(tr)
			if e != nil {
				return nil, e
			}
			found = b
			n++
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("%d members named %s", n, name)
	}
	return found, nil
}
