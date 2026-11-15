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
	if _, e := appendLine(r.state, "STOPPED", line); e != nil {
		fmt.Fprintf(r.errw, "STOP at %s (rc=%d): %s; recording in STOPPED FAILED (%v): the admission record still refuses every later normal step\n", r.step, s.rc, s.reason, e)
	} else {
		fmt.Fprintf(r.errw, "STOP at %s (rc=%d): %s; recorded in STOPPED: only the recovery steps may run now\n", r.step, s.rc, s.reason)
	}
	return s.rc
}

// syncDir makes a directory's entries durable (a created, renamed or removed name).
func syncDir(dir string) error {
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

// replaceFile writes DIR/NAME atomically and durably: a new temp file in DIR (exclusive, no symlink), its content,
// fsync, rename over NAME, fsync DIR. renamed tells whether NAME already changed when an error is returned: before
// the rename nothing changed (the temp file is removed); after it, the new content is in place but may not be durable.
func replaceFile(dir, name, content string) (renamed bool, e error) {
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d-%d", name, os.Getpid(), time.Now().UnixNano()))
	f, e := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return false, e
	}
	_, e = f.WriteString(content)
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(tmp, filepath.Join(dir, name))
	}
	if e != nil {
		os.Remove(tmp)
		return false, e
	}
	return true, syncDir(dir)
}

// appendLine adds a line to a small newline-terminated record file by an atomic, durable replacement. An existing
// file must be a regular file whose content ends in a newline (a record without its newline would fuse with the next).
func appendLine(dir, name, line string) (renamed bool, e error) {
	old := ""
	if exists(filepath.Join(dir, name)) {
		old, e = readSmall(filepath.Join(dir, name))
		if e != nil {
			return false, e
		}
		if old != "" && !strings.HasSuffix(old, "\n") {
			return false, fmt.Errorf("%s is not newline-terminated", name)
		}
	}
	return replaceFile(dir, name, old+line)
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
	if !strings.HasSuffix(done, "\n") {
		return refuse(69, "DONE is not newline-terminated: its last record is incomplete")
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
	// Admission is durable before any effect: the INFLIGHT directory and its step record, each fsynced with its parent.
	if e := unix.Mkdir(r.p("INFLIGHT"), 0o700); e != nil {
		return refuse(72, "cannot create INFLIGHT exclusively: %v", e)
	}
	r.admitted = true
	if e := syncDir(r.state); e != nil {
		return e
	}
	_, e = replaceFile(r.p("INFLIGHT"), "step", fmt.Sprintf("epoch-%d %s\n", time.Now().Unix(), r.step))
	return e
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
	// CLOSED is replaced atomically: a failure before the rename leaves it unchanged and is a truthful refusal; a
	// failure after it (the directory fsync) is a partial admission and is recorded as a STOP.
	renamed, e := appendLine(r.state, "CLOSED", fmt.Sprintf("epoch-%d %s\n", time.Now().Unix(), r.step))
	if renamed {
		r.admitted = true
	}
	if e != nil && !renamed {
		return refuse(77, "cannot record %s in CLOSED: %v", r.step, e)
	}
	if e != nil {
		return e
	}
	r.admitted = true
	return nil
}

// body runs after admission: the package bytes, the parameters, then the step.
func (r *run[P]) body() error {
	if e := VerifyPackage(r.state, r.plan.PackageFiles); e != nil {
		return e
	}
	if r.class == "init" {
		if exists(r.p("PURPOSE")) {
			return &stop{rc: 73, reason: "PURPOSE appeared after admission"}
		}
		_, e := replaceFile(r.state, "PURPOSE", r.purpose+"\n")
		return e
	}
	raw, e := readBeneath(filepath.Join(r.state, "pkg"), r.plan.ParamsFile)
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
	x, e := NewExecutor(r.state, r.plan.Programs, r.plan.OutputRoots)
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

// succeed records OK durably BEFORE the latch is cleared: DONE is replaced atomically and fsynced with its directory;
// only then are INFLIGHT/step and INFLIGHT removed, and the state directory fsynced again.
func (r *run[P]) succeed() error {
	if _, e := appendLine(r.state, "DONE", fmt.Sprintf("OK %s\n", r.step)); e != nil {
		return e
	}
	if r.class == "recovery" {
		return nil
	}
	if e := os.Remove(filepath.Join(r.p("INFLIGHT"), "step")); e != nil {
		return e
	}
	if e := unix.Rmdir(r.p("INFLIGHT")); e != nil {
		return e
	}
	return syncDir(r.state)
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
	pkg := filepath.Join(state, "pkg")
	member, e := tarMember(tarPath, "SHA256SUMS")
	liveB, le := readBeneath(pkg, "SHA256SUMS")
	live := string(liveB)
	if e != nil || le != nil || !bytes.Equal(member, liveB) {
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
		// Opened beneath pkg/ with no symlink anywhere on the way, so a symlinked ancestor cannot point the check at
		// bytes outside the package.
		got, e := hashBeneath(pkg, f)
		if e != nil {
			return &stop{rc: 84, reason: fmt.Sprintf("pkg/%s is not a regular file beneath pkg/: %v", f, e)}
		}
		if got != want {
			return &stop{rc: 84, reason: fmt.Sprintf("pkg/%s does not match SHA256SUMS", f)}
		}
	}
	return nil
}

// openBeneath opens DIR/REL read-only with openat2: beneath DIR, with no symlink or magic link anywhere on the way
// (DIR itself included), and only if it is a regular file.
func openBeneath(dir, rel string) (*os.File, error) {
	dfd, e := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(dfd)
	fd, e := unix.Openat2(dfd, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, errors.New("not a regular file")
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir, rel)), nil
}

func readBeneath(dir, rel string) ([]byte, error) {
	f, e := openBeneath(dir, rel)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if e == nil && len(b) > 16<<20 {
		e = errors.New("larger than 16 MiB")
	}
	return b, e
}

func hashBeneath(dir, rel string) (string, error) {
	f, e := openBeneath(dir, rel)
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
