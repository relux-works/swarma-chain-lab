//go:build linux

package g2run

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Executor is the ONLY path by which the engine starts another program (the static test enforces it).
type Executor struct {
	state    string
	programs map[string]resolved
	roots    map[string]bool
}

// resolved is a program pinned at construction: the file that runs (symlinks resolved once) and the argv[0] it is
// given (the table path, so a multicall binary still selects the right tool).
type resolved struct {
	file  string
	argv0 string
}

// rootOnly requires every directory from p up to "/" to be root-owned and not writable by group or others, so no
// unprivileged account can swap a name on the way.
func rootOnly(p string) error {
	for d := p; ; d = filepath.Dir(d) {
		fi, e := os.Lstat(d)
		if e != nil {
			return e
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not root-owned and closed", d)
		}
		if d == "/" {
			return nil
		}
	}
}

// NewExecutor checks the allow-list against the live files and pins each program. Symlinks (a distribution may ship
// its tools as links to a multicall binary) are resolved ONCE here: the link itself must be root-owned, every
// directory on both the table path and the resolved path must be root-owned and closed, and the resolved file must be
// a root-owned regular file, neither setuid nor setgid, not writable by group or others. The pinned file is what runs.
// The plan's Validate has already refused unregistered programs, interpreters, file-work tools and relative paths.
func NewExecutor(state string, programs map[string]Program, outputRoots []string) (*Executor, error) {
	// The executor keeps its own copy: a caller that changes its map afterwards cannot change what runs.
	own := make(map[string]resolved, len(programs))
	for name, p := range programs {
		if !validProgram(name, p.Path) || strings.TrimSpace(p.Why) == "" {
			return nil, fmt.Errorf("EXEC_TABLE %q", name)
		}
		if _, ok := registered[name]; !ok {
			return nil, fmt.Errorf("EXEC_TABLE_UNREGISTERED %q", name)
		}
		lfi, e := os.Lstat(p.Path)
		if e != nil {
			return nil, fmt.Errorf("EXEC_TABLE_MISSING %s", p.Path)
		}
		if lst, ok := lfi.Sys().(*syscall.Stat_t); !ok || lst.Uid != 0 {
			return nil, fmt.Errorf("EXEC_TABLE_OWNER %s", p.Path)
		}
		file, e := filepath.EvalSymlinks(p.Path)
		if e != nil {
			return nil, fmt.Errorf("EXEC_TABLE_RESOLVE %s", p.Path)
		}
		if e := rootOnly(filepath.Dir(p.Path)); e != nil {
			return nil, fmt.Errorf("EXEC_TABLE_PATH %s: %v", p.Path, e)
		}
		if e := rootOnly(filepath.Dir(file)); e != nil {
			return nil, fmt.Errorf("EXEC_TABLE_PATH %s: %v", file, e)
		}
		fi, e := os.Lstat(file)
		if e != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("EXEC_TABLE_NOT_REGULAR %s", file)
		}
		if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return nil, fmt.Errorf("EXEC_TABLE_SETID %s", p.Path)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("EXEC_TABLE_WRITABLE %s", p.Path)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
			return nil, fmt.Errorf("EXEC_TABLE_OWNER %s", file)
		}
		own[name] = resolved{file: file, argv0: p.Path}
	}
	roots := map[string]bool{}
	for _, r := range outputRoots {
		if !validOutputRoot(r) {
			return nil, fmt.Errorf("EXEC_OUTPUT_ROOT %q", r)
		}
		roots[r] = true
	}
	return &Executor{state: state, programs: own, roots: roots}, nil
}

// openOutput opens rel beneath its output root with openat2: no symlink, no magic link, no escape by "..". The path
// must be clean and relative ("log/x.out"); "//", ".." and an undeclared root are refused by name.
func (x *Executor) openOutput(rel string) (*os.File, error) {
	if filepath.IsAbs(rel) || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "..") || strings.ContainsAny(rel, "\x00\r\n") {
		return nil, fmt.Errorf("EXEC_OUTPUT_PATH %q", rel)
	}
	root, rest, ok := "", "", false
	for r := range x.roots {
		if strings.HasPrefix(rel, r+"/") && len(rel) > len(r)+1 {
			root, rest, ok = r, rel[len(r)+1:], true
		}
	}
	if !ok {
		return nil, fmt.Errorf("EXEC_OUTPUT_OUTSIDE_ROOTS %q", rel)
	}
	how := &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	sfd, e := unix.Open(x.state, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, fmt.Errorf("EXEC_OUTPUT_OPEN %s: state: %v", rel, e)
	}
	defer unix.Close(sfd)
	rfd, e := unix.Openat2(sfd, root, how)
	if e != nil {
		return nil, fmt.Errorf("EXEC_OUTPUT_OPEN %s: root: %v", rel, e)
	}
	defer unix.Close(rfd)
	// O_NONBLOCK so that a FIFO planted at the name cannot block the open; the target must then prove to be a regular
	// file owned by the runner, and is set to 0600 whatever mode it had before (an existing 0644 file becomes 0600).
	fd, e := unix.Openat2(rfd, rest, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_CLOEXEC | unix.O_NONBLOCK, Mode: 0o600,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, fmt.Errorf("EXEC_OUTPUT_OPEN %s: %v", rel, e)
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() {
		unix.Close(fd)
		return nil, fmt.Errorf("EXEC_OUTPUT_NOT_PRIVATE_FILE %s", rel)
	}
	if e = unix.Fchmod(fd, 0o600); e == nil {
		e = unix.Ftruncate(fd, 0)
	}
	if e == nil {
		_, e = unix.FcntlInt(uintptr(fd), unix.F_SETFL, 0) // clears O_NONBLOCK
	}
	if e != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("EXEC_OUTPUT_OPEN %s: %v", rel, e)
	}
	return os.NewFile(uintptr(fd), filepath.Join(x.state, rel)), nil
}

// capped keeps at most MaxCapture bytes and remembers that more were written.
type capped struct {
	b    []byte
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := MaxCapture - len(c.b); len(p) > room {
		c.b = append(c.b, p[:room]...)
		c.over = true
		return room, errors.New("capture limit") // stops an endless producer (it gets EPIPE or SIGPIPE)
	}
	c.b = append(c.b, p...)
	return len(p), nil
}

// Run is ExecFixed: no shell, a fixed absolute path from the allow-list, a fixed environment, stdin from /dev/null,
// the working directory "/", a new process group, every descriptor of the runner closed in the child (Go opens all
// files close-on-exec; the test lists the child's descriptors). A program that cannot start, is killed by a signal,
// exits with a status outside WantRC, overflows the capture, or whose output cannot be opened is an error.
func (x *Executor) Run(c Cmd) (Result, error) {
	p, ok := x.programs[c.Program]
	if !ok {
		return Result{}, fmt.Errorf("EXEC_UNKNOWN_PROGRAM %q", c.Program)
	}
	argv := append([]string{p.argv0}, c.Args...)
	for _, a := range c.Args {
		if strings.IndexByte(a, 0) >= 0 {
			return Result{}, fmt.Errorf("EXEC_NUL_ARGUMENT %s", c.Program)
		}
	}
	if len(c.Operands) > 0 && !c.NoDoubleDash {
		argv = append(argv, "--")
	}
	for _, o := range c.Operands {
		if !ValidOperand(o) {
			return Result{}, fmt.Errorf("EXEC_OPERAND %s %q", c.Program, o)
		}
		argv = append(argv, o)
	}
	want := c.WantRC
	if len(want) == 0 {
		want = []int{0}
	}
	devnull, e := os.Open(os.DevNull)
	if e != nil {
		return Result{}, fmt.Errorf("EXEC_STDIN %s: %v", c.Program, e)
	}
	defer devnull.Close()
	cmd := &exec.Cmd{Path: p.file, Args: argv, Env: FixedEnv, Dir: "/", Stdin: devnull}
	buf := &capped{}
	if c.Stdout == "" {
		cmd.Stdout = buf
	} else {
		f, e := x.openOutput(c.Stdout)
		if e != nil {
			return Result{}, e
		}
		defer f.Close()
		cmd.Stdout = f
	}
	if c.Merge {
		cmd.Stderr = cmd.Stdout
	} else {
		cmd.Stderr = os.Stderr
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if c.Cred != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: c.Cred.UID, Gid: c.Cred.GID, Groups: c.Cred.Groups}
	}
	e = cmd.Run()
	if buf.over {
		return Result{}, fmt.Errorf("EXEC_OUTPUT_TOO_LARGE %s", c.Program)
	}
	rc := 0
	var ee *exec.ExitError
	switch {
	case e == nil:
	case errors.As(e, &ee):
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return Result{}, fmt.Errorf("EXEC_SIGNALED %s %v", c.Program, ws.Signal())
		}
		rc = ee.ExitCode()
	default:
		return Result{}, fmt.Errorf("EXEC_START %s: %v", c.Program, e)
	}
	for _, w := range want {
		if rc == w {
			return Result{RC: rc, Stdout: buf.b}, nil
		}
	}
	return Result{}, fmt.Errorf("EXEC_STATUS %s exited %d, want %v", c.Program, rc, want)
}
