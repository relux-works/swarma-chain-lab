//go:build linux

package g2run

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// Executor is the ONLY path by which the engine starts another program (the static test enforces it).
type Executor struct {
	programs map[string]string
}

// NewExecutor checks the table once more; the plan's Validate has already refused interpreters and relative paths.
func NewExecutor(programs map[string]string) (*Executor, error) {
	for name, abs := range programs {
		if !validProgram(name, abs) {
			return nil, fmt.Errorf("EXEC_TABLE %q", name)
		}
	}
	return &Executor{programs: programs}, nil
}

// Run is ExecFixed: no shell, a fixed absolute path, a fixed environment, stdin from /dev/null, the working directory
// "/". A program that is killed by a signal, cannot start, or whose output cannot be opened is an error.
func (x *Executor) Run(c Cmd) (Result, error) {
	abs, ok := x.programs[c.Program]
	if !ok {
		return Result{}, fmt.Errorf("EXEC_UNKNOWN_PROGRAM %q", c.Program)
	}
	for _, a := range c.Args {
		if bytes.IndexByte([]byte(a), 0) >= 0 {
			return Result{}, fmt.Errorf("EXEC_NUL_ARGUMENT %s", c.Program)
		}
	}
	devnull, e := os.Open(os.DevNull)
	if e != nil {
		return Result{}, fmt.Errorf("EXEC_STDIN %s: %v", c.Program, e)
	}
	defer devnull.Close()
	cmd := &exec.Cmd{Path: abs, Args: append([]string{abs}, c.Args...), Env: FixedEnv, Dir: "/", Stdin: devnull}
	var buf bytes.Buffer
	if c.Stdout == "" {
		cmd.Stdout = &buf
	} else {
		f, e := os.OpenFile(c.Stdout, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, 0600)
		if e != nil {
			return Result{}, fmt.Errorf("EXEC_OUTPUT_OPEN %s: %v", c.Stdout, e)
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
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: c.Cred.UID, Gid: c.Cred.GID, Groups: c.Cred.Groups, NoSetGroups: false}
	}
	e = cmd.Run()
	var ee *exec.ExitError
	switch {
	case e == nil:
		return Result{RC: 0, Stdout: buf.Bytes()}, nil
	case errors.As(e, &ee):
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if ok && ws.Signaled() {
			return Result{}, fmt.Errorf("EXEC_SIGNALED %s %v", c.Program, ws.Signal())
		}
		return Result{RC: ee.ExitCode(), Stdout: buf.Bytes()}, nil
	default:
		return Result{}, fmt.Errorf("EXEC_START %s: %v", c.Program, e)
	}
}
