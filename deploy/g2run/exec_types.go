package g2run

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// FixedEnv is the whole environment of every program the engine runs. Nothing is inherited.
var FixedEnv = []string{"HOME=/root", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// MaxCapture bounds a captured standard output; a program that writes more is an error, never a truncated success.
const MaxCapture = 1 << 20

// Program is one entry of a plan's ALLOW-LIST: the absolute path, and why the plan needs it (the argv forms its typed
// wrappers build). The path must be a root-owned regular file that is neither setuid nor setgid nor writable by group
// or others (Go cannot set no-new-privileges for a single exec, so a set-id program is refused outright).
type Program struct {
	Path string
	Why  string
}

// registered is the CLOSED set of programs the engine has reviewed typed wrappers for: name -> why. Only package
// init functions of wrapper files (and of test files) call RegisterProgram; a plan may name no other program, so an
// interpreter or file-work tool that no denylist happens to name (an "ash", a "cp") is still refused.
var registered = map[string]string{}

// RegisterProgram adds a program to the closed set. It must be called from an init function.
func RegisterProgram(name, why string) {
	if name == "" || why == "" || forbiddenPrograms[name] {
		panic("g2run: RegisterProgram " + name)
	}
	registered[name] = why
}

// Cred runs a program as UID and GID with exactly the supplementary GROUPS, set by the kernel in the child
// (setgroups, setgid, setuid before exec). It replaces runuser and setpriv.
type Cred struct {
	UID    uint32
	GID    uint32
	Groups []uint32
}

// Cmd is one program run, built by a typed wrapper.
//   - Args are the program's options and fixed words; Operands are the VALUES. Each operand is a ValidOperand (it can
//     never be read as an option) and is passed after a "--" separator unless NoDoubleDash is set for a program that
//     takes no "--" (the operand check still applies).
//   - Stdout empty captures at most MaxCapture bytes. Otherwise it is a path RELATIVE to one of the plan's output roots
//     ("log/x.out"); ExecFixed opens it beneath that root, with no symlink anywhere on the way, BEFORE the program
//     starts, so a failed open is an error and never the program's status.
//   - WantRC lists the statuses that count as success; empty means {0}. Any other status is an error (fail closed:
//     an operation that forgets to look at the status cannot accept a failure).
type Cmd struct {
	Program      string
	Args         []string
	Operands     []string
	NoDoubleDash bool
	Stdout       string
	Merge        bool // stderr goes where stdout goes
	Cred         *Cred
	WantRC       []int
	// Stdin, when set, is a BOUNDED in-memory buffer produced by typed code (for example an archive built in memory),
	// at most MaxStdin bytes; never a path and never a pipe from another program (QA $UP1dms6I). Default /dev/null.
	Stdin []byte
	// Timeout ends the program's whole process group with SIGKILL; zero means DefaultTimeout.
	Timeout time.Duration
}

// MaxStdin bounds Cmd.Stdin.
const MaxStdin = 256 << 20

// DefaultTimeout bounds every program the engine runs.
const DefaultTimeout = 10 * time.Minute

// flagValue builds one "-flag=value" argument from a constant flag and a TYPED value that must be a ValidOperand. It
// is the only way a value may enter Cmd.Args (the static test refuses any other non-constant element); an invalid
// payload panics, which the runner records as a STOP.
func flagValue(flag, value string) string {
	if !strings.HasPrefix(flag, "-") || !ValidOperand(value) {
		panic(fmt.Sprintf("g2run: flagValue %s refused value %q", flag, value))
	}
	return flag + "=" + value
}

// Result is a finished run whose status was one of Cmd.WantRC.
type Result struct {
	RC     int
	Stdout []byte
}

// ValidOperand is a value that can never be taken for an option or split into two arguments: non-empty, not starting
// with '-', no NUL, CR or LF. Typed decoders use it at decode; ExecFixed checks it again.
func ValidOperand(s string) bool {
	return s != "" && !strings.HasPrefix(s, "-") && !strings.ContainsAny(s, "\x00\r\n")
}

// Execer runs one program through ExecFixed. Operations receive it in their Ctx; tests may substitute a recorder.
type Execer interface {
	Run(Cmd) (Result, error)
}

// Ctx is what an operation sees while it runs.
type Ctx struct {
	State   string // the attempt's private state directory
	Step    string
	Purpose string
	Exec    Execer
	Out     io.Writer
}
