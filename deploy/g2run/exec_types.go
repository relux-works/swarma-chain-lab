package g2run

import "io"

// FixedEnv is the whole environment of every program the engine runs. Nothing is inherited.
var FixedEnv = []string{"HOME=/root", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// Cred runs a program as UID and GID with exactly the supplementary GROUPS, set by the kernel in the child
// (setgroups, setgid, setuid before exec). It replaces runuser and setpriv.
type Cred struct {
	UID    uint32
	GID    uint32
	Groups []uint32
}

// Cmd is one program run. Program names an entry of the plan's program table; Args is argv[1:], built by a typed
// wrapper from typed fields. Stdout empty captures the output; otherwise it is an absolute path that ExecFixed opens
// (create or truncate, 0600) BEFORE the program starts, so a failed open is an error and never the program's status.
type Cmd struct {
	Program string
	Args    []string
	Stdout  string
	Merge   bool // stderr goes where stdout goes
	Cred    *Cred
}

// Result is a finished run. RC is the program's exit status; a non-zero RC is not an error here, the typed operation
// decides what it requires.
type Result struct {
	RC     int
	Stdout []byte
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
