//go:build linux

package g2run

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The E2 operations. Each Validate refuses malformed typed values by name before any operation of the step runs; each
// Do works in Go or through one typed wrapper over ExecFixed. No operation passes a value to a shell or interpreter.

func init() {
	RegisterProgram("getent", "account and group lookups through NSS: getent passwd|group -- NAME")
	RegisterProgram("systemctl", "unit control: start|stop|is-enabled -- UNIT, show -p PROP --value -- UNIT")
	RegisterProgram("journalctl", "one unit's journal since a time: --unit=U --since=T --no-pager -o cat")
	RegisterProgram("namecoin-cli", "read-only node RPCs as the node's own user (Cred): -conf= -datadir= METHOD ARGS")
	RegisterProgram("client.py", "the pinned slot client (sha256 checked in its step): status 100, under Cred")
	RegisterProgram("age", "encrypts an archive built in memory to one recipient: --recipient=R --output=OUT, stdin from Go")
}

// readRegular reads a small regular file without following a final symlink.
func readRegular(p Path, max int64) ([]byte, error) {
	f, e := os.OpenFile(string(p), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e == nil && int64(len(b)) > max {
		e = fmt.Errorf("%s is larger than %d bytes", p, max)
	}
	return b, e
}

func sha256File(p Path) (string, error) {
	f, e := os.OpenFile(string(p), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return "", e
	}
	defer f.Close()
	if fi, e := f.Stat(); e != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	h := sha256.New()
	if _, e := io.Copy(h, bufio.NewReader(f)); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---- files ---------------------------------------------------------------------------------------------------------

// CheckSHA256 requires a regular file's sha256 to be exactly Want.
type CheckSHA256 struct {
	Path Path
	Want Hex64
}

func (o CheckSHA256) Kind() string    { return "check-sha256" }
func (o CheckSHA256) Validate() error { return validateAll(o.Path, o.Want) }
func (o CheckSHA256) Do(c *Ctx) error {
	got, e := sha256File(o.Path)
	if e != nil {
		return e
	}
	if got != string(o.Want) {
		return fmt.Errorf("%s is %s, want %s", o.Path, got, o.Want)
	}
	fmt.Fprintf(c.Out, "%s  %s\n", got, o.Path)
	return nil
}

// ExpectStat requires a path (not followed if a symlink) to be exactly OWNER:GROUP MODE with LINKS hard links and, when
// Size >= 0, SIZE bytes.
type ExpectStat struct {
	Path         Path
	Owner, Group Name
	Mode         Mode
	Links        int
	Size         int64
}

func (o ExpectStat) Kind() string { return "expect-stat" }
func (o ExpectStat) Validate() error {
	if e := validateAll(o.Path, o.Owner, o.Group); e != nil {
		return e
	}
	if o.Links < 1 || o.Size < -1 {
		return errors.New("STAT_EXPECTATION_REFUSED")
	}
	return nil
}
func (o ExpectStat) Do(c *Ctx) error {
	fi, e := os.Lstat(string(o.Path))
	if e != nil {
		return e
	}
	st := fi.Sys().(*syscall.Stat_t)
	uid, e := lookupID(c, "passwd", o.Owner)
	if e != nil {
		return e
	}
	gid, e := lookupID(c, "group", o.Group)
	if e != nil {
		return e
	}
	mode := Mode(uint32(fi.Mode().Perm()) | setidBits(fi.Mode()))
	if ID(st.Uid) != uid || ID(st.Gid) != gid || mode != o.Mode || int(st.Nlink) != o.Links || (o.Size >= 0 && st.Size != o.Size) {
		return fmt.Errorf("%s is uid %d gid %d mode %s links %d size %d; want %s:%s %s links %d size %d",
			o.Path, st.Uid, st.Gid, mode, st.Nlink, st.Size, o.Owner, o.Group, o.Mode, o.Links, o.Size)
	}
	return nil
}

func setidBits(m os.FileMode) uint32 {
	var b uint32
	if m&os.ModeSetuid != 0 {
		b |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		b |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		b |= 0o1000
	}
	return b
}

// ExpectPath requires a path's presence state: Absent (nothing at the name, not even a dangling link), NonEmpty (a
// regular file with content) or Empty (absent or a zero-length regular file).
type ExpectPath struct {
	Path  Path
	State string
}

func (o ExpectPath) Kind() string { return "expect-path" }
func (o ExpectPath) Validate() error {
	if o.State != "absent" && o.State != "non-empty" && o.State != "empty" {
		return fmt.Errorf("PATH_STATE_REFUSED %q", o.State)
	}
	return o.Path.Validate()
}
func (o ExpectPath) Do(*Ctx) error {
	fi, e := os.Lstat(string(o.Path))
	switch o.State {
	case "absent":
		if e == nil {
			return fmt.Errorf("%s exists", o.Path)
		}
		if !errors.Is(e, fs.ErrNotExist) {
			return e
		}
	case "non-empty":
		if e != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
			return fmt.Errorf("%s is not a non-empty regular file", o.Path)
		}
	case "empty":
		if e == nil && (!fi.Mode().IsRegular() || fi.Size() != 0) {
			return fmt.Errorf("%s is not empty", o.Path)
		}
		if e != nil && !errors.Is(e, fs.ErrNotExist) {
			return e
		}
	}
	return nil
}

// ExpectFirstLine requires a regular file's first line to be exactly Want.
type ExpectFirstLine struct {
	Path Path
	Want string
}

func (o ExpectFirstLine) Kind() string { return "expect-first-line" }
func (o ExpectFirstLine) Validate() error {
	if strings.ContainsAny(o.Want, "\r\n\x00") {
		return errors.New("FIRST_LINE_REFUSED")
	}
	return o.Path.Validate()
}
func (o ExpectFirstLine) Do(*Ctx) error {
	b, e := readRegular(o.Path, 1<<20)
	if e != nil {
		return e
	}
	first, _, _ := strings.Cut(string(b), "\n")
	if first != o.Want {
		return fmt.Errorf("%s starts %q, want %q", o.Path, first, o.Want)
	}
	return nil
}

// ExpectNoMatch requires that no line of a regular file matches a compiled pattern (Go RE2: linear time, no
// backtracking, no evaluation). The pattern is a constant of the compiled plan.
type ExpectNoMatch struct {
	Path    Path
	Pattern *regexp.Regexp
}

func (o ExpectNoMatch) Kind() string { return "expect-no-match" }
func (o ExpectNoMatch) Validate() error {
	if o.Pattern == nil {
		return errors.New("PATTERN_MISSING")
	}
	return o.Path.Validate()
}
func (o ExpectNoMatch) Do(*Ctx) error {
	b, e := readRegular(o.Path, 64<<20)
	if e != nil {
		return e
	}
	for i, l := range strings.Split(string(b), "\n") {
		if o.Pattern.MatchString(l) {
			return fmt.Errorf("%s line %d matches %s", o.Path, i+1, o.Pattern)
		}
	}
	return nil
}

// RenderVersion writes In with every "@VERSION@" replaced by H12 (12 lowercase hex) into the new file Out.
type RenderVersion struct {
	H12     string
	In, Out Path
}

var h12Pattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

func (o RenderVersion) Kind() string { return "render-version" }
func (o RenderVersion) Validate() error {
	if !h12Pattern.MatchString(o.H12) {
		return fmt.Errorf("VERSION_REFUSED %q", o.H12)
	}
	return validateAll(o.In, o.Out)
}
func (o RenderVersion) Do(*Ctx) error {
	b, e := readRegular(o.In, 1<<20)
	if e != nil {
		return e
	}
	out := strings.ReplaceAll(string(b), "@VERSION@", o.H12)
	if strings.Contains(out, "@VERSION@") || out == string(b) {
		return fmt.Errorf("%s has no @VERSION@ to render", o.In)
	}
	_, e = replaceFile(filepath.Dir(string(o.Out)), filepath.Base(string(o.Out)), out)
	return e
}

// TreeSHA256 writes "digest  path" for every regular file under Dir (sorted) into Out and requires exactly WantCount
// files; a symlink or other non-regular entry anywhere is a refusal.
type TreeSHA256 struct {
	Dir, Out  Path
	WantCount int
}

func (o TreeSHA256) Kind() string { return "tree-sha256" }
func (o TreeSHA256) Validate() error {
	if o.WantCount < 0 {
		return errors.New("COUNT_REFUSED")
	}
	return validateAll(o.Dir, o.Out)
}
func (o TreeSHA256) Do(*Ctx) error {
	var lines []string
	e := filepath.WalkDir(string(o.Dir), func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		sum, e := sha256File(Path(p))
		if e != nil {
			return e
		}
		lines = append(lines, sum+"  "+p)
		return nil
	})
	if e != nil {
		return e
	}
	sort.Strings(lines)
	if len(lines) != o.WantCount {
		return fmt.Errorf("%s holds %d regular files, want %d", o.Dir, len(lines), o.WantCount)
	}
	_, e = replaceFile(filepath.Dir(string(o.Out)), filepath.Base(string(o.Out)), strings.Join(lines, "\n")+"\n")
	return e
}

// ---- accounts ------------------------------------------------------------------------------------------------------

type account struct {
	name, gecos, home, shell string
	uid, gid                 ID
	members                  []string
}

// getent runs `getent passwd|group -- NAME` and returns the single entry. Exit 2 (not found) is an error here; the
// caller that needs absence uses ExpectAbsentAccount.
func getent(c *Ctx, db string, n Name) (account, int, error) {
	if db != "passwd" && db != "group" {
		return account{}, 0, errors.New("GETENT_DB")
	}
	var r Result
	var e error
	if db == "passwd" {
		r, e = c.Exec.Run(Cmd{Program: "getent", Args: []string{"passwd"}, Operands: []string{string(n)}, WantRC: []int{0, 2}})
	} else {
		r, e = c.Exec.Run(Cmd{Program: "getent", Args: []string{"group"}, Operands: []string{string(n)}, WantRC: []int{0, 2}})
	}
	if e != nil {
		return account{}, 0, e
	}
	if r.RC == 2 {
		if len(r.Stdout) != 0 {
			return account{}, 2, fmt.Errorf("getent %s %s: exit 2 with output", db, n)
		}
		return account{}, 2, nil
	}
	ls := strings.Split(strings.TrimSuffix(string(r.Stdout), "\n"), "\n")
	if len(ls) != 1 {
		return account{}, 0, fmt.Errorf("getent %s %s: %d entries", db, n, len(ls))
	}
	f := strings.Split(ls[0], ":")
	var a account
	switch {
	case db == "passwd" && len(f) == 7:
		uid, e1 := ParseID(f[2])
		gid, e2 := ParseID(f[3])
		if e1 != nil || e2 != nil {
			return account{}, 0, fmt.Errorf("getent passwd %s: malformed ids", n)
		}
		a = account{name: f[0], uid: uid, gid: gid, gecos: f[4], home: f[5], shell: f[6]}
	case db == "group" && len(f) == 4:
		gid, e := ParseID(f[2])
		if e != nil {
			return account{}, 0, fmt.Errorf("getent group %s: malformed gid", n)
		}
		a = account{name: f[0], gid: gid}
		if f[3] != "" {
			a.members = strings.Split(f[3], ",")
		}
	default:
		return account{}, 0, fmt.Errorf("getent %s %s: malformed entry", db, n)
	}
	if a.name != string(n) {
		return account{}, 0, fmt.Errorf("getent %s %s: returned %q", db, n, a.name)
	}
	return a, 0, nil
}

func lookupID(c *Ctx, db string, n Name) (ID, error) {
	a, rc, e := getent(c, db, n)
	if e != nil {
		return 0, e
	}
	if rc == 2 {
		return 0, fmt.Errorf("%s %s does not exist", db, n)
	}
	if db == "passwd" {
		return a.uid, nil
	}
	return a.gid, nil
}

// UserExact requires the account to exist exactly as given.
type UserExact struct {
	Name         Name
	UID, GID     ID
	Home         Path
	Gecos, Shell string
}

func (o UserExact) Kind() string { return "user-exact" }
func (o UserExact) Validate() error {
	if strings.ContainsAny(o.Gecos, ":\n\r\x00") || !strings.HasPrefix(o.Shell, "/") {
		return errors.New("ACCOUNT_FIELDS_REFUSED")
	}
	if o.Home != "/" {
		if e := o.Home.Validate(); e != nil {
			return e
		}
	}
	return o.Name.Validate()
}
func (o UserExact) Do(c *Ctx) error {
	a, rc, e := getent(c, "passwd", o.Name)
	if e != nil {
		return e
	}
	if rc == 2 || a.uid != o.UID || a.gid != o.GID || a.home != string(o.Home) || a.gecos != o.Gecos || a.shell != o.Shell {
		return fmt.Errorf("user %s is not exactly uid %d gid %d home %s gecos %q shell %s", o.Name, o.UID, o.GID, o.Home, o.Gecos, o.Shell)
	}
	return nil
}

// GroupExact requires the group to exist with exactly the gid and the explicit members (in any order).
type GroupExact struct {
	Name    Name
	GID     ID
	Members []Name
}

func (o GroupExact) Kind() string { return "group-exact" }
func (o GroupExact) Validate() error {
	for _, m := range o.Members {
		if e := m.Validate(); e != nil {
			return e
		}
	}
	return o.Name.Validate()
}
func (o GroupExact) Do(c *Ctx) error {
	a, rc, e := getent(c, "group", o.Name)
	if e != nil {
		return e
	}
	want := make([]string, 0, len(o.Members))
	for _, m := range o.Members {
		want = append(want, string(m))
	}
	got := append([]string(nil), a.members...)
	sort.Strings(want)
	sort.Strings(got)
	if rc == 2 || a.gid != o.GID || strings.Join(got, ",") != strings.Join(want, ",") {
		return fmt.Errorf("group %s is not exactly gid %d members %v (got gid %d members %v)", o.Name, o.GID, want, a.gid, got)
	}
	return nil
}

// ---- units ---------------------------------------------------------------------------------------------------------

// Systemctl starts or stops one unit.
type Systemctl struct {
	Verb string // "start" or "stop"
	Unit Unit
}

func (o Systemctl) Kind() string { return "systemctl" }
func (o Systemctl) Validate() error {
	if o.Verb != "start" && o.Verb != "stop" {
		return fmt.Errorf("SYSTEMCTL_VERB_REFUSED %q", o.Verb)
	}
	return o.Unit.Validate()
}
func (o Systemctl) Do(c *Ctx) error {
	var e error
	if o.Verb == "start" {
		_, e = c.Exec.Run(Cmd{Program: "systemctl", Args: []string{"start"}, Operands: []string{string(o.Unit)}})
	} else {
		_, e = c.Exec.Run(Cmd{Program: "systemctl", Args: []string{"stop"}, Operands: []string{string(o.Unit)}})
	}
	return e
}

// UnitProperty requires one property of a unit (MainPID, ActiveState, LoadState, UnitFileState) to equal Want; with
// Enabled it requires `is-enabled` to print "enabled".
type UnitProperty struct {
	Unit Unit
	Prop string
	Want string
}

func (o UnitProperty) Kind() string { return "unit-property" }
func (o UnitProperty) Validate() error {
	switch o.Prop {
	case "MainPID", "ActiveState", "LoadState", "is-enabled":
	default:
		return fmt.Errorf("UNIT_PROPERTY_REFUSED %q", o.Prop)
	}
	if o.Want == "" || strings.ContainsAny(o.Want, " \n\r\x00") {
		return errors.New("UNIT_WANT_REFUSED")
	}
	return o.Unit.Validate()
}
func (o UnitProperty) Do(c *Ctx) error {
	var r Result
	var e error
	switch o.Prop {
	case "MainPID":
		r, e = c.Exec.Run(Cmd{Program: "systemctl", Args: []string{"show", "-p", "MainPID", "--value"}, Operands: []string{string(o.Unit)}})
	case "ActiveState":
		r, e = c.Exec.Run(Cmd{Program: "systemctl", Args: []string{"show", "-p", "ActiveState", "--value"}, Operands: []string{string(o.Unit)}})
	case "LoadState":
		r, e = c.Exec.Run(Cmd{Program: "systemctl", Args: []string{"show", "-p", "LoadState", "--value"}, Operands: []string{string(o.Unit)}})
	case "is-enabled":
		r, e = c.Exec.Run(Cmd{Program: "systemctl", Args: []string{"is-enabled"}, Operands: []string{string(o.Unit)}, WantRC: []int{0, 1}})
	}
	if e != nil {
		return e
	}
	if got := strings.TrimSuffix(string(r.Stdout), "\n"); got != o.Want {
		return fmt.Errorf("%s %s is %q, want %q", o.Unit, o.Prop, got, o.Want)
	}
	return nil
}

// JournalNoMatch writes one unit's journal since Since into Out and requires that no line matches Pattern.
type JournalNoMatch struct {
	Unit    Unit
	Since   time.Time
	Out     string // relative to an output root
	Pattern *regexp.Regexp
}

func (o JournalNoMatch) Kind() string { return "journal-no-match" }
func (o JournalNoMatch) Validate() error {
	if o.Since.IsZero() || o.Pattern == nil || !validPackagePath(o.Out) {
		return errors.New("JOURNAL_REFUSED")
	}
	return o.Unit.Validate()
}
func (o JournalNoMatch) Do(c *Ctx) error {
	since := o.Since.UTC().Format("2006-01-02 15:04:05 UTC")
	r, e := c.Exec.Run(Cmd{Program: "journalctl", Args: []string{flagValue("--unit", string(o.Unit)), flagValue("--since", since), "--no-pager", "-o", "cat"}})
	if e != nil {
		return e
	}
	if _, e := replaceFile(filepath.Join(c.State, filepath.Dir(o.Out)), filepath.Base(o.Out), string(r.Stdout)); e != nil {
		return e
	}
	for i, l := range strings.Split(string(r.Stdout), "\n") {
		if o.Pattern.MatchString(l) {
			return fmt.Errorf("journal of %s line %d matches %s", o.Unit, i+1, o.Pattern)
		}
	}
	return nil
}

// StopNodeCleanly stops the node unit and proves a clean stop: MainPID 0, "Shutdown: done" in the part of DebugLog
// written after the stop began, and no SIGKILL in the unit's journal since then. The line count and the start time are
// taken by Go before the stop (no text count is ever re-read).
type StopNodeCleanly struct {
	Unit     Unit
	DebugLog Path
	TailOut  string // relative to an output root
	JournOut string
}

func (o StopNodeCleanly) Kind() string { return "stop-node-cleanly" }
func (o StopNodeCleanly) Validate() error {
	if !validPackagePath(o.TailOut) || !validPackagePath(o.JournOut) {
		return errors.New("OUTPUT_REFUSED")
	}
	return validateAll(o.Unit, o.DebugLog)
}
func (o StopNodeCleanly) Do(c *Ctx) error {
	before, e := readRegular(o.DebugLog, 4<<30)
	if e != nil {
		return e
	}
	t0 := time.Now()
	if e := (Systemctl{"stop", o.Unit}).Do(c); e != nil {
		return e
	}
	if e := (UnitProperty{o.Unit, "MainPID", "0"}).Do(c); e != nil {
		return e
	}
	after, e := readRegular(o.DebugLog, 4<<30)
	if e != nil {
		return e
	}
	if !bytes.HasPrefix(after, before) {
		return fmt.Errorf("%s was rewritten during the stop", o.DebugLog)
	}
	tail := after[len(before):]
	if _, e := replaceFile(filepath.Join(c.State, filepath.Dir(o.TailOut)), filepath.Base(o.TailOut), string(tail)); e != nil {
		return e
	}
	if !bytes.Contains(tail, []byte("Shutdown: done")) {
		return errors.New("the node log after the stop has no 'Shutdown: done'")
	}
	return (JournalNoMatch{Unit: o.Unit, Since: t0.Add(-time.Second), Out: o.JournOut, Pattern: regexp.MustCompile(`SIGKILL`)}).Do(c)
}

// ---- the node ------------------------------------------------------------------------------------------------------

// Node identifies the node CLI and the account it runs as. CLI and User come from the S0 baseline, validated at
// decode; the CLI is also in the plan's program table under its basename, so ExecFixed pins it.
type Node struct {
	CLI     Path
	UID     ID
	GID     ID
	Conf    Path
	Datadir Path
}

func (n Node) Validate() error { return validateAll(n.CLI, n.Conf, n.Datadir) }

var nodeMethods = map[string]bool{"getindexinfo": true, "getblockchaininfo": true, "name_show": true, "name_pending": true}

func (n Node) rpc(c *Ctx, method string, args []string, wait bool, want []int) (Result, error) {
	if !nodeMethods[method] {
		return Result{}, fmt.Errorf("NODE_RPC_REFUSED %q", method)
	}
	ops := append([]string{method}, args...)
	cmd := Cmd{Program: filepath.Base(string(n.CLI)), Args: []string{flagValue("-conf", string(n.Conf)), flagValue("-datadir", string(n.Datadir))},
		Operands: ops, NoDoubleDash: true, Cred: &Cred{UID: uint32(n.UID), GID: uint32(n.GID), Groups: []uint32{uint32(n.GID)}}, WantRC: want}
	if wait {
		cmd.Args = []string{flagValue("-conf", string(n.Conf)), flagValue("-datadir", string(n.Datadir)), "-rpcwait", "-rpcwaittimeout=60"}
	}
	return c.Exec.Run(cmd)
}

// NodeRPC runs one read-only RPC as the node's own user and writes its answer into Out.
type NodeRPC struct {
	Node   Node
	Method string
	Args   []string
	Out    string // relative to an output root
}

func (o NodeRPC) Kind() string { return "node-rpc" }
func (o NodeRPC) Validate() error {
	if !nodeMethods[o.Method] || !validPackagePath(o.Out) {
		return fmt.Errorf("NODE_RPC_REFUSED %q", o.Method)
	}
	for _, a := range o.Args {
		if !ValidOperand(a) {
			return fmt.Errorf("NODE_RPC_ARGUMENT_REFUSED %q", a)
		}
	}
	return o.Node.Validate()
}
func (o NodeRPC) Do(c *Ctx) error {
	r, e := o.Node.rpc(c, o.Method, o.Args, false, nil)
	if e != nil {
		return e
	}
	_, e = replaceFile(filepath.Join(c.State, filepath.Dir(o.Out)), filepath.Base(o.Out), string(r.Stdout))
	return e
}

// NodeSynced waits (Interval steps, at most Tries) until `getindexinfo txindex` reports synced=true. It retries only on
// RPC -28 (exit 28, warming up) or an explicit "synced": false; any other status or answer is refused at once.
type NodeSynced struct {
	Node     Node
	Tries    int
	Interval time.Duration
}

func (o NodeSynced) Kind() string { return "node-synced" }
func (o NodeSynced) Validate() error {
	if o.Tries < 1 || o.Tries > 1000 || o.Interval < 0 {
		return errors.New("NODE_WAIT_REFUSED")
	}
	return o.Node.Validate()
}
func (o NodeSynced) Do(c *Ctx) error {
	for i := 1; i <= o.Tries; i++ {
		r, e := o.Node.rpc(c, "getindexinfo", []string{"txindex"}, true, []int{0, 28})
		if e != nil {
			return e
		}
		if r.RC != 0 && r.RC != 28 {
			return fmt.Errorf("getindexinfo txindex exited %d", r.RC) // never retried, whatever the Execer
		}
		if r.RC == 0 {
			var v struct {
				Txindex *struct {
					Synced *bool `json:"synced"`
				} `json:"txindex"`
			}
			if e := json.Unmarshal(r.Stdout, &v); e != nil || v.Txindex == nil || v.Txindex.Synced == nil {
				return fmt.Errorf("getindexinfo answer without a boolean txindex.synced: %q", r.Stdout)
			}
			if *v.Txindex.Synced {
				fmt.Fprintf(c.Out, "node synced after try %d\n", i)
				return nil
			}
		}
		time.Sleep(o.Interval)
	}
	return fmt.Errorf("getindexinfo txindex not synced after %d tries", o.Tries)
}

// RouteCode calls one node route as configured in the wallet config and requires the HTTP status Want. The route's
// credential is parsed in Go and used only in memory (it replaces the curl-config pipe).
type RouteCode struct {
	WalletConfig Path
	Route        string // observer|wallet|broadcast
	Method       string // a JSON-RPC method name
	Want         int
}

var rpcMethodPattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

func (o RouteCode) Kind() string { return "route-code" }
func (o RouteCode) Validate() error {
	if o.Route != "observer" && o.Route != "wallet" && o.Route != "broadcast" {
		return fmt.Errorf("ROUTE_REFUSED %q", o.Route)
	}
	if !rpcMethodPattern.MatchString(o.Method) || o.Want < 100 || o.Want > 599 {
		return errors.New("ROUTE_CALL_REFUSED")
	}
	return o.WalletConfig.Validate()
}

type routeCred struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (o RouteCode) Do(c *Ctx) error {
	raw, e := readRegular(o.WalletConfig, 1<<20)
	if e != nil {
		return e
	}
	var cfg map[string]json.RawMessage
	if e := json.Unmarshal(raw, &cfg); e != nil {
		return errors.New("wallet config is not a JSON object")
	}
	routeRaw := cfg[o.Route]
	if o.Route == "wallet" {
		var w map[string]json.RawMessage
		if e := json.Unmarshal(cfg["wallet"], &w); e != nil {
			return errors.New("wallet route missing")
		}
		routeRaw = w["route"]
	}
	var r routeCred
	d := json.NewDecoder(bytes.NewReader(routeRaw))
	d.DisallowUnknownFields()
	if e := d.Decode(&r); e != nil || r.Host != "127.0.0.1" || r.Port <= 0 || r.Port > 65535 || r.Username == "" ||
		strings.ContainsAny(r.Username, ":\x00\r\n") || r.Password == "" {
		return fmt.Errorf("route %s is not {host 127.0.0.1, port, username, password}", o.Route)
	}
	body := fmt.Sprintf(`{"jsonrpc":"1.0","id":"s4","method":%q,"params":[]}`, o.Method)
	req, e := http.NewRequest("POST", "http://127.0.0.1:"+strconv.Itoa(r.Port)+"/", strings.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("content-type", "text/plain")
	req.SetBasicAuth(r.Username, r.Password)
	resp, e := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if e != nil {
		return fmt.Errorf("route %s: %v", o.Route, e)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != o.Want {
		return fmt.Errorf("route %s %s returned %d, want %d", o.Route, o.Method, resp.StatusCode, o.Want)
	}
	fmt.Fprintf(c.Out, "route %s %s %d\n", o.Route, o.Method, resp.StatusCode)
	return nil
}

// ---- the slot client -----------------------------------------------------------------------------------------------

// SlotStatus runs the pinned slot client (`client.py status 100`) under Cred with no supplementary group and requires
// its output (stderr merged when Merged) to be exactly Want; AnyStatus accepts any exit status (a refusal by the peer).
type SlotStatus struct {
	UID, GID  ID
	Want      string
	Merged    bool
	AnyStatus bool
}

func (o SlotStatus) Kind() string { return "slot-status" }
func (o SlotStatus) Validate() error {
	if o.Want == "" || strings.ContainsAny(o.Want, "\n\r\x00") {
		return errors.New("SLOT_WANT_REFUSED")
	}
	return nil
}
func (o SlotStatus) Do(c *Ctx) error {
	want := []int{0}
	if o.AnyStatus {
		want = make([]int, 256)
		for i := range want {
			want[i] = i
		}
	}
	r, e := c.Exec.Run(Cmd{Program: "client.py", Args: []string{"status", "100"}, Merge: o.Merged,
		Cred: &Cred{UID: uint32(o.UID), GID: uint32(o.GID), Groups: []uint32{}}, WantRC: want})
	if e != nil {
		return e
	}
	if got := strings.TrimSuffix(string(r.Stdout), "\n"); got != o.Want {
		return fmt.Errorf("client.py as %d:%d printed %q (rc %d), want %q", o.UID, o.GID, got, r.RC, o.Want)
	}
	return nil
}

// ---- the age backup ------------------------------------------------------------------------------------------------

// AgeBackup archives Paths (relative to Dir; regular files and directories only, no symlink anywhere) in memory and
// encrypts the archive with age to one Recipient into the NEW file Out. An existing Out is refused; on any failure Out
// is removed. The archive reaches age as bounded stdin produced here, never through a path or another program.
type AgeBackup struct {
	Out       Path
	Recipient string
	Dir       Path
	Paths     []string
}

var agePattern = regexp.MustCompile(`^age1[0-9a-z]{58}$`)

func (o AgeBackup) Kind() string { return "age-backup" }
func (o AgeBackup) Validate() error {
	if !agePattern.MatchString(o.Recipient) || len(o.Paths) == 0 {
		return errors.New("AGE_BACKUP_REFUSED")
	}
	for _, p := range o.Paths {
		if !validPackagePath(p) {
			return fmt.Errorf("AGE_PATH_REFUSED %q", p)
		}
	}
	return validateAll(o.Out, o.Dir)
}
func (o AgeBackup) Do(c *Ctx) error {
	if _, e := os.Lstat(string(o.Out)); !errors.Is(e, fs.ErrNotExist) {
		return fmt.Errorf("%s already exists", o.Out)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(rel string) error {
		p := filepath.Join(string(o.Dir), rel)
		fi, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return fmt.Errorf("%s is neither a regular file nor a directory", p)
		}
		h, e := tar.FileInfoHeader(fi, "")
		if e != nil {
			return e
		}
		h.Name = rel
		if fi.IsDir() {
			h.Name = rel + "/"
		}
		if e := tw.WriteHeader(h); e != nil {
			return e
		}
		if fi.Mode().IsRegular() {
			b, e := readRegular(Path(p), MaxStdin)
			if e != nil {
				return e
			}
			if _, e := tw.Write(b); e != nil {
				return e
			}
		}
		if buf.Len() > MaxStdin {
			return errors.New("the archive exceeds MaxStdin")
		}
		return nil
	}
	for _, rel := range o.Paths {
		e := filepath.WalkDir(filepath.Join(string(o.Dir), rel), func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			r, e := filepath.Rel(string(o.Dir), p)
			if e != nil {
				return e
			}
			return add(r)
		})
		if e != nil {
			return e
		}
	}
	if e := tw.Close(); e != nil {
		return e
	}
	_, e := c.Exec.Run(Cmd{Program: "age", Args: []string{flagValue("--recipient", o.Recipient), flagValue("--output", string(o.Out))}, Stdin: buf.Bytes()})
	if e != nil {
		os.Remove(string(o.Out))
		return fmt.Errorf("the age backup failed, %s removed: %v", o.Out, e)
	}
	fi, e := os.Lstat(string(o.Out))
	if e != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
		os.Remove(string(o.Out))
		return fmt.Errorf("age produced no ciphertext at %s", o.Out)
	}
	return nil
}
