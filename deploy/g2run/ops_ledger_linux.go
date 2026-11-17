//go:build linux

package g2run

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-chain-lab/deploy/g2ledger"
)

// The ledger operations call the attempt ledger IN-PROCESS (g2ledger.Run, the same code path as `deploy-kit
// g2-ledger`), with every argument a "-flag=value" built from a validated typed field. No process is started here; the
// ledger's own exec-create (the key and rpcauth tools) runs inside g2ledger, under that package's review.

// ledgerRun is the one entry point; tests replace it with a recorder.
var ledgerRun = func(args []string, out *bytes.Buffer) error { return g2ledger.Run(args, nil, out) }

func ledgerDir(c *Ctx) string { return filepath.Join(c.State, "ledger") }

// kv builds one "-flag=value" ledger argument from a validated value.
func kv(flag, value string) string {
	if strings.ContainsAny(value, "\x00\r\n") {
		panic("g2run: ledger value " + flag)
	}
	return "-" + flag + "=" + value
}

func ledger(c *Ctx, verb string, args ...string) error {
	var out bytes.Buffer
	e := ledgerRun(append([]string{verb, kv("dir", ledgerDir(c))}, args...), &out)
	c.Out.Write(out.Bytes())
	if e != nil {
		return fmt.Errorf("g2-ledger %s: %v", verb, e)
	}
	return nil
}

// LedgerInit binds the attempt: verified manifest, S0 baseline, purpose and scope.
type LedgerInit struct {
	Manifest, Baseline, Scope Path
	Purpose                   string
}

func (o LedgerInit) Kind() string { return "ledger-init" }
func (o LedgerInit) Validate() error {
	if !purposePattern.MatchString(o.Purpose) {
		return fmt.Errorf("PURPOSE_REFUSED %q", o.Purpose)
	}
	return validateAll(o.Manifest, o.Baseline, o.Scope)
}
func (o LedgerInit) Do(c *Ctx) error {
	return ledger(c, "init", kv("manifest", string(o.Manifest)), kv("baseline", string(o.Baseline)),
		kv("purpose", o.Purpose), kv("scope", string(o.Scope)))
}

// LedgerVerify checks the whole ledger chain.
type LedgerVerify struct{}

func (LedgerVerify) Kind() string    { return "ledger-verify" }
func (LedgerVerify) Validate() error { return nil }
func (LedgerVerify) Do(c *Ctx) error { return ledger(c, "verify") }

// CreateGroup creates one group with an explicit gid.
type CreateGroup struct {
	Name Name
	GID  ID
	Ret  Ret
}

func (o CreateGroup) Kind() string    { return "ledger-create-group" }
func (o CreateGroup) Validate() error { return validateAll(o.Name, o.Ret) }
func (o CreateGroup) Do(c *Ctx) error {
	return ledger(c, "create-group", kv("name", string(o.Name)), kv("gid", o.GID.String()), kv("ret", string(o.Ret)))
}

// CreateUser creates one account (nologin shell, the given role) with explicit ids.
type CreateUser struct {
	Name     Name
	UID, GID ID
	Home     Path
	Gecos    string
	Shell    Path
	Role     string // service|tree-owner
	Ret      Ret
}

func (o CreateUser) Kind() string { return "ledger-create-user" }
func (o CreateUser) Validate() error {
	if o.Role != "service" && o.Role != "tree-owner" {
		return fmt.Errorf("ROLE_REFUSED %q", o.Role)
	}
	if strings.ContainsAny(o.Gecos, ":\x00\r\n") {
		return errors.New("GECOS_REFUSED")
	}
	if o.Home != "/" {
		if e := o.Home.Validate(); e != nil {
			return e
		}
	}
	return validateAll(o.Name, o.Shell, o.Ret)
}
func (o CreateUser) Do(c *Ctx) error {
	return ledger(c, "create-user", kv("name", string(o.Name)), kv("uid", o.UID.String()), kv("gid", o.GID.String()),
		kv("home", string(o.Home)), kv("gecos", o.Gecos), kv("shell", string(o.Shell)), kv("role", o.Role), kv("ret", string(o.Ret)))
}

// AddMember adds a supplementary membership.
type AddMember struct{ User, Group Name }

func (o AddMember) Kind() string    { return "ledger-add-member" }
func (o AddMember) Validate() error { return validateAll(o.User, o.Group) }
func (o AddMember) Do(c *Ctx) error {
	return ledger(c, "add-member", kv("user", string(o.User)), kv("group", string(o.Group)))
}

// CreateDir creates one directory with its final owner, group and mode.
type CreateDir struct {
	Path         Path
	Owner, Group Name
	Mode         Mode
	Ret          Ret
}

func (o CreateDir) Kind() string    { return "ledger-create-dir" }
func (o CreateDir) Validate() error { return validateAll(o.Path, o.Owner, o.Group, o.Ret) }
func (o CreateDir) Do(c *Ctx) error {
	return ledger(c, "create-dir", kv("path", string(o.Path)), kv("owner", string(o.Owner)), kv("group", string(o.Group)),
		kv("mode", o.Mode.String()), kv("ret", string(o.Ret)))
}

// CreateFile creates one file from a source with its final owner, group and mode.
type CreateFile struct {
	Path, Src    Path
	Owner, Group Name
	Mode         Mode
	Ret          Ret
}

func (o CreateFile) Kind() string    { return "ledger-create-file" }
func (o CreateFile) Validate() error { return validateAll(o.Path, o.Src, o.Owner, o.Group, o.Ret) }
func (o CreateFile) Do(c *Ctx) error {
	return ledger(c, "create-file", kv("path", string(o.Path)), kv("src", string(o.Src)), kv("owner", string(o.Owner)),
		kv("group", string(o.Group)), kv("mode", o.Mode.String()), kv("ret", string(o.Ret)))
}

// CreateKey creates one secret key with the verified kit's g2-keygen, through the ledger's exec-create, with its
// final owner, group and mode (no second copy, no chown afterwards).
type CreateKey struct {
	Kit          Path
	Path         Path
	Owner, Group Name
	Mode         Mode
	Ret          Ret
}

func (o CreateKey) Kind() string    { return "ledger-create-key" }
func (o CreateKey) Validate() error { return validateAll(o.Kit, o.Path, o.Owner, o.Group, o.Ret) }
func (o CreateKey) Do(c *Ctx) error {
	return ledger(c, "exec-create", kv("kind", "secret"), kv("ret", string(o.Ret)), kv("path", string(o.Path)), "--",
		string(o.Kit), "g2-keygen", kv("out", string(o.Path)), kv("mode", o.Mode.String()), kv("owner", string(o.Owner)),
		kv("group", string(o.Group)))
}

// ModifyFile replaces an existing config with a staged one, live == backup required, through the ledger.
type ModifyFile struct{ Path, Backup, New Path }

func (o ModifyFile) Kind() string    { return "ledger-modify-file" }
func (o ModifyFile) Validate() error { return validateAll(o.Path, o.Backup, o.New) }
func (o ModifyFile) Do(c *Ctx) error {
	return ledger(c, "modify-file", kv("path", string(o.Path)), kv("backup", string(o.Backup)), kv("new", string(o.New)))
}

// Enable records and performs one unit enable.
type Enable struct{ Unit Unit }

func (o Enable) Kind() string    { return "ledger-enable" }
func (o Enable) Validate() error { return o.Unit.Validate() }
func (o Enable) Do(c *Ctx) error { return ledger(c, "enable", kv("unit", string(o.Unit))) }
