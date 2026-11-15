//go:build linux

package g2run

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type BaselineDeps struct {
	Lookup    PortLookupOps
	Groups    PortGroupReader
	Units     PortUnitReader
	Inventory PortInventory
}
type BaselineNode struct{ Unit, Config, CLI string }

// Baseline is the g2-baseline port. Every evidence name is preserved. Dirs,
// account keys, units and node paths are instance parameters. The parent of Out
// must exist; Out itself is exclusive, and all directories/files are 0700/0600.
type Baseline struct {
	FS                         PortFS
	Out, Purpose, Operator     string
	Dirs, Users, Groups, Units []string
	IDs                        []uint32
	Node                       *BaselineNode
	Deps                       BaselineDeps
}

func (Baseline) Kind() string { return "baseline" }
func (b Baseline) Validate() error {
	if e := b.FS.Validate(); e != nil {
		return e
	}
	if !portPurpose(b.Purpose) || !portAccount(b.Operator) {
		return errors.New("BASELINE_PARAMETERS")
	}
	if b.Deps.Lookup == nil || b.Deps.Groups == nil || b.Deps.Units == nil || b.Deps.Inventory == nil {
		return errors.New("BASELINE_E2_DEPENDENCIES")
	}
	if e := portPaths(b.FS, b.Out, filepath.Dir(b.Out)); e != nil {
		return e
	}
	if len(b.Dirs) > 1024 || len(b.IDs) > 1024 || len(b.Users) > 1024 || len(b.Groups) > 1024 || len(b.Units) > 1024 {
		return errors.New("BASELINE_COUNT")
	}
	names := map[string]bool{}
	for _, d := range b.Dirs {
		if !b.FS.allowed(d) || portWithin(b.Out, d) || portWithin(d, b.Out) {
			return errors.New("BASELINE_DIRECTORY")
		}
		n := baselineName(d)
		if names[n] {
			return errors.New("BASELINE_DUPLICATE_DIRECTORY")
		}
		names[n] = true
	}
	for _, n := range append(append([]string{}, b.Users...), b.Groups...) {
		if !portAccount(n) {
			return errors.New("BASELINE_ACCOUNT")
		}
	}
	for _, n := range b.IDs {
		if n == ^uint32(0) {
			return errors.New("BASELINE_ID")
		}
	}
	for _, u := range b.Units {
		if !portUnit(u) {
			return errors.New("BASELINE_UNIT")
		}
	}
	if b.Purpose == "station" {
		if b.Node == nil || !portUnit(b.Node.Unit) || portPaths(b.FS, b.Node.Config, b.Node.CLI) != nil {
			return errors.New("BASELINE_NODE")
		}
	} else if b.Node != nil {
		return errors.New("BASELINE_REHEARSAL_NODE")
	}
	return nil
}
func baselineName(p string) string { return strings.ReplaceAll(p, "/", "_") + ".txt" }
func (b Baseline) Do(c *Ctx) (err error) {
	if e := b.Validate(); e != nil {
		return e
	}
	if c == nil {
		return errors.New("BASELINE_CONTEXT")
	}
	if e := b.FS.mkdir(b.Out); e != nil {
		return e
	}
	if e := b.FS.writeAtomic(b.Out+"/errors.txt", nil, 0600); e != nil {
		return e
	}
	ef, e := b.FS.open(b.Out+"/errors.txt", unix.O_WRONLY|unix.O_APPEND, false)
	if e != nil {
		return e
	}
	defer ef.Close()
	phase := "directories"
	defer func() {
		if err != nil {
			_, we := fmt.Fprintf(ef, "BASELINE_INCOMPLETE phase=%s\n", phase)
			if we == nil {
				we = ef.Sync()
			}
			if we != nil {
				err = errors.Join(err, errors.New("BASELINE_ERROR_LOG_WRITE"))
			}
		}
	}()
	if e = b.FS.mkdir(b.Out + "/ls"); e != nil {
		return e
	}
	if e = b.FS.mkdir(b.Out + "/meta"); e != nil {
		return e
	}
	put := func(name string, raw []byte) error { return b.FS.writeAtomic(b.Out+"/"+name, raw, 0600) }
	for _, d := range b.Dirs {
		phase = "directory." + baselineName(d)
		info, e := b.FS.stat(d)
		if errors.Is(e, os.ErrNotExist) {
			if e = put("ls/"+baselineName(d), []byte("ABSENT\n")); e != nil {
				return e
			}
			continue
		}
		if e != nil {
			return e
		}
		if !info.IsDir() {
			return errors.New("BASELINE_NOT_PLAIN_DIRECTORY")
		}
		f, e := b.FS.open(d, unix.O_RDONLY, true)
		if e != nil {
			return e
		}
		entries, e := f.ReadDir(-1)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		names := make([]string, 0, len(entries))
		for _, en := range entries {
			if strings.ContainsAny(en.Name(), "\x00\r\n") {
				return errors.New("BASELINE_ENTRY_ENCODING")
			}
			names = append(names, en.Name())
		}
		sort.Strings(names)
		var listing string
		if len(names) > 0 {
			listing = strings.Join(names, "\n") + "\n"
		}
		if e = put("ls/"+baselineName(d), []byte(listing)); e != nil {
			return e
		}
		df, e := b.FS.open(d, unix.O_RDONLY, true)
		if e != nil {
			return e
		}
		var stat unix.Stat_t
		e = unix.Fstat(int(df.Fd()), &stat)
		ce = df.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		owner, e := b.lookupName(c, PortPasswd, stat.Uid)
		if e != nil {
			return e
		}
		group, e := b.lookupName(c, PortGroup, stat.Gid)
		if e != nil {
			return e
		}
		if e = put("meta/"+baselineName(d), []byte(fmt.Sprintf("%s:%s %o\n", owner, group, stat.Mode&07777))); e != nil {
			return e
		}
	}
	phase = "accounts"
	var accounts bytes.Buffer
	for _, id := range b.IDs {
		key := strconv.FormatUint(uint64(id), 10)
		for _, db := range []PortDatabase{PortPasswd, PortGroup} {
			phase = "accounts." + string(db) + "." + key
			rec, e := lookupPort(c, b.Deps.Lookup, PortLookup{db, key})
			if e != nil {
				return e
			}
			value := ""
			if rec != nil {
				value = rec.Name
			}
			fmt.Fprintf(&accounts, "%s %s: %s\n", db, key, value)
		}
	}
	for _, u := range b.Users {
		phase = "accounts.user." + u
		rec, e := lookupPort(c, b.Deps.Lookup, PortLookup{PortPasswd, u})
		if e != nil {
			return e
		}
		value := ""
		if rec != nil {
			value = fmt.Sprintf("%d:%d", rec.ID, rec.Primary)
		}
		fmt.Fprintf(&accounts, "user %s: %s\n", u, value)
	}
	for _, g := range b.Groups {
		phase = "accounts.group." + g
		rec, e := lookupPort(c, b.Deps.Lookup, PortLookup{PortGroup, g})
		if e != nil {
			return e
		}
		value := ""
		if rec != nil {
			value = rec.Fields[2] + ":" + rec.Fields[3]
		}
		fmt.Fprintf(&accounts, "group %s: %s\n", g, value)
	}
	phase = "accounts.operator"
	user, e := lookupPort(c, b.Deps.Lookup, PortLookup{PortPasswd, b.Operator})
	if e != nil {
		return e
	}
	if user == nil {
		return errors.New("BASELINE_OPERATOR_MISSING")
	}
	group, e := lookupPort(c, b.Deps.Lookup, PortLookup{PortGroup, strconv.FormatUint(uint64(user.Primary), 10)})
	if e != nil {
		return e
	}
	if group == nil {
		return errors.New("BASELINE_OPERATOR_GROUP_MISSING")
	}
	groups, e := portGroups(c, b.Deps.Groups, b.Operator)
	if e != nil {
		return e
	}
	fmt.Fprintf(&accounts, "id %s: uid=%d(%s) gid=%d(%s) groups=", b.Operator, user.ID, user.Name, user.Primary, group.Name)
	for i, g := range groups {
		if i != 0 {
			accounts.WriteByte(',')
		}
		fmt.Fprintf(&accounts, "%d(%s)", g.ID, g.Name)
	}
	accounts.WriteByte('\n')
	if e = put("accounts.txt", accounts.Bytes()); e != nil {
		return e
	}
	phase = "node"
	if b.Purpose == "station" {
		if e = b.node(c, put); e != nil {
			return e
		}
	} else if e = put("meta/node-skipped.txt", []byte("rehearsal: no node-specific read (no node of this attempt)\n")); e != nil {
		return e
	}
	phase = "units"
	for _, u := range b.Units {
		phase = "unit." + u
		s, e := portUnitInfo(c, b.Deps.Units, u)
		if e != nil {
			return e
		}
		if e = put("meta/unit-"+u+".txt", s.baseline()); e != nil {
			return e
		}
	}
	phase = "listeners"
	listeners, e := b.Deps.Inventory.Listeners(c)
	if e != nil || len(listeners) > 1<<20 {
		return errors.New("BASELINE_LISTENERS")
	}
	set := map[string]bool{}
	for _, s := range listeners {
		if s == "" || strings.ContainsAny(s, "\x00\r\n") {
			return errors.New("BASELINE_LISTENER_SHAPE")
		}
		set[s] = true
	}
	listeners = nil
	for s := range set {
		listeners = append(listeners, s)
	}
	sort.Strings(listeners)
	text := ""
	if len(listeners) > 0 {
		text = strings.Join(listeners, "\n") + "\n"
	}
	if e = put("listen-local.txt", []byte(text)); e != nil {
		return e
	}
	phase = "unit-inventory"
	rows, e := portUnits(c, b.Deps.Inventory)
	if e != nil {
		return e
	}
	var units bytes.Buffer
	for _, r := range rows {
		units.WriteString(r.Line)
		units.WriteByte('\n')
	}
	if e = put("units.txt", units.Bytes()); e != nil {
		return e
	}
	phase = "taken-at"
	return put("taken-at.txt", []byte(time.Now().UTC().Format("2006-01-02T15:04:05Z")+"\n"))
}
func (b Baseline) lookupName(c *Ctx, db PortDatabase, id uint32) (string, error) {
	r, e := lookupPort(c, b.Deps.Lookup, PortLookup{db, strconv.FormatUint(uint64(id), 10)})
	if e != nil {
		return "", e
	}
	if r == nil {
		return "UNKNOWN", nil
	}
	return r.Name, nil
}

var plaintextRPCPassword = regexp.MustCompile(`(?m)^[\t\v\f\r ]*(main\.)?rpcpassword[\t\v\f\r ]*=`)

func (b Baseline) node(c *Ctx, put func(string, []byte) error) error {
	raw, e := b.FS.read(b.Node.Config)
	if e != nil {
		return errors.New("BASELINE_NODE_CONFIG")
	}
	if plaintextRPCPassword.Match(raw) {
		return errors.New("BASELINE_PLAINTEXT_CREDENTIAL")
	}
	if e = put("namecoin.conf", raw); e != nil {
		return e
	}
	f, e := b.FS.open(b.Node.Config, unix.O_RDONLY, false)
	if e != nil {
		return e
	}
	var st unix.Stat_t
	e = unix.Fstat(int(f.Fd()), &st)
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	owner, e := b.lookupName(c, PortPasswd, st.Uid)
	if e != nil {
		return e
	}
	group, e := b.lookupName(c, PortGroup, st.Gid)
	if e != nil {
		return e
	}
	if e = put("namecoin.conf.meta", []byte(fmt.Sprintf("%s %s %o\n", owner, group, st.Mode&07777))); e != nil {
		return e
	}
	if e = put("namecoin.conf.sha256", []byte(portDigestBytes(raw)+"  "+b.Node.Config+"\n")); e != nil {
		return e
	}
	unit, e := portUnitInfo(c, b.Deps.Units, b.Node.Unit)
	if e != nil {
		return e
	}
	if e = put("meta/unit-"+b.Node.Unit+".txt", unit.baseline()); e != nil {
		return e
	}
	if unit.LoadState != "loaded" {
		return errors.New("BASELINE_NODE_NOT_LOADED")
	}
	user := unit.User
	if user == "" {
		user = "root"
	}
	if !portAccount(user) {
		return errors.New("BASELINE_NODE_USER")
	}
	if e = put("meta/node-user.txt", []byte(user+"\n")); e != nil {
		return e
	}
	if _, e = b.FS.openExecutable(b.Node.CLI); e != nil {
		return e
	}
	return put("meta/node-cli.txt", []byte(b.Node.CLI+"\n"))
}
func (fs PortFS) openExecutable(p string) (bool, error) {
	f, e := fs.open(p, unix.O_RDONLY, false)
	if e != nil {
		return false, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return false, e
	}
	if st.Mode().Perm()&0111 == 0 {
		return false, errors.New("NODE_CLI_NOT_EXECUTABLE")
	}
	return true, nil
}
