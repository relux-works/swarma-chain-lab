package g2ledger

import (
	"errors"
	"flag"
	"io"
	"strconv"
)

type pathsFlag []string

func (p *pathsFlag) String() string { return "declared output paths" }
func (p *pathsFlag) Set(s string) error {
	if len(*p) >= 64 {
		return errors.New("PATH_COUNT")
	}
	*p = append(*p, s)
	return nil
}

// Run is the CLI adapter; injected System only changes privileged operations.
func Run(args []string, sys System, out io.Writer) error {
	if len(args) == 0 {
		return fail(2, "usage: g2-ledger init|verify|create-dir|create-file|exec-create|modify-file|create-user|create-group|add-member|enable|replay [flags]")
	}
	op := args[0]
	f := flag.NewFlagSet("g2-ledger "+op, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("dir", "", "private ledger directory")
	var path, src, owner, group, mode, ret, manifest, baseline, backup, newPath, kind, name, user, unit, replayMode string
	var uid, gid uint64
	var secret bool
	var paths pathsFlag
	switch op {
	case "init":
		f.StringVar(&manifest, "manifest", "", "verified release manifest")
		f.StringVar(&baseline, "baseline", "", "S0 directory")
	case "verify":
	case "create-dir", "create-file":
		f.StringVar(&path, "path", "", "new absolute path")
		f.StringVar(&owner, "owner", "", "owner name or numeric uid")
		f.StringVar(&group, "group", "", "group name or numeric gid")
		f.StringVar(&mode, "mode", "", "octal mode")
		f.StringVar(&ret, "ret", "", "d6|state|remove")
		if op == "create-file" {
			f.StringVar(&src, "src", "", "source file")
			f.BoolVar(&secret, "secret", false, "omit content digest")
		}
	case "exec-create":
		f.StringVar(&kind, "kind", "", "file|secret")
		f.StringVar(&ret, "ret", "", "d6|state|remove")
		f.Var(&paths, "path", "declared output; repeat for each output")
	case "modify-file":
		f.StringVar(&path, "path", "", "existing config")
		f.StringVar(&backup, "backup", "", "S0 copy")
		f.StringVar(&newPath, "new", "", "staged replacement")
	case "create-user", "create-group":
		f.StringVar(&name, "name", "", "account name")
		f.StringVar(&ret, "ret", "", "d6|state|remove")
		f.Uint64Var(&gid, "gid", 1<<32, "explicit gid")
		if op == "create-user" {
			f.Uint64Var(&uid, "uid", 1<<32, "explicit uid")
		}
	case "add-member":
		f.StringVar(&user, "user", "", "user")
		f.StringVar(&group, "group", "", "group")
	case "enable":
		f.StringVar(&unit, "unit", "", "unit name")
	case "replay":
		f.StringVar(&replayMode, "mode", "", "station|station-remove|rehearsal")
	default:
		return fail(2, "UNKNOWN_SUBCOMMAND")
	}
	if f.Parse(args[1:]) != nil || !validPath(*dir) || op != "exec-create" && f.NArg() != 0 {
		return fail(2, "USAGE_FLAGS")
	}
	validRet := func() bool { return ret == "d6" || ret == "state" || ret == "remove" }
	switch op {
	case "init":
		if !validPath(manifest) || !validPath(baseline) {
			return fail(2, "USAGE_INIT")
		}
		return Init(*dir, manifest, baseline)
	case "create-dir", "create-file":
		if !validPath(path) || owner == "" || group == "" || mode == "" || !validRet() || op == "create-file" && !validPath(src) {
			return fail(2, "USAGE_CREATE")
		}
	case "exec-create":
		if len(paths) == 0 || f.NArg() == 0 || !validRet() || kind != "file" && kind != "secret" {
			return fail(2, "USAGE_EXEC")
		}
		for _, p := range paths {
			if !validPath(p) {
				return fail(2, "USAGE_EXEC_PATH")
			}
		}
	case "modify-file":
		if !validPath(path) || !validPath(backup) || !validPath(newPath) {
			return fail(2, "USAGE_MODIFY")
		}
	case "create-user", "create-group":
		if !namePattern.MatchString(name) || gid >= 1<<32 || uid >= 1<<32 || !validRet() {
			return fail(2, "USAGE_ACCOUNT")
		}
	case "add-member":
		if !namePattern.MatchString(user) || !namePattern.MatchString(group) {
			return fail(2, "USAGE_MEMBER")
		}
	case "enable":
		if !unitPattern.MatchString(unit) {
			return fail(2, "USAGE_UNIT")
		}
	case "replay":
		if replayMode != "station" && replayMode != "station-remove" && replayMode != "rehearsal" {
			return fail(2, "USAGE_REPLAY")
		}
	}
	l, e := Open(*dir, sys)
	if e != nil {
		return e
	}
	defer l.Close()
	l.output = out
	switch op {
	case "verify":
		return nil
	case "replay":
		return l.Replay(replayMode)
	case "create-dir", "create-file":
		m, e := strconv.ParseUint(mode, 8, 32)
		if e != nil || m > 0777 {
			return fail(2, "USAGE_MODE")
		}
		u, e := resolveID(l.sys, "user", owner)
		if e != nil {
			return e
		}
		g, e := resolveID(l.sys, "group", group)
		if e != nil {
			return e
		}
		kind := "dir"
		if op == "create-file" {
			kind = "file"
			if secret {
				kind = "secret"
			}
		}
		return l.CreateFS(path, src, kind, ret, u, g, uint32(m))
	case "exec-create":
		return l.ExecCreate(kind, ret, paths, f.Args())
	case "modify-file":
		return l.ModifyFile(path, backup, newPath)
	case "create-user":
		return l.CreateAccount("user", name, ret, uint32(uid), uint32(gid))
	case "create-group":
		return l.CreateAccount("group", name, ret, 0, uint32(gid))
	case "add-member":
		return l.AddMember(user, group)
	case "enable":
		return l.Enable(unit)
	}
	return fail(2, "INTERNAL_DISPATCH")
}
func resolveID(sys System, kind, name string) (uint32, error) {
	if n, e := number(name); e == nil {
		return n, nil
	}
	if !namePattern.MatchString(name) {
		return 0, fail(2, "USAGE_OWNER")
	}
	a, _, e := lookup(sys, kind, name)
	if e != nil {
		return 0, stopped("OWNER_LOOKUP "+name, e)
	}
	if a == nil {
		return 0, fail(1, "OWNER_MISSING "+name)
	}
	if kind == "user" {
		return a.UID, nil
	}
	return a.GID, nil
}
