// Package g2ledger implements a durable attempt journal and conservative undo.
package g2ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// Failure carries the CLI contract without conflating refusal with usage.
type Failure struct {
	Code   int
	Reason string
}

func (e *Failure) Error() string         { return "g2-ledger: " + e.Reason }
func fail(code int, reason string) error { return &Failure{code, reason} }
func ExitCode(e error) int {
	if e == nil {
		return 0
	}
	var f *Failure
	if errors.As(e, &f) {
		return f.Code
	}
	return 2
}
func stopped(what string, e error) error { return fail(1, what+": "+e.Error()) }

// FSIdentity has explicit zero-valued ownership fields: omitted fields are not
// equivalent to root ownership in the canonical wire format. Secret files have
// size/mtime but no content digest. Directory identity excludes mutable times.
type FSIdentity struct {
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Type    string `json:"type"`
	Mode    uint32 `json:"mode"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtime_ns"`
	SHA256  string `json:"sha256,omitempty"`
}
type Account struct {
	Name        string `json:"name"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Shell       string `json:"shell"`
	Home        string `json:"home,omitempty"`
	Description string `json:"description,omitempty"`
}
type Membership struct {
	User    Account `json:"user"`
	Group   Account `json:"group"`
	Present bool    `json:"present"`
}
type UnitLink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}
type Unit struct {
	Name  string     `json:"name"`
	State string     `json:"state"`
	Links []UnitLink `json:"links,omitempty"`
}
type Identity struct {
	Role       string      `json:"role,omitempty"` // Ledger relation, never inferred from passwd.
	Path       string      `json:"path,omitempty"`
	FS         *FSIdentity `json:"fs,omitempty"`
	Account    *Account    `json:"account,omitempty"`
	Membership *Membership `json:"membership,omitempty"`
	Unit       *Unit       `json:"unit,omitempty"`
}

// Scope declares targets before any mutation. Parents are inventory scope only;
// declaring a directory never grants authority over arbitrary descendants.
type Scope struct {
	Paths  []ScopePath `json:"paths"`
	Users  []string    `json:"users"`
	Groups []string    `json:"groups"`
	Units  []string    `json:"units"`
}
type ScopePath struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}
type DirectoryEntry struct {
	Name string `json:"name"`
	Type uint32 `json:"type"`
}
type BaselineObject struct {
	Kind     string           `json:"kind"`
	Name     string           `json:"name"`
	Identity *Identity        `json:"identity"`
	Children []DirectoryEntry `json:"children,omitempty"`
	Members  []string         `json:"members,omitempty"`
}

type Genesis struct {
	Version        int              `json:"version"`
	Purpose        string           `json:"purpose"`
	Scope          Scope            `json:"scope"`
	S0             []BaselineObject `json:"s0"`
	Attempt        string           `json:"attempt"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	ReleaseSHA     string           `json:"release_sha"`
	Commit         string           `json:"commit"`
	H12            string           `json:"h12"`
	Baseline       string           `json:"baseline"`
	BaselineSHA256 string           `json:"baseline_sha256"`
}

// Action kinds are independent of record phases; unknown kinds fail closed.
type Action struct {
	Role         string     `json:"role,omitempty"`
	Kind         string     `json:"kind"`
	Ret          string     `json:"ret"`
	Paths        []string   `json:"paths,omitempty"`
	UID          uint32     `json:"uid"`
	GID          uint32     `json:"gid"`
	Mode         uint32     `json:"mode"`
	Name         string     `json:"name,omitempty"`
	User         string     `json:"user,omitempty"`
	Group        string     `json:"group,omitempty"`
	Backup       string     `json:"backup,omitempty"`
	BackupSHA256 string     `json:"backup_sha256,omitempty"`
	NewSHA256    string     `json:"new_sha256,omitempty"`
	Before       []Identity `json:"before,omitempty"`
	Sockets      []string   `json:"sockets,omitempty"`
	Home         string     `json:"home,omitempty"`
	Description  string     `json:"description,omitempty"`
}
type Result struct {
	Intent     uint64     `json:"intent"`
	Identities []Identity `json:"identities,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}
type Body struct {
	Op      string   `json:"op"`
	Genesis *Genesis `json:"genesis,omitempty"`
	Action  *Action  `json:"action,omitempty"`
	Result  *Result  `json:"result,omitempty"`
}
type Record struct {
	Seq  uint64 `json:"seq"`
	Prev string `json:"prev"`
	Body Body   `json:"body"`
	Hash string `json:"hash"`
}
type head struct {
	Count uint64 `json:"count"`
	Hash  string `json:"hash"`
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

var namePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var unitPattern = regexp.MustCompile(`^[a-zA-Z0-9_@.:-]+\.(service|socket|timer|target)$`)

func validPath(p string) bool {
	return filepath.IsAbs(p) && p != "/" && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}
func isHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonical(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}

// Requiring our canonical encoding also rejects duplicate/aliased JSON keys,
// omitted required zero fields, nulls, trailing values and alternate numbers.
func strict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("SCHEMA_DECODE")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("SCHEMA_TRAILING")
	}
	if !bytes.Equal(raw, canonical(v)) {
		return errors.New("SCHEMA_NONCANONICAL")
	}
	return nil
}
func recordHash(r Record) string {
	return digest(canonical(struct {
		Seq  uint64 `json:"seq"`
		Prev string `json:"prev"`
		Body Body   `json:"body"`
	}{r.Seq, r.Prev, r.Body}))
}
func validAccount(a *Account, kind string) bool {
	if a == nil || !namePattern.MatchString(a.Name) || a.UID == ^uint32(0) || a.GID == ^uint32(0) {
		return false
	}
	if kind == "group" {
		return a.UID == 0 && a.Shell == "" && a.Home == "" && a.Description == ""
	}
	return (a.Shell == "/usr/sbin/nologin" || a.Shell == "/sbin/nologin") && (a.Home == "" || a.Home == "/" || validPath(a.Home)) && !strings.ContainsAny(a.Description, ":\x00\r\n")
}
func validUserRole(role string) bool { return role == "tree-owner" || role == "service" }

func validateIdentity(i Identity, kind string) error {
	if i.Role != "" && (kind != "user" || !validUserRole(i.Role)) {
		return errors.New("IDENTITY_ROLE")
	}
	n := 0
	if i.FS != nil {
		n++
	}
	if i.Account != nil {
		n++
	}
	if i.Membership != nil {
		n++
	}
	if i.Unit != nil {
		n++
	}
	if n != 1 {
		return errors.New("IDENTITY_UNION")
	}
	switch kind {
	case "dir", "tree", "file", "secret", "modify":
		f := i.FS
		maxMode := uint32(0777)
		if kind == "dir" || kind == "tree" {
			maxMode = 07777
		}
		if f == nil || (!validPath(i.Path) && !(kind == "dir" && i.Path == "/")) || f.Dev == 0 || f.Ino == 0 || f.Mode > maxMode || f.UID == ^uint32(0) || f.GID == ^uint32(0) {
			return errors.New("IDENTITY_FS")
		}
		if kind == "dir" || kind == "tree" {
			if f.Type != "dir" || f.Size != 0 || f.MtimeNS != 0 || f.SHA256 != "" {
				return errors.New("IDENTITY_DIR")
			}
		} else {
			if f.Type != "file" || f.Size < 0 {
				return errors.New("IDENTITY_FILE")
			}
			if kind == "secret" {
				if f.SHA256 != "" {
					return errors.New("SECRET_DIGEST_FORBIDDEN")
				}
			} else if !isHex(f.SHA256, 32) {
				return errors.New("IDENTITY_DIGEST")
			}
		}
	case "user", "group":
		if i.Path != "" || !validAccount(i.Account, kind) {
			return errors.New("IDENTITY_ACCOUNT")
		}
	case "membership":
		m := i.Membership
		// Existing membership subjects may have login shells; creation requires nologin.
		if i.Path != "" || m == nil || !namePattern.MatchString(m.User.Name) || m.User.Shell == "" || m.User.UID == ^uint32(0) || m.User.GID == ^uint32(0) || !validAccount(&m.Group, "group") {
			return errors.New("IDENTITY_MEMBERSHIP")
		}
	case "unit":
		if i.Path != "" || i.Unit == nil || !unitPattern.MatchString(i.Unit.Name) || (i.Unit.State != "enabled" && i.Unit.State != "disabled") {
			return errors.New("IDENTITY_UNIT")
		}
		seen := map[string]bool{}
		for _, link := range i.Unit.Links {
			if !validPath(link.Path) || !validPath(link.Target) || link.Dev == 0 || link.Ino == 0 || link.UID == ^uint32(0) || link.GID == ^uint32(0) || link.Mode != 0120777 || seen[link.Path] {
				return errors.New("IDENTITY_UNIT_LINK")
			}
			seen[link.Path] = true
		}
		if i.Unit.State == "disabled" && len(i.Unit.Links) != 0 {
			return errors.New("IDENTITY_DISABLED_LINKS")
		}
	default:
		return errors.New("UNKNOWN_KIND")
	}
	return nil
}
func validateAction(a *Action) error {
	if a == nil || a.UID == ^uint32(0) || a.GID == ^uint32(0) || (a.Ret != "d6" && a.Ret != "state" && a.Ret != "remove" && a.Ret != "rehearsal") {
		return errors.New("ACTION_RETENTION")
	}
	clean := *a
	switch a.Kind {
	case "dir", "tree", "file", "secret", "modify":
		if len(a.Paths) == 0 || (a.Kind == "dir" || a.Kind == "tree" || a.Kind == "modify") && len(a.Paths) != 1 || a.Mode > 0777 {
			return errors.New("ACTION_PATHS")
		}
		seen := map[string]bool{}
		for _, p := range a.Paths {
			if !validPath(p) || seen[p] {
				return errors.New("ACTION_PATH")
			}
			if e := targetPathPolicy(p); e != nil {
				return e
			}
			seen[p] = true
		}
		clean.Paths = nil
		clean.UID = 0
		clean.GID = 0
		clean.Mode = 0
		if a.Kind == "tree" {
			if len(a.Before) != 1 || validateIdentity(a.Before[0], "user") != nil || a.Before[0].Account.Name != a.User || a.Before[0].Account.UID != a.UID || a.Before[0].Account.GID != a.GID || forbiddenTreeID(a.UID) || forbiddenTreeID(a.GID) {
				return errors.New("TREE_OWNER_FORBIDDEN_OR_INVALID")
			}
			previous := ""
			for _, name := range a.Sockets {
				if !validTreeRelative(name) || name <= previous {
					return errors.New("TREE_SOCKET_PATH")
				}
				previous = name
			}
			clean.User = ""
			clean.Before = nil
			clean.Sockets = nil
		}
		if a.Kind == "modify" {
			if a.Ret != "state" || !validPath(a.Backup) || !isHex(a.BackupSHA256, 32) || !isHex(a.NewSHA256, 32) || len(a.Before) != 1 {
				return errors.New("ACTION_MODIFY")
			}
			if e := validateIdentity(a.Before[0], "modify"); e != nil {
				return e
			}
			if a.Before[0].Path != a.Paths[0] || a.Before[0].FS.SHA256 != a.BackupSHA256 {
				return errors.New("ACTION_BACKUP")
			}
			clean.Backup = ""
			clean.BackupSHA256 = ""
			clean.NewSHA256 = ""
			clean.Before = nil
		}
	case "user", "group":
		if !namePattern.MatchString(a.Name) {
			return errors.New("ACTION_ACCOUNT")
		}
		clean.Name = ""
		clean.GID = 0
		if a.Kind == "user" {
			if !validUserRole(a.Role) {
				return errors.New("ACTION_USER_ROLE")
			}
			clean.Role = ""
			if a.Home != "" && a.Home != "/" && !validPath(a.Home) || strings.ContainsAny(a.Description, ":\x00\r\n") {
				return errors.New("ACTION_USER_PROFILE")
			}
			clean.Home = ""
			clean.Description = ""
			clean.UID = 0
		}
	case "membership":
		if a.Ret != "remove" || !namePattern.MatchString(a.User) || !namePattern.MatchString(a.Group) || len(a.Before) != 1 {
			return errors.New("ACTION_MEMBER")
		}
		if e := validateIdentity(a.Before[0], "membership"); e != nil {
			return e
		}
		m := a.Before[0].Membership
		if m.Present || m.User.Name != a.User || m.Group.Name != a.Group {
			return errors.New("ACTION_MEMBER_BEFORE")
		}
		clean.User = ""
		clean.Group = ""
		clean.Before = nil
	case "unit":
		if a.Ret != "state" || !unitPattern.MatchString(a.Name) || len(a.Before) != 1 {
			return errors.New("ACTION_UNIT")
		}
		if e := validateIdentity(a.Before[0], "unit"); e != nil {
			return e
		}
		if a.Before[0].Unit.Name != a.Name || a.Before[0].Unit.State != "disabled" {
			return errors.New("ACTION_UNIT_BEFORE")
		}
		clean.Name = ""
		clean.Before = nil
	default:
		return errors.New("UNKNOWN_KIND")
	}
	if !bytes.Equal(canonical(clean), canonical(Action{Kind: a.Kind, Ret: a.Ret})) {
		return errors.New("ACTION_EXTRA_FIELDS")
	}
	return nil
}
func validateResult(a Action, ids []Identity) error {
	n := 1
	if len(a.Paths) > 0 {
		n = len(a.Paths)
	}
	if len(ids) != n {
		return errors.New("RESULT_COUNT")
	}
	for j, i := range ids {
		if e := validateIdentity(i, a.Kind); e != nil {
			return e
		}
		switch a.Kind {
		case "dir", "tree", "file", "secret", "modify":
			if i.Path != a.Paths[j] {
				return errors.New("RESULT_PATH")
			}
			if a.Kind == "modify" && i.FS.SHA256 != a.NewSHA256 {
				return errors.New("RESULT_NEW_HASH")
			}
			if i.FS.UID != a.UID || i.FS.GID != a.GID || i.FS.Mode != a.Mode {
				return errors.New("RESULT_METADATA")
			}
		case "user", "group":
			if i.Role != a.Role {
				return errors.New("RESULT_USER_ROLE")
			}
			if a.Kind == "user" && a.Home != "" && i.Account.Shell != "/usr/sbin/nologin" {
				return errors.New("RESULT_USER_SHELL")
			}
			if a.Kind == "user" && a.Home == "" && i.Account.Home != "" && i.Account.Home != "/nonexistent" {
				return errors.New("RESULT_USER_HOME")
			}
			if i.Account.Name != a.Name || i.Account.GID != a.GID || a.Kind == "user" && (i.Account.UID != a.UID || a.Home != "" && i.Account.Home != a.Home || i.Account.Description != a.Description) {
				return errors.New("RESULT_ACCOUNT")
			}
		case "membership":
			m := *i.Membership
			m.Present = false
			if !i.Membership.Present || !bytes.Equal(canonical(m), canonical(*a.Before[0].Membership)) {
				return errors.New("RESULT_MEMBER")
			}
		case "unit":
			if i.Unit.Name != a.Name || i.Unit.State != "enabled" || len(i.Unit.Links) == 0 {
				return errors.New("RESULT_UNIT")
			}
		}
	}
	return nil
}
func actionName(a Action) string {
	if len(a.Paths) > 0 {
		return strings.Join(a.Paths, ", ")
	}
	if a.Name != "" {
		return a.Name
	}
	return a.User + ":" + a.Group
}
func identityEqual(a, b Identity) bool { return bytes.Equal(canonical(a), canonical(b)) }
func accountEqual(a, b Account) bool {
	return a.Name == b.Name && a.UID == b.UID && a.GID == b.GID && a.Shell == b.Shell && a.Home == b.Home && a.Description == b.Description
}
func orphan(a Action) error   { return fail(3, "ORPHAN "+actionName(a)) }
func mismatch(a Action) error { return fail(1, "IDENTITY_MISMATCH "+actionName(a)) }
func namedError(reason string, a Action) error {
	return fail(1, fmt.Sprintf("%s %s", reason, actionName(a)))
}
