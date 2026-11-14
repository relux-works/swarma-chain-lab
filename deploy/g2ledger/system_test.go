//go:build linux

package g2ledger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fakeReply struct {
	out    string
	status int
	err    error
}
type fakeSystem struct {
	unitRoot   string
	unitFiles  map[string]string
	also       map[string][]string
	unitLinks  map[string][]UnitLink
	usergroups bool // models login.defs USERGROUPS_ENAB, independent of ledger policy
	chownError error
	users      map[string]Account
	groups     map[string]Account
	members    map[string]map[string]bool
	units      map[string]string
	live       map[string]bool
	calls      []string
	fault      func(string, []string) (fakeReply, bool)
	tool       func(string, []string) (string, int, error)
}

func newSystem() *fakeSystem {
	return &fakeSystem{unitFiles: map[string]string{}, also: map[string][]string{}, unitLinks: map[string][]UnitLink{}, users: map[string]Account{}, groups: map[string]Account{}, members: map[string]map[string]bool{}, units: map[string]string{}, live: map[string]bool{}}
}
func (s *fakeSystem) Chown(f *os.File, u, g uint32) error {
	if s.chownError != nil {
		return s.chownError
	}
	return (RealSystem{}).Chown(f, u, g)
}
func (s *fakeSystem) Run(cmd string, args ...string) (string, int, error) {
	s.calls = append(s.calls, cmd+" "+strings.Join(args, " "))
	if s.fault != nil {
		if r, ok := s.fault(cmd, args); ok {
			return r.out, r.status, r.err
		}
	}
	switch cmd {
	case "/usr/bin/getent":
		db, key := args[0], args[1]
		table := s.users
		if db == "group" {
			table = s.groups
		}
		var found *Account
		for name, a := range table {
			id := a.UID
			if db == "group" {
				id = a.GID
			}
			if name == key || strconv.FormatUint(uint64(id), 10) == key {
				copy := a
				found = &copy
				break
			}
		}
		if found == nil {
			return "", 2, nil
		}
		a := *found
		if db == "passwd" {
			home := a.Home
			if home == "" {
				home = "/nonexistent"
			}
			return fmt.Sprintf("%s:x:%d:%d:%s:%s:%s\n", a.Name, a.UID, a.GID, a.Description, home, a.Shell), 0, nil
		}
		ms := []string{}
		for u, yes := range s.members[a.Name] {
			if yes {
				ms = append(ms, u)
			}
		}
		return fmt.Sprintf("%s:x:%d:%s\n", a.Name, a.GID, strings.Join(ms, ",")), 0, nil
	case "/usr/sbin/groupadd":
		name := args[len(args)-1]
		n, _ := strconv.ParseUint(args[1], 10, 32)
		if _, ok := s.groups[name]; ok {
			return "", 9, nil
		}
		for _, g := range s.groups {
			if g.GID == uint32(n) {
				return "", 4, nil
			}
		}
		s.groups[name] = Account{Name: name, GID: uint32(n)}
		return "", 0, nil
	case "/usr/sbin/useradd":
		name := args[len(args)-1]
		if _, ok := s.users[name]; ok {
			return "", 9, nil
		}
		a := Account{Name: name}
		for i := 0; i < len(args)-1; i++ {
			switch args[i] {
			case "-u":
				v, _ := strconv.ParseUint(args[i+1], 10, 32)
				a.UID = uint32(v)
			case "-g":
				v, _ := strconv.ParseUint(args[i+1], 10, 32)
				a.GID = uint32(v)
			case "-d":
				a.Home = args[i+1]
			case "-c":
				a.Description = args[i+1]
			case "-s":
				a.Shell = args[i+1]
			}
		}
		for _, u := range s.users {
			if u.UID == a.UID {
				return "", 4, nil
			}
		}
		groupFound := false
		for _, g := range s.groups {
			if g.GID == a.GID {
				groupFound = true
			}
		}
		if !groupFound {
			return "", 6, nil
		}
		if a.Shell != "/usr/sbin/nologin" {
			return "", 3, nil
		}
		s.users[name] = a
		return "", 0, nil
	case "/usr/sbin/usermod":
		if len(args) != 3 || args[0] != "-aG" {
			return "", 2, nil
		}
		group, user := args[1], args[2]
		if _, ok := s.users[user]; !ok {
			return "", 6, nil
		}
		if _, ok := s.groups[group]; !ok {
			return "", 6, nil
		}
		if s.members[group] == nil {
			s.members[group] = map[string]bool{}
		}
		s.members[group][user] = true
		return "", 0, nil
	case "/usr/sbin/userdel":
		name := args[0]
		if _, ok := s.users[name]; !ok {
			return "", 6, nil
		}
		if s.live[name] {
			return "", 8, nil
		}
		delete(s.users, name)
		if group, ok := s.groups[name]; ok && s.usergroups {
			used := false
			for _, user := range s.users {
				used = used || user.GID == group.GID
			}
			for user, present := range s.members[name] {
				used = used || user != name && present
			}
			if !used {
				delete(s.groups, name)
				delete(s.members, name)
			}
		}
		for _, m := range s.members {
			delete(m, name)
		}
		return "", 0, nil
	case "/usr/sbin/groupdel":
		name := args[0]
		g, ok := s.groups[name]
		if !ok {
			return "", 6, nil
		}
		for _, u := range s.users {
			if u.GID == g.GID {
				return "", 8, nil
			}
		}
		delete(s.groups, name)
		delete(s.members, name)
		return "", 0, nil
	case "/usr/bin/gpasswd":
		user, group := args[1], args[2]
		if !s.members[group][user] {
			return "", 3, nil
		}
		delete(s.members[group], user)
		return "", 0, nil
	case "/usr/bin/systemctl":
		verb := args[0]
		if verb == "daemon-reload" {
			for name, links := range s.unitLinks {
				present := false
				for _, link := range links {
					_ = filepath.WalkDir(s.unitRoot, func(path string, entry os.DirEntry, err error) error {
						if err != nil {
							return err
						}
						if entry.Type()&os.ModeSymlink != 0 {
							target, _ := os.Readlink(path)
							present = present || target == link.Target
						}
						return nil
					})
				}
				if !present {
					s.units[name] = "disabled"
				}
			}
			return "", 0, nil
		}
		name := args[1]
		if verb == "cat" {
			if text, ok := s.unitFiles[name]; ok {
				return text, 0, nil
			}
			if _, ok := s.units[name]; ok {
				return "[Unit]\nDescription=fixture\n[Install]\nWantedBy=multi-user.target\n", 0, nil
			}
			return "", 1, nil
		}
		state, ok := s.units[name]
		if verb == "is-enabled" {
			if !ok {
				return "not-found\n", 4, nil
			}
			if state == "enabled" {
				return "enabled\n", 0, nil
			}
			if state == "disabled" {
				return "disabled\n", 1, nil
			}
			status := 1
			if state == "enabled-runtime" || state == "alias" || state == "static" || state == "indirect" || state == "generated" || state == "transient" {
				status = 0
			}
			return state + "\n", status, nil
		}
		if !ok {
			return "", 1, nil
		}
		if verb == "enable" {
			output := ""
			for _, unit := range append([]string{name}, s.also[name]...) {
				path := filepath.Join(s.unitRoot, "multi-user.target.wants", unit)
				target := filepath.Join(s.unitRoot, unit)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					return "", -1, err
				}
				if _, err := os.Lstat(path); os.IsNotExist(err) {
					if err = os.Symlink(target, path); err != nil {
						return "", -1, err
					}
					output += fmt.Sprintf("Created symlink %s -> %s.\n", path, target)
					s.unitLinks[unit] = append(s.unitLinks[unit], UnitLink{Path: path, Target: target})
				}
				s.units[unit] = "enabled"
			}
			return output, 0, nil
		}
		if verb == "disable" {
			for _, unit := range append([]string{name}, s.also[name]...) {
				target := filepath.Join(s.unitRoot, unit)
				err := filepath.WalkDir(s.unitRoot, func(path string, entry os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if entry.Type()&os.ModeSymlink != 0 {
						got, err := os.Readlink(path)
						if err != nil {
							return err
						}
						if got == target {
							return os.Remove(path)
						}
					}
					return nil
				})
				if err != nil {
					return "", -1, err
				}
				s.units[unit] = "disabled"
			}
			return "", 0, nil
		}
	}
	if s.tool != nil {
		return s.tool(cmd, args)
	}
	return "", -1, errors.New("unexpected fake command")
}
func (s *fakeSystem) called(prefix string) bool {
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// Claim: the non-root system model refuses name/ID collisions, missing subjects,
// live-user deletion and primary-group deletion instead of granting fake success.
func TestLedgerFakeEncodesToolRefusals(t *testing.T) {
	s := newSystem()
	s.groups["demo"] = Account{Name: "demo", GID: 301}
	s.users["demo"] = Account{Name: "demo", UID: 301, GID: 301, Shell: "/usr/sbin/nologin"}
	cases := []struct {
		cmd    string
		args   []string
		status int
	}{
		{"/usr/sbin/groupadd", []string{"-g", "302", "demo"}, 9},
		{"/usr/sbin/groupadd", []string{"-g", "301", "other"}, 4},
		{"/usr/sbin/useradd", []string{"-u", "302", "-g", "301", "demo"}, 9},
		{"/usr/sbin/useradd", []string{"-u", "301", "-g", "301", "-s", "/usr/sbin/nologin", "other"}, 4},
		{"/usr/sbin/useradd", []string{"-u", "302", "-g", "999", "-s", "/usr/sbin/nologin", "other"}, 6},
		{"/usr/sbin/usermod", []string{"-aG", "demo", "missing"}, 6},
		{"/usr/sbin/groupdel", []string{"demo"}, 8},
		{"/usr/bin/getent", []string{"passwd", "missing"}, 2},
	}
	for _, c := range cases {
		_, status, e := s.Run(c.cmd, c.args...)
		if e != nil || status != c.status {
			t.Fatalf("%s: status=%d err=%v", c.cmd, status, e)
		}
	}
	s.live["demo"] = true
	_, status, e := s.Run("/usr/sbin/userdel", "demo")
	if e != nil || status != 8 {
		t.Fatal(status, e)
	}
	s.live["demo"] = false
	_, status, e = s.Run("/usr/sbin/userdel", "demo")
	if e != nil || status != 0 {
		t.Fatal(status, e)
	}
	_, status, e = s.Run("/usr/sbin/groupdel", "demo")
	if e != nil || status != 0 {
		t.Fatal(status, e)
	}
}
