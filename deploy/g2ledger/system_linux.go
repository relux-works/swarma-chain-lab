package g2ledger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// System is the privilege boundary. Filesystem creation, identity reads and
// unlink/rename remain real descriptor operations even when System is a fake.
// Run returns stdout and the actual exit status; execution/timeout errors are
// separate. Child stderr is intentionally never echoed (it may contain input).
type System interface {
	Run(command string, args ...string) (string, int, error)
	Chown(file *os.File, uid, gid uint32) error
	// UnitPaths returns the system unit search order and persistent install directory.
	UnitPaths() ([]string, string, error)
}
type RealSystem struct{}

func (s RealSystem) UnitPaths() ([]string, string, error) {
	// Both systemd-analyze unit-paths and enable use lookup_paths_init(..., 0).
	// Persistent system enablement uses SYSTEM_CONFIG_UNIT_DIR, not a search
	// directory chosen from the receipt. See the pinned sources in G2-LEDGER.md.
	out, status, err := s.Run("/usr/bin/systemd-analyze", "--system", "unit-paths")
	if err != nil {
		return nil, "", err
	}
	if status != 0 || out == "" {
		return nil, "", errors.New("UNIT_SEARCH_PATH")
	}
	paths := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for _, path := range paths {
		if !validPath(path) {
			return nil, "", errors.New("UNIT_SEARCH_PATH")
		}
	}
	return paths, "/etc/systemd/system", nil
}

func (RealSystem) Chown(f *os.File, uid, gid uint32) error {
	// Avoid requiring privilege for an already-correct descriptor in fixtures.
	current, e := fsOwnership(f)
	if e != nil {
		return e
	}
	if current[0] == uid && current[1] == gid {
		return nil
	}
	return f.Chown(int(uid), int(gid))
}
func (RealSystem) Run(command string, args ...string) (string, int, error) {
	if command == "/usr/sbin/useradd" || command == "/usr/sbin/groupadd" || command == "/usr/sbin/usermod" || command == "/usr/sbin/userdel" || command == "/usr/sbin/groupdel" || command == "/usr/bin/gpasswd" || command == "/usr/bin/systemctl" && (len(args) == 0 || args[0] != "is-enabled") {
		if os.Geteuid() != 0 {
			return "", -1, errors.New("ROOT_REQUIRED")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	// systemctl enable reports created links on stderr, not stdout. Capture
	// both only for this non-secret command and force its documented C format.
	var b []byte
	var e error
	if command == "/usr/bin/systemctl" && len(args) > 0 && args[0] == "enable" {
		cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_URLIFY=0")
		b, e = cmd.CombinedOutput()
	} else {
		b, e = cmd.Output()
	}
	if ctx.Err() != nil {
		return "", -1, errors.New("COMMAND_TIMEOUT")
	}
	if e == nil {
		return string(b), 0, nil
	}
	var status *exec.ExitError
	if errors.As(e, &status) {
		return string(b), status.ExitCode(), nil
	}
	return "", -1, errors.New("COMMAND_EXEC")
}
func number(s string) (uint32, error) {
	n, e := strconv.ParseUint(s, 10, 32)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("LOOKUP_NUMBER")
	}
	return uint32(n), nil
}

// getent(1): only exit 2 with empty stdout is absence. Operational failures,
// malformed lines, extra records and a mismatched requested key are errors.
func lookup(sys System, kind, name string) (*Account, []string, error) {
	db, fields := "passwd", 7
	if kind == "group" {
		db = "group"
		fields = 4
	}
	out, status, e := sys.Run("/usr/bin/getent", db, name)
	if e != nil {
		return nil, nil, e
	}
	if status == 2 && out == "" {
		return nil, nil, nil
	}
	if status != 0 {
		return nil, nil, fmt.Errorf("GETENT_STATUS_%d", status)
	}
	line := strings.TrimSuffix(out, "\n")
	if strings.ContainsAny(line, "\r\n") {
		return nil, nil, errors.New("GETENT_RECORD_COUNT")
	}
	p := strings.Split(line, ":")
	if len(p) != fields || !namePattern.MatchString(p[0]) {
		return nil, nil, errors.New("GETENT_SCHEMA")
	}
	id, e := number(p[2])
	if e != nil {
		return nil, nil, e
	}
	if p[0] != name && strconv.FormatUint(uint64(id), 10) != name {
		return nil, nil, errors.New("GETENT_KEY")
	}
	a := &Account{Name: p[0]}
	members := []string{}
	if kind == "user" {
		a.UID = id
		a.GID, e = number(p[3])
		a.Shell = p[6]
		a.Home = p[5]
		a.Description = p[4]
		if e != nil || !strings.HasPrefix(a.Shell, "/") {
			return nil, nil, errors.New("GETENT_USER")
		}
	} else {
		a.GID = id
		if p[3] != "" {
			seen := map[string]bool{}
			for _, m := range strings.Split(p[3], ",") {
				if !namePattern.MatchString(m) || seen[m] {
					return nil, nil, errors.New("GETENT_MEMBERS")
				}
				seen[m] = true
				members = append(members, m)
			}
		}
	}
	return a, members, nil
}
func membership(sys System, user, group string) (*Identity, error) {
	u, _, e := lookup(sys, "user", user)
	if e != nil {
		return nil, e
	}
	g, members, e := lookup(sys, "group", group)
	if e != nil {
		return nil, e
	}
	if u == nil || g == nil {
		return nil, nil
	}
	present := u.GID == g.GID
	for _, m := range members {
		if m == user {
			present = true
		}
	}
	return &Identity{Membership: &Membership{User: *u, Group: *g, Present: present}}, nil
}

// Only the exact documented disabled/1 and enabled/0 states are supported.
// Other legitimate systemd states are deliberately errors, never absence.
func unitState(sys System, name string) (*Identity, error) {
	out, status, e := sys.Run("/usr/bin/systemctl", "is-enabled", name)
	if e != nil {
		return nil, e
	}
	state := strings.TrimSuffix(out, "\n")
	if !(state == "enabled" && status == 0 || state == "disabled" && status == 1) {
		return nil, fmt.Errorf("IS_ENABLED_UNEXPECTED_STATE_STATUS_%d", status)
	}
	return &Identity{Unit: &Unit{Name: name, State: state}}, nil
}
func commandOK(sys System, command string, args ...string) error {
	_, status, e := sys.Run(command, args...)
	if e != nil {
		return e
	}
	if status != 0 {
		return fmt.Errorf("COMMAND_STATUS_%d", status)
	}
	return nil
}
