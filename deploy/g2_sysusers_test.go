package deploy

// Owner S5 (PX1): the rendered sysusers.conf against its real consumer,
// systemd-sysusers. Every run is "--dry-run --root=<new fixture root>" under
// the test temp directory, with one pre-provisioned fixture agent account; the
// helper below is the only caller and checks that the fixture is unchanged.
// The consumer layer skips, saying so, only when systemd-sysusers is absent
// or refuses the --dry-run option itself (older releases, which then exit
// before reading anything); it never runs without --dry-run.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	g2FixtureAgent  = "fixtureagent"
	g2FixturePasswd = "fixtureagent:x:1201:1201:Fixture agent:/nonexistent:/usr/sbin/nologin\n"
	g2FixtureGroup  = "fixtureagent:x:1201:\n"
)

// g2SysusersDryRun gives conf to systemd-sysusers only as --dry-run against a
// new isolated root and fails the test if that root's etc changed in any way.
func g2SysusersDryRun(t *testing.T, conf []byte) (int, string) {
	t.Helper()
	binary, e := exec.LookPath("systemd-sysusers")
	if e != nil {
		t.Skip("systemd-sysusers not installed: the real-consumer layer did not run")
	}
	root, tmp := t.TempDir(), filepath.Clean(os.TempDir())
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(root, tmp+"/") || tmp == "/" {
		t.Fatal("[setup failed] fixture root is not an isolated temp directory")
	}
	etc, config := filepath.Join(root, "etc"), filepath.Join(root, "g2-sysusers.conf")
	if os.Mkdir(etc, 0700) != nil || os.WriteFile(filepath.Join(etc, "passwd"), []byte(g2FixturePasswd), 0600) != nil || os.WriteFile(filepath.Join(etc, "group"), []byte(g2FixtureGroup), 0600) != nil || os.WriteFile(config, conf, 0600) != nil {
		t.Fatal("[setup failed] fixture root")
	}
	cmd := exec.Command(binary, "--dry-run", "--root="+root, config)
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState == nil {
		t.Fatal("[setup failed] systemd-sysusers did not run")
	}
	passwd, e1 := os.ReadFile(filepath.Join(etc, "passwd"))
	group, e2 := os.ReadFile(filepath.Join(etc, "group"))
	entries, e3 := os.ReadDir(etc)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if e1 != nil || e2 != nil || e3 != nil || string(passwd) != g2FixturePasswd || string(group) != g2FixtureGroup || !reflect.DeepEqual(names, []string{"group", "passwd"}) {
		t.Fatalf("G2_SYSUSERS_DRY_RUN changed the fixture root: %v", names)
	}
	exit := cmd.ProcessState.ExitCode()
	if exit != 0 && strings.Contains(string(out), "unrecognized option '--dry-run'") {
		t.Skip("this systemd-sysusers has no --dry-run (it refused the option and did nothing): the real-consumer layer did not run")
	}
	return exit, string(out)
}

// g2CreatesGroup matches the consumer's dry-run plan line for one group and
// GID, in the wording of older and newer systemd releases.
func g2CreatesGroup(out, name string, gid uint32) bool {
	return regexp.MustCompile(`(?im)^creating group '?` + regexp.QuoteMeta(name) + `'? with gid ` + strconv.FormatUint(uint64(gid), 10) + `\.$`).MatchString(out)
}

// g2ResolveAgentUser is the documented operator step: the one agent-user
// token becomes the existing account name.
func g2ResolveAgentUser(t *testing.T, conf []byte) []byte {
	t.Helper()
	if bytes.Count(conf, []byte(G2AgentUserPlaceholder)) != 1 || !bytes.HasSuffix(conf, []byte("\nm "+G2AgentUserPlaceholder+" swarma-wallet-peer\n")) {
		t.Fatal("agent-user token is not exactly once, on the last line", string(conf))
	}
	return bytes.ReplaceAll(conf, []byte(G2AgentUserPlaceholder), []byte(g2FixtureAgent))
}

// Claim: the real systemd-sysusers (dry-run, isolated root) refuses the unresolved rendered sysusers.conf and writes nothing, and accepts its resolved neighbour.
func TestPX1S5SysusersUnresolvedRefused(t *testing.T) {
	files, e := RenderG2PayTemplates(g2Params())
	if e != nil {
		t.Fatal(e)
	}
	conf := files[G2FileSysusers]
	exit, out := g2SysusersDryRun(t, g2ResolveAgentUser(t, conf))
	t.Logf("resolved neighbour: consumer_exit=%d\n%s", exit, out)
	if exit != 0 || strings.Contains(strings.ToLower(out), "creating user '"+g2FixtureAgent+"'") || strings.Contains(strings.ToLower(out), "creating user "+g2FixtureAgent+" ") || !g2CreatesGroup(out, "swarma-wallet-peer", 1301) || !g2CreatesGroup(out, "swarma-wallet-status", 1401) {
		t.Fatal("G2_SYSUSERS_RESOLVED: the resolved neighbour was refused or misapplied")
	}
	exit, out = g2SysusersDryRun(t, conf)
	t.Logf("unresolved: consumer_exit=%d\n%s", exit, out)
	if exit == 0 || !strings.Contains(out, G2AgentUserPlaceholder) || strings.Contains(out, "Would write") || strings.Contains(strings.ToLower(out), "creating") {
		t.Fatal("G2_SYSUSERS_UNRESOLVED: the real consumer accepts the unresolved agent user")
	}
}

// Claim: GID 65535 for either rendered group is refused with ErrPolicy before rendering, while 65533 and 65536 render and the real consumer applies them.
// The consumer refusing a hand-edited 65535 line grounds the guard in the consumer's own ID domain, not in this module's rule.
func TestPX1S5SysusersGIDDomain(t *testing.T) {
	rows := []struct {
		name             string
		socket, operator uint32
		want             error
	}{
		{"socket-65535", 65535, 1401, ErrPolicy},
		{"operator-65535", 1301, 65535, ErrPolicy},
		{"socket-65533", 65533, 1401, nil},
		{"socket-65536", 65536, 1401, nil},
		{"operator-65533", 1301, 65533, nil},
		{"operator-65536", 1301, 65536, nil},
	}
	for _, c := range rows {
		p := g2Params()
		p.AgentSocketGID, p.OperatorGID = c.socket, c.operator
		files, renderErr := RenderG2PayTemplates(p)
		if e := ValidateG2PayParameters(p); e != c.want || renderErr != c.want || (files == nil) != (c.want != nil) {
			t.Fatalf("G2_SYSUSERS_GID %s: validate=%v render=%v want %v", c.name, e, renderErr, c.want)
		}
	}
	for _, c := range rows {
		if c.want != nil {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			p := g2Params()
			p.AgentSocketGID, p.OperatorGID = c.socket, c.operator
			files, _ := RenderG2PayTemplates(p)
			exit, out := g2SysusersDryRun(t, g2ResolveAgentUser(t, files[G2FileSysusers]))
			t.Logf("consumer_exit=%d\n%s", exit, out)
			if exit != 0 || !g2CreatesGroup(out, "swarma-wallet-peer", c.socket) || !g2CreatesGroup(out, "swarma-wallet-status", c.operator) {
				t.Fatal("G2_SYSUSERS_GID_NEIGHBOUR refused by the real consumer", c.name)
			}
		})
	}
	files, _ := RenderG2PayTemplates(g2Params())
	resolved := g2ResolveAgentUser(t, files[G2FileSysusers])
	for _, line := range []string{"g swarma-wallet-peer 1301\n", "g swarma-wallet-status 1401\n"} {
		t.Run("consumer-refuses-"+strings.Fields(line)[1]+"-65535", func(t *testing.T) {
			bad := bytes.Replace(resolved, []byte(line), []byte(line[:len(line)-5]+"65535\n"), 1)
			if bytes.Equal(bad, resolved) {
				t.Fatal("[setup failed] fixture edit did not apply")
			}
			exit, out := g2SysusersDryRun(t, bad)
			t.Logf("consumer_exit=%d\n%s", exit, out)
			if exit == 0 || !strings.Contains(out, "65535") || strings.Contains(out, "Would write") {
				t.Fatal("consumer did not refuse the GID 65535 line; the deploy guard is not grounded", line)
			}
		})
	}
}
