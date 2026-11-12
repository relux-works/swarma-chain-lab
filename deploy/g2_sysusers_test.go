package deploy

// Owner S5 (PX1): the rendered sysusers.conf against its real consumer,
// systemd-sysusers. Every run is "--dry-run --root=<new fixture root>" under
// the test temp directory, with fixture passwd and group files; the helper
// below is the only caller and checks that the fixture is unchanged.
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

// Fixture account databases of the isolated root. "cedar" is g2Params' agent
// user at its agent_uid 1201; "someone" owns that UID in the collision state.
const (
	g2FixtureOther  = "fixtureother:x:1500:1500:Fixture other:/nonexistent:/usr/sbin/nologin\n"
	g2FixtureOtherG = "fixtureother:x:1500:\n"
	g2FixtureCedar  = "cedar:x:1201:1201:Fixture agent:/nonexistent:/usr/sbin/nologin\n"
	g2FixtureCedarG = "cedar:x:1201:\n"
	g2FixtureTaken  = "someone:x:1201:1201:Fixture collision:/nonexistent:/usr/sbin/nologin\n"
	g2FixtureTakenG = "someone:x:1201:\n"
)

// g2SysusersDryRun gives conf to systemd-sysusers only as --dry-run against a
// new isolated root holding the given passwd and group files, and fails the
// test if that root's etc changed in any way.
func g2SysusersDryRun(t *testing.T, conf []byte, passwdFixture, groupFixture string) (int, string) {
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
	if os.Mkdir(etc, 0700) != nil || os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwdFixture), 0600) != nil || os.WriteFile(filepath.Join(etc, "group"), []byte(groupFixture), 0600) != nil || os.WriteFile(config, conf, 0600) != nil {
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
	if e1 != nil || e2 != nil || e3 != nil || string(passwd) != passwdFixture || string(group) != groupFixture || !reflect.DeepEqual(names, []string{"group", "passwd"}) {
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

// g2CreatesUserGID matches the consumer's dry-run plan line that creates the
// user name with primary GID gid, in older and newer wording.
func g2CreatesUserGID(out, name string, gid uint32) bool {
	return regexp.MustCompile(`(?im)^creating user '?` + regexp.QuoteMeta(name) + `'? \(.*\) with uid [0-9]+ and gid ` + strconv.FormatUint(uint64(gid), 10) + `\.$`).MatchString(out)
}

// g2CreatedUID returns the UID the consumer's dry-run plan would give name,
// or false when it plans no such user.
func g2CreatedUID(out, name string) (uint32, bool) {
	m := regexp.MustCompile(`(?im)^creating user '?` + regexp.QuoteMeta(name) + `'? \(.*\) with uid ([0-9]+) `).FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	id, e := strconv.ParseUint(m[1], 10, 32)
	return uint32(id), e == nil
}

// Claim: the real systemd-sysusers (dry-run, isolated root) applies the
// resolved rendered sysusers.conf as intended: on a first install it would
// create the agent at exactly agent_uid and the service at exactly
// service_uid, with both groups at their pinned GIDs, and would give the agent
// its own group at exactly the primary GID G2AgentSlotGIDs derives (the GID
// the T18 readback requires); with the agent already
// at agent_uid it creates no agent. On a UID collision it still exits 0 but
// would create the agent at another UID: the target-host flow's preflight
// refuses that state before the apply, and its post-apply check refuses the
// substituted result before activation (both over a fixture database holding
// exactly the consumer's planned result). Exit 0 alone never authorizes
// activation. Limit: dry-run plans, not a host apply.
func TestPX1S5SysusersResolvedConsumer(t *testing.T) {
	p := g2Params()
	files, e := RenderG2PayTemplates(p)
	if e != nil {
		t.Fatal(e)
	}
	conf := files[G2FileSysusers]

	t.Run("first-install", func(t *testing.T) {
		exit, out := g2SysusersDryRun(t, conf, g2FixtureOther, g2FixtureOtherG)
		t.Logf("consumer_exit=%d\n%s", exit, out)
		agent, agentOK := g2CreatedUID(out, p.AgentUser)
		service, serviceOK := g2CreatedUID(out, "swarma-wallet")
		if exit != 0 || !agentOK || agent != p.AgentUID || !serviceOK || service != p.ServiceUID || !g2CreatesGroup(out, G2AgentSocketGroup, p.AgentSocketGID) || !g2CreatesGroup(out, G2OperatorGroup, p.OperatorGID) {
			t.Fatalf("G2_SYSUSERS_AGENT_UID the consumer would not create the agent at %d and the service at %d: agent=%d/%v service=%d/%v", p.AgentUID, p.ServiceUID, agent, agentOK, service, serviceOK)
		}
		if primary, _, e := G2AgentSlotGIDs(p); e != nil || !g2CreatesGroup(out, p.AgentUser, primary) || !g2CreatesUserGID(out, p.AgentUser, primary) {
			t.Fatalf("G2_SYSUSERS_PRIMARY_GID the consumer would not give the agent its own group at the derived primary GID %d (%v)", primary, e)
		}
	})
	t.Run("existing-agent", func(t *testing.T) {
		exit, out := g2SysusersDryRun(t, conf, g2FixtureCedar, g2FixtureCedarG)
		t.Logf("consumer_exit=%d\n%s", exit, out)
		if _, again := g2CreatedUID(out, p.AgentUser); exit != 0 || again || !g2CreatesGroup(out, G2AgentSocketGroup, p.AgentSocketGID) {
			t.Fatal("G2_SYSUSERS_EXISTING the consumer refused or recreated the existing agent")
		}
	})
	t.Run("uid-collision", func(t *testing.T) {
		exit, out := g2SysusersDryRun(t, conf, g2FixtureTaken, g2FixtureTakenG)
		t.Logf("consumer_exit=%d\n%s", exit, out)
		uid, ok := g2CreatedUID(out, p.AgentUser)
		if exit != 0 || !ok || uid == p.AgentUID {
			t.Fatalf("G2_SYSUSERS_COLLISION expected exit 0 with a substituted UID, got exit=%d uid=%d/%v", exit, uid, ok)
		}
		var log []string
		before := newG2FixtureDB(&log)
		before.add("someone", p.AgentUID)
		if e := ValidateG2PayIdentity(p, before); e != ErrPolicy {
			t.Fatal("G2_SYSUSERS_COLLISION the preflight admitted the collision state", e)
		}
		after := newG2FixtureDB(&log)
		after.add("someone", p.AgentUID)
		after.add(p.AgentUser, uid, p.AgentSocketGID)
		if e := VerifyG2AgentAccount(p, after); e != ErrPolicy {
			t.Fatal("G2_SYSUSERS_COLLISION the post-apply check admitted the substituted UID", e)
		}
		clean := newG2FixtureDB(&log)
		clean.add(p.AgentUser, p.AgentUID, p.AgentSocketGID)
		if e := VerifyG2AgentAccount(p, clean); e != nil {
			t.Fatal("exact-UID neighbour refused", e)
		}
	})
}

// Claim: GID 65535 for either rendered group is refused with ErrPolicy before rendering (the frozen identity domain, which
// ValidateG2PayParameters runs first), while 65533 and 65536 render and the real consumer applies them. The consumer
// refusing a hand-edited 65535 line grounds the guard in the consumer's own ID domain, not in this module's rule.
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
			exit, out := g2SysusersDryRun(t, files[G2FileSysusers], g2FixtureOther, g2FixtureOtherG)
			t.Logf("consumer_exit=%d\n%s", exit, out)
			if exit != 0 || !g2CreatesGroup(out, "swarma-wallet-peer", c.socket) || !g2CreatesGroup(out, "swarma-wallet-status", c.operator) {
				t.Fatal("G2_SYSUSERS_GID_NEIGHBOUR refused by the real consumer", c.name)
			}
		})
	}
	files, _ := RenderG2PayTemplates(g2Params())
	resolved := files[G2FileSysusers]
	for _, line := range []string{"g swarma-wallet-peer 1301\n", "g swarma-wallet-status 1401\n"} {
		t.Run("consumer-refuses-"+strings.Fields(line)[1]+"-65535", func(t *testing.T) {
			bad := bytes.Replace(resolved, []byte(line), []byte(line[:len(line)-5]+"65535\n"), 1)
			if bytes.Equal(bad, resolved) {
				t.Fatal("[setup failed] fixture edit did not apply")
			}
			exit, out := g2SysusersDryRun(t, bad, g2FixtureOther, g2FixtureOtherG)
			t.Logf("consumer_exit=%d\n%s", exit, out)
			if exit == 0 || !strings.Contains(out, "65535") || strings.Contains(out, "Would write") {
				t.Fatal("consumer did not refuse the GID 65535 line; the deploy guard is not grounded", line)
			}
		})
	}
}
