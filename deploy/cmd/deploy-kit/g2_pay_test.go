package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

const (
	cliKeyG  = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	cliKey2G = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)

func cliParams() deploy.G2PayParameters {
	return deploy.G2PayParameters{Network: "main", Genesis: "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770", AgentUID: 1201, AgentSocketGID: 1301, OperatorGID: 1401, ServiceUID: 1101, AgentUser: "cedar", AgentKeyFile: "/srv/agent/action.key", NodeDataDir: "/var/lib/namecoind-main", Grantee: cliKeyG, ReceiptPubkey: cliKey2G, FeeRateSatVB: 110, HotWalletName: "swarma-g2-hot", NodeRPCPort: 8336, G2: deploy.G2OperatorParameters{RequireTermsVersion: 2, MaxTransferSat: 100000, MaxDaySat: 300000, MaxDayCount: 10, MaxFeeSat: 100000, MaxFloatSat: 2000000, LowFloatSat: 500000, Canary: deploy.G2CanaryParameters{Outpoint: deploy.G2Outpoint{TxID: strings.Repeat("c", 64)}, ValueSat: 10000}, ConfirmationsK: 2, ConflictBlocksN: 6, ReadRatePerHour: 60, JournalSpendCapacity: 2048}}
}

// Claim: g2-render writes exactly the six G2 files (0600) into a new
// directory and prints their names; it refuses an existing directory (no
// overwrite), a relative output path and invalid parameters, creating
// nothing for the invalid input.
func TestG2RenderCommand(t *testing.T) {
	root := t.TempDir()
	params := filepath.Join(root, "params.json")
	raw, _ := json.Marshal(cliParams())
	os.WriteFile(params, append(raw, '\n'), 0600)
	out := filepath.Join(root, "rendered")
	var stdout bytes.Buffer
	if e := g2Render([]string{"-params", params, "-out", out}, &stdout); e != nil {
		t.Fatal("G2_CLI_RENDER positive", e)
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 6 || !strings.Contains(stdout.String(), `"status":"G2_RENDERED"`) {
		t.Fatal("G2_CLI_RENDER files", entries, stdout.String())
	}
	for _, entry := range entries {
		info, _ := entry.Info()
		if info.Mode().Perm() != 0600 {
			t.Fatal("rendered file mode", entry.Name(), info.Mode())
		}
	}
	if e := g2Render([]string{"-params", params, "-out", out}, io.Discard); e != deploy.ErrInput {
		t.Fatal("G2_CLI_RENDER overwrote an existing directory", e)
	}
	if e := g2Render([]string{"-params", params, "-out", "rendered"}, io.Discard); e != deploy.ErrInput {
		t.Fatal("relative output accepted", e)
	}
	bad := cliParams()
	bad.G2.AllowSingleUse = true
	raw, _ = json.Marshal(bad)
	os.WriteFile(params, raw, 0600)
	other := filepath.Join(root, "other")
	if e := g2Render([]string{"-params", params, "-out", other}, io.Discard); e != deploy.ErrPolicy {
		t.Fatal("G2_CLI_RENDER invalid parameters accepted", e)
	}
	if _, e := os.Stat(other); !os.IsNotExist(e) {
		t.Fatal("output created for invalid parameters")
	}
}

// Claim: g2-custody-probe prints a report and succeeds only when every probe
// passes; a missing denied path makes it fail with ErrCustody after printing
// the evidence. g2-custody-verify accepts that genuine report with -launch=false,
// refuses it under the default launch layout and refuses a tampered report.
// Limit: runs as the test UID; skipped as root.
func TestG2CustodyCommands(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses file modes")
	}
	root, _ := os.MkdirTemp("", "t18cli")
	denied := filepath.Join(root, "receipt.key")
	os.WriteFile(denied, []byte("x"), 0)
	t.Cleanup(func() { os.Chmod(denied, 0600); os.RemoveAll(root) })
	sock := filepath.Join(root, "w.sock")
	l, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := tcp.Addr().String()
	tcp.Close()
	uid := uint32(os.Getuid())
	spec := deploy.CustodySpecV1{Version: 1, AgentUID: uid, ServiceUID: uid + 1, DeniedReads: []string{denied}, DeniedRPC: []string{closed}, AllowedSocket: sock}
	specPath := filepath.Join(root, "spec.json")
	raw, _ := json.Marshal(spec)
	os.WriteFile(specPath, append(raw, '\n'), 0600)
	var stdout bytes.Buffer
	if e := g2CustodyProbe([]string{"-spec", specPath}, &stdout); e != nil {
		t.Fatal("G2_CLI_PROBE positive", e, stdout.String())
	}
	reportPath := filepath.Join(root, "report.json")
	os.WriteFile(reportPath, stdout.Bytes(), 0600)
	if e := g2CustodyVerify([]string{"-spec", specPath, "-report", reportPath, "-launch=false"}, io.Discard); e != nil {
		t.Fatal("G2_CLI_VERIFY genuine report", e)
	}
	if e := g2CustodyVerify([]string{"-spec", specPath, "-report", reportPath}, io.Discard); e != deploy.ErrPolicy {
		t.Fatal("G2_CLI_VERIFY accepted a non-launch spec", e)
	}
	tampered := bytes.Replace(stdout.Bytes(), []byte(`"uid":`), []byte(`"uid":1`), 1)
	os.WriteFile(reportPath, tampered, 0600)
	if e := g2CustodyVerify([]string{"-spec", specPath, "-report", reportPath, "-launch=false"}, io.Discard); e != deploy.ErrCustody {
		t.Fatal("G2_CLI_VERIFY accepted a tampered report", e)
	}
	spec.DeniedReads = append(spec.DeniedReads, filepath.Join(root, "missing"))
	raw, _ = json.Marshal(spec)
	os.WriteFile(specPath, raw, 0600)
	stdout.Reset()
	if e := g2CustodyProbe([]string{"-spec", specPath}, &stdout); e != deploy.ErrCustody || !strings.Contains(stdout.String(), `"observed":"ENOENT","pass":false`) {
		t.Fatal("G2_CLI_PROBE passed a missing denied path", e, stdout.String())
	}
	if r, e := deploy.RunCustodyProbe(context.Background(), spec); e != nil || r.Pass {
		t.Fatal("library disagrees with the command", e)
	}
}

// g2FreeID returns an ID above the usual account ranges that lookup reports
// as genuinely absent on this host.
func g2FreeID(t *testing.T, start uint32, taken map[uint32]bool) uint32 {
	t.Helper()
	for id := start; id < start+1000; id++ {
		if taken[id] || deploy.G2ReservedID(id) {
			continue
		}
		var unknown user.UnknownUserIdError
		if _, e := user.LookupId(strconv.FormatUint(uint64(id), 10)); errors.As(e, &unknown) {
			return id
		}
	}
	t.Fatal("[setup failed] no free UID on this host")
	return 0
}

// Claim: g2-host-flow, on this host's REAL account database, runs the
// systemd-sysusers step only after the preflight passed and the activation
// command only after the post-apply account check passed: an absent agent
// name whose agent_uid another account owns is refused before the apply; an
// absent name at a free UID passes the preflight, is applied (with exactly the
// rendered sysusers.conf on standard input, argument "-") and is refused
// after it, because the account still does not exist; a failed apply, a
// failed activation and a missing activation command refuse; the existing
// test account at its own UID, in its primary group and outside the operator
// GID, is activated once and prints G2_HOST_FLOW_ACTIVATED. Limit: the
// sysusers and activation binaries are recording fakes, so no account or
// service changes; skipped as root or when the test account is outside the
// frozen identity domain.
func TestG2HostFlowCommand(t *testing.T) {
	cur, e := user.Current()
	if e != nil {
		t.Skip("[setup] the test account cannot be looked up on this host:", e)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	base := cliParams()
	base.AgentUser, base.AgentUID, base.AgentSocketGID = cur.Username, uid, gid
	if deploy.G2ReservedID(uid) || deploy.G2ReservedID(gid) || deploy.ValidateG2PayIdentityDomain(deploy.G2PayParameters{AgentUID: uid, ServiceUID: uid + 1, AgentSocketGID: gid, OperatorGID: gid + 1, AgentUser: cur.Username, AgentKeyFile: "/k", NodeDataDir: "/d"}) != nil {
		t.Skip("the test account (root, a reserved ID or a name outside the sysusers rule) cannot stand in for the agent")
	}
	groups, e := deploy.G2HostAccounts{}.UserGroups(cur.Username)
	if e != nil {
		t.Skip("[setup] the test account's groups cannot be read:", e)
	}
	taken := map[uint32]bool{uid: true, gid: true}
	for _, g := range groups {
		taken[g] = true
	}
	base.OperatorGID = g2FreeID(t, 3000000000, taken)
	taken[base.OperatorGID] = true
	base.ServiceUID = g2FreeID(t, 3000000000, taken)
	taken[base.ServiceUID] = true
	salt := make([]byte, 6)
	rand.Read(salt)
	absent := "g2absent" + hex.EncodeToString(salt)
	var unknown user.UnknownUserError
	if _, e := user.Lookup(absent); !errors.As(e, &unknown) {
		t.Fatal("[setup failed] fixture name is not absent", absent, e)
	}

	work := t.TempDir()
	sysusers := filepath.Join(work, "systemd-sysusers")
	activate := filepath.Join(work, "activate")
	os.WriteFile(sysusers, []byte("#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = - ] || exit 7\ncat >\"$G2_FAKE_APPLIED\"\nexit \"${G2_FAKE_SYSUSERS_EXIT:-0}\"\n"), 0700)
	os.WriteFile(activate, []byte("#!/bin/sh\necho activated >>\"$1\"\nexit \"${G2_FAKE_ACTIVATE_EXIT:-0}\"\n"), 0700)

	run := func(name string, p deploy.G2PayParameters, withActivation bool, env ...string) (error, string, []byte, bool) {
		t.Helper()
		dir := filepath.Join(work, name)
		os.Mkdir(dir, 0700)
		params, applied, marker := filepath.Join(dir, "params.json"), filepath.Join(dir, "applied.conf"), filepath.Join(dir, "activated")
		raw, _ := json.Marshal(p)
		os.WriteFile(params, append(raw, '\n'), 0600)
		t.Setenv("G2_FAKE_APPLIED", applied)
		t.Setenv("G2_FAKE_SYSUSERS_EXIT", "0")
		t.Setenv("G2_FAKE_ACTIVATE_EXIT", "0")
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			t.Setenv(k, v)
		}
		args := []string{"-params", params, "-sysusers", sysusers}
		if withActivation {
			args = append(args, "--", activate, marker)
		}
		var stdout bytes.Buffer
		e := g2HostFlow(args, &stdout)
		appliedBytes, _ := os.ReadFile(applied)
		_, activated := os.Stat(marker)
		return e, stdout.String(), appliedBytes, activated == nil
	}

	// Valid neighbour: the existing account at its own UID is activated once.
	e, out, applied, activated := run("clean", base, true)
	files, _ := deploy.RenderG2PayTemplates(base)
	if e != nil || out != "G2_HOST_FLOW_ACTIVATED\n" || !activated || !bytes.Equal(applied, files[deploy.G2FileSysusers]) {
		t.Fatalf("G2_CLI_HOST_FLOW clean path: err=%v out=%q activated=%v applied=%q", e, out, activated, applied)
	}

	preflight := base
	preflight.AgentUser = absent // agent_uid stays owned by the test account
	if e, _, applied, activated := run("preflight-refused", preflight, true); !errors.Is(e, deploy.ErrPolicy) || applied != nil || activated {
		t.Fatalf("G2_CLI_HOST_FLOW applied past a refused preflight: err=%v applied=%v activated=%v", e, applied != nil, activated)
	}
	post := base
	post.AgentUser, post.AgentUID = absent, g2FreeID(t, 3000000000, taken)
	if e, _, applied, activated := run("post-apply-refused", post, true); !errors.Is(e, deploy.ErrPolicy) || applied == nil || activated {
		t.Fatalf("G2_CLI_HOST_FLOW activated past a refused post-apply check: err=%v applied=%v activated=%v", e, applied != nil, activated)
	}
	if e, _, _, activated := run("sysusers-failed", base, true, "G2_FAKE_SYSUSERS_EXIT=1"); !errors.Is(e, deploy.ErrPolicy) || activated {
		t.Fatalf("G2_CLI_HOST_FLOW activated after a failed apply: err=%v activated=%v", e, activated)
	}
	if e, out, _, _ := run("activation-failed", base, true, "G2_FAKE_ACTIVATE_EXIT=1"); !errors.Is(e, deploy.ErrPolicy) || out != "" {
		t.Fatalf("G2_CLI_HOST_FLOW reported a failed activation: err=%v out=%q", e, out)
	}
	if e, _, applied, _ := run("no-activation", base, false); e != deploy.ErrInput || applied != nil {
		t.Fatalf("G2_CLI_HOST_FLOW ran without an activation command: err=%v", e)
	}
}

// Claim: g2-agent-groups accepts the readback only when its GIDs are exactly
// {own primary GID 1201, agent_socket_gid 1301} derived from the parameters
// (any order, a repeated GID allowed) and then prints the two GIDs; a third
// group, the operator GID, a missing primary or socket GID, no GID, a
// non-canonical GID and invalid parameters are refused and print nothing.
// The neighbour with another agent_uid shows the primary GID follows the
// parameters.
func TestG2AgentGroupsCommand(t *testing.T) {
	root := t.TempDir()
	write := func(name string, p deploy.G2PayParameters) string {
		raw, _ := json.Marshal(p)
		path := filepath.Join(root, name)
		os.WriteFile(path, append(raw, '\n'), 0600)
		return path
	}
	params := write("params.json", cliParams())
	moved := cliParams()
	moved.AgentUID = 2201
	movedParams := write("params-2201.json", moved)
	bad := cliParams()
	bad.OperatorGID = bad.AgentSocketGID
	badParams := write("params-bad.json", bad)
	for _, c := range []struct {
		params string
		gids   []string
		want   string
	}{
		{params, []string{"1201", "1301"}, "G2_AGENT_GROUPS_OK primary=1201 socket=1301\n"},
		{params, []string{"1301", "1201", "1301"}, "G2_AGENT_GROUPS_OK primary=1201 socket=1301\n"},
		{movedParams, []string{"2201", "1301"}, "G2_AGENT_GROUPS_OK primary=2201 socket=1301\n"},
	} {
		var stdout bytes.Buffer
		if e := g2AgentGroups(append([]string{"-params", c.params, "--"}, c.gids...), &stdout); e != nil || stdout.String() != c.want {
			t.Fatalf("G2_CLI_AGENT_GROUPS positive %v: %v %q", c.gids, e, stdout.String())
		}
	}
	for _, c := range []struct {
		name   string
		params string
		gids   []string
		want   error
	}{
		{"third-group", params, []string{"1201", "1301", "4242"}, deploy.ErrPolicy},
		{"operator", params, []string{"1201", "1301", "1401"}, deploy.ErrPolicy},
		{"primary-missing", params, []string{"1301"}, deploy.ErrPolicy},
		{"socket-missing", params, []string{"1201"}, deploy.ErrPolicy},
		{"no-gid", params, nil, deploy.ErrPolicy},
		{"other-agent-primary", movedParams, []string{"1201", "1301"}, deploy.ErrPolicy},
		{"leading-zero", params, []string{"01201", "1301"}, deploy.ErrInput},
		{"not-a-number", params, []string{"1201", "peer"}, deploy.ErrInput},
		{"invalid-params", badParams, []string{"1201", "1301"}, deploy.ErrPolicy},
		{"absent-params", filepath.Join(root, "absent.json"), []string{"1201", "1301"}, deploy.ErrPolicy},
	} {
		var stdout bytes.Buffer
		if e := g2AgentGroups(append([]string{"-params", c.params, "--"}, c.gids...), &stdout); !errors.Is(e, c.want) || stdout.Len() != 0 {
			t.Fatalf("G2_CLI_AGENT_GROUPS %s admitted: %v %q", c.name, e, stdout.String())
		}
	}
}
