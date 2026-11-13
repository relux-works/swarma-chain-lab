package deploy

// Tests for the G2 real-host qualification runner t18-real-host-report.sh
// (the T18 and setpriv half). They run the script with /bin/sh on synthetic
// evidence directories, on a live unix socket and, end to end, with the real
// deploy-kit built from this tree. Nothing here runs setpriv, sysusers or
// anything as root, and nothing sends a wallet request.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	t18rhScript = "t18-real-host-report.sh"
	t18rhCommit = "ca5edc6809ae71f5365c142a0010ba95c43b27be"
	t18rhRunDK  = "43360330648" // Deploy kit checks, push on main at t18rhCommit
	t18rhRunAW  = "43360330369" // Agent wallet checks, push on main at t18rhCommit
	t18rhMarker = "T18_REAL_HOST_REQUEST_NOT_SENT"
	// TestPX1T18CoreNodePolicy first ran (W1_REGTEST=1, no skip) in the
	// px1-core-gate step added at this commit, in this Agent wallet checks run.
	t18rhNodeCommit = "dcad699da8cbc7e03436b00b85f667a5b2093b04"
	t18rhRunNode    = "43404324238"
	t18rhApplyNoop  = "apply no-op: account pre-created by Infra"
	t18rhNote       = "# positive-path: the real-wallet positive path (an authorized request that executes) is proven by the separate owner-authorized, bounded mainnet smoke gate, not by T18. On this host the wallet client sends nothing: positive-request is COVERED_BY_HOSTED, pinned to TestPX1CoreServiceG2FailClosed in run 43360330369, and is FAIL if the host evidence shows that any frame was sent."
	t18rhPerl       = "This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi"
)

// t18rhCovered is the expected COVERED_BY_HOSTED table: id, pinned test,
// commit, run, job. Every row is a negative or privileged case a correctly
// provisioned host cannot show without a destructive or privileged fixture.
var t18rhCovered = [][5]string{
	{"cov-enoent-not-denied", "TestPX1T18DeniedReadMustBeEACCES", t18rhCommit, t18rhRunDK, "checks"},
	{"cov-searchable-dir", "TestPX1T18SearchableDirectory", t18rhCommit, t18rhRunDK, "checks"},
	{"cov-rpc-not-refused", "TestPX1T18RPCClassification", t18rhCommit, t18rhRunDK, "checks"},
	{"cov-probe-uid-gate", "TestPX1T18ProbeUIDGate", t18rhCommit, t18rhRunDK, "checks"},
	{"cov-verify-refusals", "TestPX1T18VerifyRefusals", t18rhCommit, t18rhRunDK, "checks"},
	{"cov-host-flow-tripwire", "TestPX1S5HostFlowTripwire", t18rhCommit, t18rhRunDK, "checks"},
	{"cov-readback-refusals", "TestPX1T18CustodyScript", t18rhCommit, t18rhRunDK, "checks"},
	{"cov-core-node-policy", "TestPX1T18CoreNodePolicy", t18rhNodeCommit, t18rhRunNode, "px1-core-gate"},
	{"cov-wallet-foreign-peer", "TestPX1T5ServiceRefusals", t18rhCommit, t18rhRunAW, "px1-core-gate"},
	{"cov-positive-request-client", "TestCoreActionClient", t18rhCommit, t18rhRunAW, "w2-core"},
}

func t18rhSha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// t18rhRun runs the script with /bin/sh in this directory and returns its
// exit status and combined output.
func t18rhRun(t *testing.T, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{t18rhScript}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, e := cmd.CombinedOutput()
	if e != nil {
		if _, ok := e.(*exec.ExitError); !ok {
			t.Fatal("T18RH_SETUP", e)
		}
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// t18rhFix is one evidence set: the rendered directory, the parameters file
// and the operator and agent evidence directories, as the three phases leave
// them on a station whose every item passes.
type t18rhFix struct {
	p                     G2PayParameters
	spec                  CustodySpecV1
	rendered, params      string
	op, ag                string
	primary, socket       uint32
	statusIdx, firstRead  int
	specSHA, renderedSpec string
}

func (f *t18rhFix) write(t *testing.T, rel, content string) {
	t.Helper()
	path := filepath.Join(f.ag, rel)
	if strings.HasPrefix(rel, "op/") {
		path = filepath.Join(f.op, strings.TrimPrefix(rel, "op/"))
	}
	if e := os.WriteFile(path, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
}

// probes writes custody-report.json with one probe per target in spec order.
// obs overrides an observation by target.
func (f *t18rhFix) probes(t *testing.T, obs map[string]string) {
	t.Helper()
	r := CustodyReportV1{Version: 1, SpecSHA256: f.specSHA, UID: f.p.AgentUID, GID: f.primary, Pass: true}
	add := func(kind, target, expect, observed string) {
		if o, ok := obs[target]; ok {
			observed = o
		}
		pass := custodyPass(kind, observed)
		r.Probes = append(r.Probes, CustodyProbeV1{Kind: kind, Target: target, Expect: expect, Observed: observed, Pass: pass})
		r.Pass = r.Pass && pass
	}
	for _, p := range f.spec.DeniedReads {
		add("read", p, "denied", "EACCES")
	}
	for _, p := range f.spec.DeniedRPC {
		add("rpc", p, "denied", "HTTP_401")
	}
	add("socket", f.spec.AllowedSocket, "allowed", "CONNECTED")
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	f.write(t, "custody/custody-report.json", string(b)+"\n")
}

func t18rhLaunch(uid, gid uint32, groups string) string {
	u, g := strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10)
	return "Uid:\t" + u + "\t" + u + "\t" + u + "\t" + u + "\nGid:\t" + g + "\t" + g + "\t" + g + "\t" + g + "\nGroups:\t" + groups + " \nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n"
}

func t18rhFixture(t *testing.T) *t18rhFix {
	t.Helper()
	f := &t18rhFix{p: g2Params()}
	var e error
	if f.primary, f.socket, e = G2AgentSlotGIDs(f.p); e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	f.rendered, f.op, f.ag = filepath.Join(root, "rendered"), filepath.Join(root, "op"), filepath.Join(root, "ag")
	for _, d := range []string{f.rendered, f.op, filepath.Join(f.op, "render"), f.ag, filepath.Join(f.ag, "custody")} {
		if e := os.Mkdir(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	files, e := RenderG2PayTemplates(f.p)
	if e != nil {
		t.Fatal(e)
	}
	var cmp strings.Builder
	for _, name := range []string{"client.json", "custody-spec.json", "namecoin-rpc.conf", "service.json", "sysusers.conf", "tmpfiles.conf"} {
		os.WriteFile(filepath.Join(f.rendered, name), files[name], 0600)
		os.WriteFile(filepath.Join(f.op, "render", name), files[name], 0600)
		cmp.WriteString("same " + name + "\n")
	}
	if f.spec, e = ParseCustodySpec(files[G2FileCustodySpec][:len(files[G2FileCustodySpec])-1]); e != nil {
		t.Fatal(e)
	}
	f.specSHA = CustodySpecSHA256(f.spec)
	f.renderedSpec = filepath.Join(f.rendered, G2FileCustodySpec)
	f.statusIdx, f.firstRead = -1, 0
	for i, p := range f.spec.DeniedReads {
		if p == G2StatusSocketDir {
			f.statusIdx = i
		}
	}
	raw, e := json.Marshal(f.p)
	if e != nil {
		t.Fatal(e)
	}
	f.params = filepath.Join(root, "parameters.json")
	os.WriteFile(f.params, append(raw, '\n'), 0600)

	f.write(t, "op/render-cmp.txt", cmp.String())
	f.write(t, "op/exits.txt", "render_exit=0\nhost_flow_exit=0\naccount_groups_exit=0\n")
	f.write(t, "op/host-flow.out", "G2_HOST_FLOW_ACTIVATED\n")
	f.write(t, "op/host-flow-mode.txt", "apply=noop activation=noop sysusers=true\n")
	f.write(t, "op/account-real.txt", "uid=1201 gid=1201 groups=1201,1301\n")
	f.write(t, "op/account-groups.txt", "G2_AGENT_GROUPS_OK observed_gid=1201 declared_primary_gid=1201 socket_gid=1301\n")
	f.write(t, "op/txindex.json", `{"txindex":{"synced":true,"best_block_height":812345}}`)
	f.write(t, "inputs.sha256", t18rhSha(files[G2FileCustodySpec])+"\n"+t18rhSha(files[G2FileClientConfig])+"\n"+t18rhSha(append(raw, '\n'))+"\n")
	f.write(t, "launch.txt", t18rhLaunch(f.p.AgentUID, f.primary, strconv.FormatUint(uint64(f.primary), 10)+" "+strconv.FormatUint(uint64(f.socket), 10)))
	f.write(t, "custody/credentials.txt", "uid=1201 gid=1201 groups=1201 1301\n")
	f.write(t, "custody/credentials-check.txt", "G2_AGENT_GROUPS_OK observed_gid=1201 declared_primary_gid=1201 socket_gid=1301\n")
	f.probes(t, nil)
	f.write(t, "custody/exits.txt", "uid=1201 probe_exit=0 positive_exit=3 verify_exit=0\n")
	f.write(t, "custody/custody-verify.txt", "T18_CUSTODY_VERIFIED "+f.specSHA+"\n")
	f.write(t, "custody/positive-request.json", `{"v":1}`)
	f.write(t, "custody/positive-receipt.json", t18rhMarker+"\n")
	f.write(t, "peer.txt", "PEER connect=ok uid=1101 gid=1101\n")
	f.write(t, "socket-stat.txt", "socket|1101|1301|660\n")
	f.write(t, "perl-version.txt", t18rhPerl+"\n")
	return f
}

func (f *t18rhFix) report(t *testing.T, wallet string) (int, string) {
	t.Helper()
	return t18rhRun(t, nil, "report", f.op, f.ag, f.rendered, f.params, wallet)
}

// t18rhIDs returns the item ids of a report (no header, OVERALL, comment or
// the literal no-op apply line).
func t18rhIDs(out string) []string {
	var ids []string
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i == 0 || strings.HasPrefix(line, "OVERALL ") || strings.HasPrefix(line, "#") || line == t18rhApplyNoop {
			continue
		}
		ids = append(ids, strings.Fields(line)[0])
	}
	return ids
}

// Claim: the report emits exactly the T18 item set of the contract, in order:
// the node precondition (txindex), render, the account checks, the agent's
// inputs, the setpriv launch form, the credential readback, one denied-read
// item per denied_reads path of the frozen launch custody spec (rendered by
// RenderG2PayTemplates, in spec order), the status directory (A8, which must
// be one of them), one denied-rpc item per denied_rpc target, the peer
// identity precondition (perl), the wallet socket, the custody verify step,
// the positive own-agent request and the COVERED_BY_HOSTED table. The literal
// line "apply no-op: account pre-created by Infra" stands once, right before
// the account item, and the positive-path statement (the owner-authorized
// mainnet smoke gate proves the real-wallet positive path, not T18) once,
// right before positive-request. Every pin names a test function present in
// this tree; the commit is ca5edc68 and the run the hosted push run of the
// module that holds the test, except TestPX1T18CoreNodePolicy, pinned to the
// px1-core-gate run at dcad699d that ran it with W1_REGTEST=1.
// T18-REAL-HOST.md carries the SMOKE-G2.md §4 launch line verbatim, both
// literal statements and the pins, and deploy/README.md links it. Limit: that
// the pinned tests ran green in those runs is recorded from the hosted runs,
// not re-checked here.
func TestT18RealHostItemContract(t *testing.T) {
	f := t18rhFixture(t)
	if e := ValidateG2CustodyLaunchSpec(f.spec); e != nil || f.statusIdx < 0 {
		t.Fatal("T18RH_CONTRACT the fixture is not the launch spec", e, f.statusIdx)
	}
	want := []string{"node-txindex", "render", "account", "agent-inputs", "launch-form", "credentials"}
	for _, p := range f.spec.DeniedReads {
		want = append(want, "denied-read:"+p)
		if p == G2StatusSocketDir {
			want = append(want, "status-dir")
		}
	}
	for _, r := range f.spec.DeniedRPC {
		want = append(want, "denied-rpc:"+r)
	}
	want = append(want, "peer-precondition", "allowed-socket", "custody-verify", "positive-request")
	for _, c := range t18rhCovered {
		want = append(want, c[0])
	}
	code, out := f.report(t, "real")
	if code != 0 || !strings.Contains(out, "\nOVERALL PASS ") {
		t.Fatalf("T18RH_CONTRACT the all-pass evidence did not pass: %d\n%s", code, out)
	}
	if got := t18rhIDs(out); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("T18RH_CONTRACT item set\n got %q\nwant %q", got, want)
	}
	header := "T18-REAL-HOST v1 wallet=real commit=" + t18rhCommit + " spec_sha256=" + f.specSHA + " agent_uid=1201 primary_gid=1201 socket_gid=1301 service_uid=1101\n"
	if !strings.HasPrefix(out, header) {
		t.Fatalf("T18RH_CONTRACT header %q", strings.SplitN(out, "\n", 2)[0])
	}
	if strings.Count(out, "\n"+t18rhApplyNoop+"\naccount PASS ") != 1 || strings.Count(out, t18rhApplyNoop) != 1 {
		t.Fatal("T18RH_CONTRACT the no-op apply line is not printed once, before the account item\n", out)
	}
	if strings.Count(out, "\n"+t18rhNote+"\npositive-request COVERED_BY_HOSTED ") != 1 || strings.Count(out, "# positive-path:") != 1 {
		t.Fatal("T18RH_CONTRACT the positive-path statement is not printed once, before positive-request\n", out)
	}
	if !strings.HasSuffix(out, " run=real\n") {
		t.Fatal("T18RH_CONTRACT the OVERALL line does not name the real run\n", out)
	}

	code, items := t18rhRun(t, nil, "items")
	var wantItems strings.Builder
	for _, c := range t18rhCovered {
		wantItems.WriteString(c[0] + " COVERED_BY_HOSTED pin=" + c[1] + " commit=" + c[2] + " run=" + c[3] + " job=" + c[4] + "\n")
	}
	if code != 0 || items != wantItems.String() {
		t.Fatalf("T18RH_CONTRACT pin table\n got %q\nwant %q", items, wantItems.String())
	}
	if !strings.Contains(out, "\npositive-request COVERED_BY_HOSTED pin=TestPX1CoreServiceG2FailClosed commit="+t18rhCommit+" run="+t18rhRunAW+" job=px1-core-gate host=not-sent positive_path=mainnet-smoke-gate\n") {
		t.Fatal("T18RH_CONTRACT positive-request pin", out)
	}
	pinned := append([]string{"TestPX1CoreServiceG2FailClosed"}, func() (n []string) {
		for _, c := range t18rhCovered {
			n = append(n, c[1])
		}
		return
	}()...)
	for _, name := range pinned {
		dir := "."
		if !strings.HasPrefix(name, "TestPX1T18") && !strings.HasPrefix(name, "TestPX1S5") {
			dir = filepath.Join("..", "experiments", "agent-wallet")
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
		found := 0
		for _, path := range files {
			raw, _ := os.ReadFile(path)
			found += strings.Count(string(raw), "\nfunc "+name+"(t *testing.T)")
		}
		if found != 1 {
			t.Fatalf("T18RH_CONTRACT pin %s: %d definitions in %s", name, found, dir)
		}
	}

	doc, e := os.ReadFile("T18-REAL-HOST.md")
	if e != nil {
		t.Fatal(e)
	}
	smoke, e := os.ReadFile("SMOKE-G2.md")
	if e != nil {
		t.Fatal(e)
	}
	launch := `setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --init-groups -- \`
	for _, line := range []string{launch,
		`AGENT_UID=$(awk -v u="$AGENT_USER" '$1 == "u" && $2 == u { split($3, id, ":"); print id[1] }' sysusers.conf)`,
		`AGENT_GID=$(awk -v u="$AGENT_USER" '$1 == "u" && $2 == u { n = split($3, id, ":"); print id[n] }' sysusers.conf)`} {
		if !strings.Contains(string(smoke), line) || !strings.Contains(string(doc), line) {
			t.Fatalf("T18RH_CONTRACT SMOKE-G2.md §4 line not carried verbatim: %s", line)
		}
	}
	for _, id := range append(want, t18rhRunDK, t18rhRunAW, t18rhCommit, t18rhRunNode, t18rhNodeCommit, "TestPX1T18CoreNodePolicy", t18rhApplyNoop,
		"proven by the separate owner-authorized, bounded mainnet smoke gate, not by T18", "valid-only-as-a-stand-in-run", "perl -v") {
		if strings.HasPrefix(id, "denied-read:") || strings.HasPrefix(id, "denied-rpc:") {
			continue
		}
		if !strings.Contains(strings.Join(strings.Fields(string(doc)), " "), id) {
			t.Fatalf("T18RH_CONTRACT T18-REAL-HOST.md does not name %s", id)
		}
	}
	readme, e := os.ReadFile("README.md")
	if e != nil || !strings.Contains(string(readme), "](T18-REAL-HOST.md)") {
		t.Fatal("T18RH_CONTRACT deploy/README.md does not link T18-REAL-HOST.md", e)
	}
	if regexp.MustCompile(`--regid="?\$AGENT_USER|--regid=[a-z]`).Match(doc) {
		t.Fatal("T18RH_CONTRACT T18-REAL-HOST.md gives --regid a name")
	}
}

// Claim: the composer turns each known-bad host observation into a FAIL of
// the named item and an OVERALL FAIL with exit 1, beside the all-pass evidence
// (OVERALL PASS, exit 0) and the stand-in evidence (every placeholder-backed
// item STAND_IN, none PASS, OVERALL PASS valid only as a stand-in run). In
// particular an ENOENT on a denied_reads path is never counted as denied (a
// missing stand-in placeholder included), a stand-in listener (peer UID 0) is
// never a PASS, a stand-in is STAND_IN only when the socket connected, a sent
// wallet request or any client error output fails the positive-request item
// instead of hiding behind its hosted pin, the account item fails whenever
// the exact group set read from the REAL account is refused, missing or for
// another UID even though g2-host-flow passed, and when the no-op apply mode
// is not recorded; and peer-precondition fails without perl's version line.
func TestT18RealHostReportControls(t *testing.T) {
	files, _ := RenderG2PayTemplates(g2Params())
	spec, _ := ParseCustodySpec(files[G2FileCustodySpec][:len(files[G2FileCustodySpec])-1])
	read0, rpc0 := spec.DeniedReads[0], spec.DeniedRPC[0]
	stdLaunch := func(t *testing.T, f *t18rhFix, groups string, uid, gid uint32) {
		f.write(t, "launch.txt", t18rhLaunch(uid, gid, groups))
	}
	cases := []struct {
		name, wallet string
		edit         func(*testing.T, *t18rhFix)
		code         int
		line         string // regexp that must match a whole line
	}{
		{"valid-real", "real", func(*testing.T, *t18rhFix) {}, 0, `^OVERALL PASS pass=\d+ stand_in=0 covered=11 fail=0 invalid=0 missing=0 run=real$`},
		{"valid-stand-in", "stand-in", func(t *testing.T, f *t18rhFix) {
			f.write(t, "peer.txt", "PEER connect=ok uid=0 gid=0\n")
			f.write(t, "socket-stat.txt", "socket|0|1301|660\n")
		}, 0, `^allowed-socket STAND_IN wallet=stand-in probe=CONNECTED peer_uid=0 service_uid=1101 `},
		{"valid-stand-in-overall", "stand-in", func(*testing.T, *t18rhFix) {}, 0, `^OVERALL PASS pass=\d+ stand_in=\d+ covered=11 fail=0 invalid=0 missing=0 run=stand-in valid-only-as-a-stand-in-run$`},
		{"stand-in-placeholder-missing", "stand-in", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{read0: "ENOENT"}) }, 1, `^denied-read:` + regexp.QuoteMeta(read0) + ` FAIL observed=ENOENT$`},
		{"account-real-group-set-refused", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/account-real.txt", "uid=1201 gid=1201 groups=1201,1301,1401\n")
			f.write(t, "op/account-groups.txt", "deploy: invalid policy\n")
			f.write(t, "op/exits.txt", "render_exit=0\nhost_flow_exit=0\naccount_groups_exit=1\n")
		}, 1, `^account FAIL host_flow=G2_HOST_FLOW_ACTIVATED apply_noop=1 real_account=uid=1201_gid=1201_groups=1201,1301,1401 group_set=deploy:_invalid_policy$`},
		{"account-real-group-set-missing", "real", func(t *testing.T, f *t18rhFix) {
			os.Remove(filepath.Join(f.op, "account-groups.txt"))
			f.write(t, "op/exits.txt", "render_exit=0\nhost_flow_exit=0\n")
		}, 1, `^account FAIL host_flow=G2_HOST_FLOW_ACTIVATED apply_noop=1 .* group_set=$`},
		{"account-real-group-set-exit", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/exits.txt", "render_exit=0\nhost_flow_exit=0\naccount_groups_exit=1\n")
		}, 1, `^account FAIL host_flow=G2_HOST_FLOW_ACTIVATED apply_noop=1 `},
		{"account-real-other-uid", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/account-real.txt", "uid=1202 gid=1201 groups=1201,1301\n")
		}, 1, `^account FAIL host_flow=G2_HOST_FLOW_ACTIVATED apply_noop=1 real_account=uid=1202_`},
		{"account-noop-not-recorded", "real", func(t *testing.T, f *t18rhFix) { os.Remove(filepath.Join(f.op, "host-flow-mode.txt")) }, 1, `^account FAIL host_flow=G2_HOST_FLOW_ACTIVATED apply_noop=0 `},
		{"perl-missing", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "perl-version.txt", "") }, 1, `^peer-precondition FAIL perl_v=none$`},
		{"perl-other-line", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "perl-version.txt", "sh: 1: perl: not found\n") }, 1, `^peer-precondition FAIL perl_v=sh:_1:_perl:_not_found$`},
		{"request-client-error", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "custody/positive.err", "dial: connected\n") }, 1, `^positive-request FAIL host=request-sent-or-unknown$`},
		{"enoent-denied-read", "real", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{read0: "ENOENT"}) }, 1, `^denied-read:` + regexp.QuoteMeta(read0) + ` FAIL observed=ENOENT$`},
		{"readable-denied-read", "real", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{read0: "READ_OK"}) }, 1, `^denied-read:` + regexp.QuoteMeta(read0) + ` FAIL observed=READ_OK$`},
		{"status-dir-enoent", "real", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{G2StatusSocketDir: "ENOENT"}) }, 1, `^status-dir FAIL path=/run/swarma-wallet-status observed=ENOENT$`},
		{"rpc-answered", "real", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{rpc0: "HTTP_OK"}) }, 1, `^denied-rpc:` + regexp.QuoteMeta(rpc0) + ` FAIL observed=HTTP_OK$`},
		{"no-custody-report", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "custody/custody-report.json", "") }, 1, `^denied-read:` + regexp.QuoteMeta(read0) + ` FAIL observed=none$`},
		{"stand-in-declared-real", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "peer.txt", "PEER connect=ok uid=0 gid=0\n")
			f.write(t, "socket-stat.txt", "socket|0|1301|660\n")
		}, 1, `^allowed-socket FAIL wallet=real probe=CONNECTED peer_uid=0 `},
		{"real-wallet-wrong-socket-owner", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "socket-stat.txt", "socket|0|1301|660\n") }, 1, `^allowed-socket FAIL wallet=real `},
		{"real-wallet-socket-mode", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "socket-stat.txt", "socket|1101|1301|666\n") }, 1, `^allowed-socket FAIL wallet=real `},
		{"real-wallet-no-peer", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "peer.txt", "PEER connect=failed\n") }, 1, `^allowed-socket FAIL wallet=real probe=CONNECTED peer_uid=none `},
		{"stand-in-not-connected", "stand-in", func(t *testing.T, f *t18rhFix) {
			f.probes(t, map[string]string{"/run/swarma-wallet/wallet.sock": "EACCES"})
			f.write(t, "peer.txt", "PEER connect=failed\n")
		}, 1, `^allowed-socket FAIL wallet=stand-in probe=EACCES `},
		{"request-sent", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/positive-receipt.json", `{"receipt":{"verdict":"executed"}}`+"\n")
			f.write(t, "custody/exits.txt", "uid=1201 probe_exit=0 positive_exit=0 verify_exit=0\n")
		}, 1, `^positive-request FAIL host=request-sent-or-unknown$`},
		{"request-marker-but-other-exit", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/exits.txt", "uid=1201 probe_exit=0 positive_exit=0 verify_exit=0\n")
		}, 1, `^positive-request FAIL host=request-sent-or-unknown$`},
		{"launch-swapped-roles", "real", func(t *testing.T, f *t18rhFix) { stdLaunch(t, f, "1301 1201", 1201, 1301) }, 1, `^launch-form FAIL uid=1201,1201,1201,1201 gid=1301,1301,1301,1301 `},
		{"launch-reduced-groups", "real", func(t *testing.T, f *t18rhFix) { stdLaunch(t, f, "1301", 1201, 1201) }, 1, `^launch-form FAIL .* groups=1301 `},
		{"launch-extra-group", "real", func(t *testing.T, f *t18rhFix) { stdLaunch(t, f, "1201 1301 1401", 1201, 1201) }, 1, `^launch-form FAIL .* groups=1201,1301,1401 `},
		{"launch-not-agent", "real", func(t *testing.T, f *t18rhFix) { stdLaunch(t, f, "1201 1301", 1101, 1201) }, 1, `^launch-form FAIL uid=1101,1101,1101,1101 `},
		{"launch-saved-root", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "launch.txt", strings.Replace(t18rhLaunch(1201, 1201, "1201 1301"), "Uid:\t1201\t1201\t1201", "Uid:\t1201\t1201\t0", 1))
		}, 1, `^launch-form FAIL uid=1201,1201,0,1201 `},
		{"launch-capability", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "launch.txt", strings.Replace(t18rhLaunch(1201, 1201, "1201 1301"), "CapEff:\t0000000000000000", "CapEff:\t0000000000000400", 1))
		}, 1, `^launch-form FAIL .* caps=0000000000000000,0000000000000400 `},
		{"launch-missing", "real", func(t *testing.T, f *t18rhFix) { os.Remove(filepath.Join(f.ag, "launch.txt")) }, 1, `^launch-form FAIL uid=none `},
		{"credentials-refused", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/exits.txt", "credentials=refused\n")
			f.write(t, "custody/credentials-check.txt", "deploy: invalid policy\n")
			for _, n := range []string{"custody-report.json", "custody-verify.txt", "positive-request.json", "positive-receipt.json"} {
				os.Remove(filepath.Join(f.ag, "custody", n))
			}
		}, 1, `^credentials FAIL uid=1201,gid=1201,groups=1201,1301 check=deploy:,invalid,policy$`},
		{"credentials-check-other-gid", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/credentials-check.txt", "G2_AGENT_GROUPS_OK observed_gid=1301 declared_primary_gid=1201 socket_gid=1301\n")
		}, 1, `^credentials FAIL `},
		{"verify-failed", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/exits.txt", "uid=1201 probe_exit=0 positive_exit=3 verify_exit=1\n")
		}, 1, `^custody-verify FAIL exits=uid=1201,probe_exit=0,positive_exit=3,verify_exit=1 `},
		{"verify-other-spec", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/custody-verify.txt", "T18_CUSTODY_VERIFIED "+strings.Repeat("0", 64)+"\n")
		}, 1, `^custody-verify FAIL `},
		{"probe-failed", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/exits.txt", "uid=1201 probe_exit=1 positive_exit=3 verify_exit=0\n")
		}, 1, `^custody-verify FAIL `},
		{"txindex-syncing", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/txindex.json", `{"txindex":{"synced":false,"best_block_height":812345}}`)
		}, 1, `^node-txindex FAIL getindexinfo=\{"txindex":\{"synced":false,`},
		{"txindex-missing", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "op/txindex.json", "") }, 1, `^node-txindex FAIL getindexinfo=missing$`},
		{"render-differs", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/render-cmp.txt", "same client.json\ndiffer custody-spec.json\nsame namecoin-rpc.conf\nsame service.json\nsame sysusers.conf\nsame tmpfiles.conf\n")
		}, 1, `^render FAIL differ=custody-spec.json,none render_exit=0$`},
		{"account-refused", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/exits.txt", "render_exit=0\nhost_flow_exit=1\n")
			f.write(t, "op/host-flow.out", "g2 host flow: post-apply group set: deploy: invalid policy\n")
		}, 1, `^account FAIL host_flow=g2_host_flow:_post-apply_group_set:_deploy:_invalid_policy apply_noop=1 `},
		{"agent-inputs-differ", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "inputs.sha256", "0\n0\n0\n") }, 1, `^agent-inputs FAIL `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := t18rhFixture(t)
			c.edit(t, f)
			code, out := f.report(t, c.wallet)
			if code != c.code || !regexp.MustCompile(`(?m)`+c.line).MatchString(out) {
				t.Fatalf("T18RH_REPORT %s: exit %d (want %d), want line %s\n%s", c.name, code, c.code, c.line, out)
			}
			overall := "\nOVERALL PASS "
			if c.code != 0 {
				overall = "\nOVERALL FAIL "
			}
			if !strings.Contains(out, overall) {
				t.Fatalf("T18RH_REPORT %s: no %q\n%s", c.name, overall, out)
			}
			if c.code != 0 && strings.Contains(out, " fail=0 invalid=0 missing=0") {
				t.Fatalf("T18RH_REPORT %s: a failing item did not count\n%s", c.name, out)
			}
			// A stand-in run never reports a placeholder-backed item PASS.
			if c.wallet == "stand-in" && regexp.MustCompile(`(?m)^(denied-read:\S+|status-dir|allowed-socket) PASS `).MatchString(out) {
				t.Fatalf("T18RH_REPORT %s: a placeholder-backed item is PASS on a stand-in run\n%s", c.name, out)
			}
			if c.name == "valid-stand-in-overall" && strings.Count(out, " STAND_IN ") != len(f.spec.DeniedReads)+2 {
				t.Fatalf("T18RH_REPORT %s: want every denied read, status-dir and the socket STAND_IN\n%s", c.name, out)
			}
		})
	}
}

// Claim: check, run on a stored report, recomputes OVERALL and exits 0 only
// for a consistent report: the valid real-wallet report and the valid
// all-PASS/COVERED_BY_HOSTED/STAND_IN stand-in report pass. Each known-bad
// edit of the valid report is refused with exit 1, OVERALL FAIL and the named
// reason: a FAIL item; a COVERED item without its pin, commit or hosted run
// id, or with a run id that is not one of the two pinned runs; a wallet PASS
// on a stand-in host; STAND_IN on a real-wallet host or on another item; a
// denied read reported PASS on ENOENT; a status directory or an RPC target
// PASS without a refusal; a wallet PASS without the service peer UID; a
// positive request COVERED without host=not-sent; a covered item claimed as a
// host PASS; a missing, duplicate or unknown-verdict item; a bad header; and a
// stated OVERALL PASS that the items contradict. The r2 conditions add: a
// COVERED item whose pin, commit, run or job differs from its table row (in
// particular TestPX1T18CoreNodePolicy pinned to the Deploy kit run in which it
// skipped); a stand-in run with any placeholder-backed item (a denied read,
// the status directory, the socket) PASS; STAND_IN for a denied read on a real
// run; an account PASS without the literal no-op apply line, with it twice,
// or without the REAL account's exact set evidence; a missing positive-path
// statement or positive_path token; and a perl-less peer precondition PASS.
func TestT18RealHostCheckControls(t *testing.T) {
	f := t18rhFixture(t)
	code, real := f.report(t, "real")
	if code != 0 {
		t.Fatal("T18RH_CHECK setup", real)
	}
	f.write(t, "peer.txt", "PEER connect=ok uid=0 gid=0\n")
	code, standIn := f.report(t, "stand-in")
	if code != 0 || !strings.Contains(standIn, "\nallowed-socket STAND_IN ") {
		t.Fatal("T18RH_CHECK setup stand-in", standIn)
	}
	dir := t.TempDir()
	check := func(name, text string) (int, string) {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte(text), 0600)
		return t18rhRun(t, nil, "check", path)
	}
	for name, text := range map[string]string{"valid-real": real, "valid-stand-in": standIn} {
		if code, out := check(name, text); code != 0 || !strings.HasPrefix(out, "OVERALL PASS ") {
			t.Fatalf("T18RH_CHECK %s refused: %d %s", name, code, out)
		}
	}
	if _, out := check("valid-stand-in-run", standIn); !strings.HasSuffix(out, " run=stand-in valid-only-as-a-stand-in-run\n") {
		t.Fatalf("T18RH_CHECK a stand-in OVERALL line does not say it is valid only as a stand-in run: %s", out)
	}
	read0 := "denied-read:" + f.spec.DeniedReads[0]
	sub := func(text, re, repl string) string {
		out := regexp.MustCompile(`(?m)`+re).ReplaceAllString(text, repl)
		if out == text {
			t.Fatalf("T18RH_CHECK edit %q matched nothing", re)
		}
		return out
	}
	cases := []struct{ name, text, reason string }{
		{"fail-item", sub(real, `^account PASS .*$`, "account FAIL host_flow=refused"), "fail=1"},
		{"covered-no-pin", sub(real, `^(cov-searchable-dir COVERED_BY_HOSTED) pin=\S+ `, "$1 "), "no-pin:cov-searchable-dir"},
		{"covered-empty-pin", sub(real, `^(cov-searchable-dir COVERED_BY_HOSTED) pin=\S+ `, "$1 pin= "), "no-pin:cov-searchable-dir"},
		{"covered-no-run", sub(real, `^(cov-host-flow-tripwire .*) run=\d+ `, "$1 "), "no-run:cov-host-flow-tripwire"},
		{"covered-other-run", sub(real, `^(cov-host-flow-tripwire .*) run=\d+ `, "$1 run=1 "), "no-run:cov-host-flow-tripwire"},
		{"covered-no-commit", sub(real, `^(cov-verify-refusals .*) commit=\S+ `, "$1 "), "no-commit:cov-verify-refusals"},
		{"positive-no-run", sub(real, `^(positive-request .*) run=\d+ `, "$1 "), "no-run:positive-request"},
		{"positive-sent", sub(real, `host=not-sent `, "host=sent "), "request-not-shown-unsent"},
		{"wallet-pass-on-stand-in", sub(standIn, `^allowed-socket STAND_IN `, "allowed-socket PASS "), "wallet-pass-on-stand-in"},
		{"stand-in-on-real", sub(real, `^allowed-socket PASS `, "allowed-socket STAND_IN "), "stand-in-misplaced:allowed-socket"},
		{"stand-in-other-item", sub(standIn, `^account PASS `, "account STAND_IN "), "stand-in-misplaced:account"},
		{"enoent-as-denied", sub(real, `^(`+regexp.QuoteMeta(read0)+`) PASS observed=EACCES$`, "$1 PASS observed=ENOENT"), "read-pass-without-eacces:" + read0},
		{"status-enoent", sub(real, `^status-dir PASS path=(\S+) observed=EACCES$`, "status-dir PASS path=$1 observed=ENOENT"), "status-pass-without-eacces"},
		{"rpc-answered", sub(real, `^(denied-rpc:\S+) PASS observed=HTTP_401$`, "$1 PASS observed=HTTP_OK"), "rpc-pass-without-refusal:"},
		{"wallet-other-peer", sub(real, `peer_uid=1101 `, "peer_uid=0 "), "wallet-pass-without-peer-identity"},
		{"wallet-not-connected", sub(real, `probe=CONNECTED `, "probe=REFUSED "), "wallet-pass-without-connect"},
		{"covered-as-pass", sub(real, `^cov-rpc-not-refused COVERED_BY_HOSTED `, "cov-rpc-not-refused PASS "), "covered-item-verdict:cov-rpc-not-refused"},
		{"host-item-covered", sub(real, `^credentials PASS `, "credentials COVERED_BY_HOSTED pin=TestPX1T18CustodyScript commit="+t18rhCommit+" run="+t18rhRunDK+" "), "covered-not-allowed:credentials"},
		{"missing-item", sub(real, `^custody-verify .*\n`, ""), "missing:custody-verify"},
		{"missing-covered", sub(real, `^cov-wallet-foreign-peer .*\n`, ""), "missing:cov-wallet-foreign-peer"},
		{"missing-denied-rpc", sub(real, `^denied-rpc:.*\n`, ""), "missing:denied-rpc"},
		{"duplicate", sub(real, `^(render PASS .*)$`, "$1\n$1"), "duplicate:render"},
		{"unknown-verdict", sub(real, `^render PASS `, "render SKIP "), "verdict:render"},
		{"no-evidence", sub(real, `^render PASS .*$`, "render PASS"), "no-evidence:render"},
		{"bad-header", sub(real, `^T18-REAL-HOST v1 wallet=real `, "T18-REAL-HOST v1 wallet=maybe "), "header"},
		{"empty", "", "header"},
		{"node-policy-skipped-run", sub(real, `^(cov-core-node-policy .*) commit=\S+ run=\d+ `, "$1 commit="+t18rhCommit+" run="+t18rhRunDK+" "), "no-run:cov-core-node-policy"},
		{"node-policy-other-commit", sub(real, `^(cov-core-node-policy .*) commit=\S+ `, "$1 commit="+t18rhCommit+" "), "no-commit:cov-core-node-policy"},
		{"covered-other-pin", sub(real, `^(cov-searchable-dir COVERED_BY_HOSTED) pin=\S+ `, "$1 pin=TestPX1T18RPCClassification "), "no-pin:cov-searchable-dir"},
		{"covered-other-job", sub(real, `^(cov-wallet-foreign-peer .*) job=\S+$`, "$1 job=w2-core"), "no-job:cov-wallet-foreign-peer"},
		{"covered-unknown", sub(real, `^cov-searchable-dir `, "cov-anything "), "covered-not-allowed:cov-anything"},
		{"stand-in-read-pass", sub(standIn, `^(denied-read:\S+) STAND_IN `, "$1 PASS "), "stand-in-placeholder-pass:" + read0},
		{"stand-in-status-pass", sub(standIn, `^status-dir STAND_IN `, "status-dir PASS "), "stand-in-placeholder-pass:status-dir"},
		{"stand-in-read-on-real", sub(real, `^(`+regexp.QuoteMeta(read0)+`) PASS `, "$1 STAND_IN "), "stand-in-misplaced:" + read0},
		{"stand-in-read-enoent", sub(standIn, `^(`+regexp.QuoteMeta(read0)+`) STAND_IN observed=EACCES$`, "$1 STAND_IN observed=ENOENT"), "read-pass-without-eacces:" + read0},
		{"apply-line-removed", sub(real, `^`+regexp.QuoteMeta(t18rhApplyNoop)+`\n`, ""), "apply-noop-line"},
		{"apply-line-twice", sub(real, `^(`+regexp.QuoteMeta(t18rhApplyNoop)+`)$`, "$1\n$1"), "apply-noop-line"},
		{"account-no-noop", sub(real, `^(account PASS .*) apply=noop `, "$1 apply=sysusers "), "account-pass-without-noop-apply"},
		{"account-no-group-set", sub(real, `^(account PASS .*) group_set=G2_AGENT_GROUPS_OK$`, "$1"), "account-pass-without-real-group-set"},
		{"account-other-real", sub(real, `real_account=uid=1201_gid=1201_groups=1201,1301 `, "real_account=uid=1201_gid=1201_groups=1201,1301,1401 "), "account-pass-without-real-account"},
		{"positive-note-removed", sub(real, `^# positive-path: .*\n`, ""), "positive-path-statement"},
		{"positive-path-token-removed", sub(real, ` positive_path=mainnet-smoke-gate$`, ""), "positive-path-not-stated"},
		{"perl-pass-without-version", sub(real, `^peer-precondition PASS perl_v=\S+$`, "peer-precondition PASS perl_v=none"), "peer-precondition-without-perl-version"},
		{"missing-peer-precondition", sub(real, `^peer-precondition .*\n`, ""), "missing:peer-precondition"},
	}
	for _, c := range cases {
		code, out := check(c.name, c.text)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, c.reason) {
			t.Fatalf("T18RH_CHECK %s: exit %d, want 1 with %q\n%s", c.name, code, c.reason, out)
		}
	}
	// A stated OVERALL PASS above a failing item is refused as a contradiction.
	lied := sub(real, `^account PASS .*$`, "account FAIL host_flow=refused")
	if code, out := check("stated-pass", lied); code != 1 || !strings.Contains(out, "# stated OVERALL PASS disagrees") {
		t.Fatalf("T18RH_CHECK stated OVERALL: %d\n%s", code, out)
	}
}

// Claim: the dry run needs no root, no station and no deploy-kit: self-test
// composes its synthetic evidence through the real report path and prints
// SELF_TEST PASS with exit 0 only when the valid samples pass (the real run
// with its no-op apply line, the stand-in run with its placeholders STAND_IN
// and its OVERALL line valid only as a stand-in run) and its known-bad samples
// (a placeholder reported PASS on a stand-in run, a refused real-account
// group set, ENOENT, a stand-in declared real, a sent request, STAND_IN on a
// real wallet) fail with their named lines.
func TestT18RealHostSelfTest(t *testing.T) {
	code, out := t18rhRun(t, []string{"DEPLOY_KIT=/nonexistent/deploy-kit"}, "self-test")
	if code != 0 || !strings.HasSuffix(out, "SELF_TEST PASS\n") || strings.Count(out, " ok exit=") != 10 {
		t.Fatalf("T18RH_SELF_TEST %d\n%s", code, out)
	}
}

// Claim: no-request mode, the AGENT_WALLET of the custody script in the agent
// phase, sends nothing: with T18_REAL_HOST_NO_REQUEST=1 and the custody
// script's exact argument shape it prints only the marker and exits 3, and it
// refuses (64, no marker) without that variable, so the runner can never be
// mistaken for a wallet client.
func TestT18RealHostNoRequestMode(t *testing.T) {
	code, out := t18rhRun(t, []string{"T18_REAL_HOST_NO_REQUEST=1"}, "--config", "client.json", "--request", "request.json")
	if code != 3 || out != t18rhMarker+"\n" {
		t.Fatalf("T18RH_NO_REQUEST %d %q", code, out)
	}
	code, out = t18rhRun(t, []string{"T18_REAL_HOST_NO_REQUEST="}, "--config", "client.json", "--request", "request.json")
	if code != 64 || strings.Contains(out, t18rhMarker) {
		t.Fatalf("T18RH_NO_REQUEST without the variable %d %q", code, out)
	}
	for _, args := range [][]string{{}, {"nonsense"}, {"report"}, {"check"}, {"agent", "x"}, {"operator", "x"}, {"--config", "c", "--request"}} {
		if code, _ := t18rhRun(t, nil, args...); code != 64 {
			t.Fatalf("T18RH_USAGE %q exit %d", args, code)
		}
	}
}

// t18rhListener serves a unix socket that records how many bytes each
// connection sent before it closed.
func t18rhListener(t *testing.T, path string) chan int {
	t.Helper()
	l, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan int, 16)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			n, _ := io.Copy(io.Discard, c)
			c.Close()
			got <- int(n)
		}
	}()
	return got
}

// Claim: peer connects to the socket, reads the listener's kernel credentials
// (SO_PEERCRED) and sends no byte: on a live listener it prints exactly
// "PEER connect=ok uid=<listener UID> gid=<listener GID>" and the listener
// receives zero bytes; with no listener it prints "PEER connect=failed" and
// exits 2. Limit: the listener runs as the test UID (same-UID); the
// cross-UID identification is the real-wallet host item.
func TestT18RealHostPeerIdentity(t *testing.T) {
	if _, e := exec.LookPath("perl"); e != nil {
		t.Skip("T18RH_PEER perl is not installed: the peer identity layer did not run")
	}
	dir, e := os.MkdirTemp("", "t18rh")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "w.sock")
	got := t18rhListener(t, sock)
	code, out := t18rhRun(t, nil, "peer", sock)
	want := "PEER connect=ok uid=" + strconv.Itoa(os.Getuid()) + " gid=" + strconv.Itoa(os.Getgid()) + "\n"
	if code != 0 || out != want {
		t.Fatalf("T18RH_PEER %d %q want %q", code, out, want)
	}
	select {
	case n := <-got:
		if n != 0 {
			t.Fatalf("T18RH_PEER the check sent %d bytes", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("T18RH_PEER the listener saw no connection")
	}
	if code, out := t18rhRun(t, nil, "peer", filepath.Join(dir, "absent.sock")); code != 2 || out != "PEER connect=failed\n" {
		t.Fatalf("T18RH_PEER absent socket %d %q", code, out)
	}
}

// Claim (end to end on this host, as the test UID): the agent phase runs the
// unchanged g2-custody-check.sh with the real deploy-kit (readback, probe,
// verify) and the runner as AGENT_WALLET, so the wallet socket receives no
// byte from any of its connections and no request is sent: the custody
// script prints T18_FAIL by construction, exits.txt records positive_exit=3
// and the receipt is the marker. The operator phase re-renders the parameters
// with the real deploy-kit and compares them byte for byte with the rendered
// directory; it records the no-op apply mode and reads the account's exact
// group set through the real g2-agent-groups, which accepts {UID, 1301} and
// refuses the same account with a third group. The report then shows credentials PASS (the readback accepted
// the fixture `id`), every fixture denied read EACCES (STAND_IN), the RPC target
// REFUSED, the socket STAND_IN with the listener's UID, render and
// agent-inputs PASS, peer-precondition PASS from the host's real `perl -v`,
// the literal no-op apply line and positive-request COVERED_BY_HOSTED with
// host=not-sent. As a stand-in run the fixture denied reads are STAND_IN.
// Limits: id is the fixture readback adapter of
// TestPX1T18CustodyScript (no setpriv runs here); the spec uses fixture paths
// (no status directory), so custody-verify, which requires the launch layout,
// and status-dir are FAIL; the account check runs against this host's account
// database, where the agent account does not exist, so the preflight refuses
// it (FAIL); launch-form reads this test process, not a setpriv launch.
func TestT18RealHostAgentPhase(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses file modes; the probe refuses root anyway")
	}
	if _, e := exec.LookPath("perl"); e != nil {
		t.Skip("T18RH_AGENT perl is not installed: the agent phase did not run")
	}
	uid := uint32(os.Getuid())
	p := g2Params()
	p.AgentUID, p.ServiceUID = uid, uid+1
	if G2ReservedID(uid) || G2ReservedID(uid+1) || uid == p.AgentSocketGID || uid == p.OperatorGID {
		t.Skip("the test UID cannot stand in for the agent UID")
	}
	files, e := RenderG2PayTemplates(p)
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.MkdirTemp("", "t18rh")
	if e != nil {
		t.Fatal(e)
	}
	key, state := filepath.Join(root, "receipt.key"), filepath.Join(root, "state")
	os.WriteFile(key, []byte("not-a-key"), 0600)
	os.Mkdir(state, 0700)
	os.Chmod(key, 0)
	os.Chmod(state, 0)
	t.Cleanup(func() { os.Chmod(state, 0700); os.Chmod(key, 0600); os.RemoveAll(root) })
	sock := filepath.Join(root, "w.sock")
	got := t18rhListener(t, sock)
	spec := CustodySpecV1{Version: 1, AgentUID: uid, ServiceUID: uid + 1, DeniedReads: []string{key, state}, DeniedRPC: []string{g2ClosedPort(t)}, AllowedSocket: sock}
	specRaw, _ := json.Marshal(spec)
	rendered := filepath.Join(root, "rendered")
	os.Mkdir(rendered, 0700)
	for name, b := range files {
		os.WriteFile(filepath.Join(rendered, name), b, 0600)
	}
	in := filepath.Join(root, "in")
	os.Mkdir(in, 0700)
	specPath, clientPath, paramsPath := filepath.Join(in, "custody-spec.json"), filepath.Join(in, "client.json"), filepath.Join(in, "parameters.json")
	os.WriteFile(specPath, append(specRaw, '\n'), 0600)
	os.WriteFile(clientPath, files[G2FileClientConfig], 0600)
	rawParams, _ := json.Marshal(p)
	os.WriteFile(paramsPath, append(rawParams, '\n'), 0600)
	txindex := filepath.Join(in, "getindexinfo.json")
	os.WriteFile(txindex, []byte("{\n  \"txindex\": {\n    \"synced\": true,\n    \"best_block_height\": 7\n  }\n}\n"), 0600)

	kit := g2BuildDeployKit(t)
	_, _, bin := g2ScriptFakes(t, kit)
	u := strconv.FormatUint(uint64(uid), 10)
	env := []string{"DEPLOY_KIT=" + kit, "PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_ID_G=" + u + " 1301"}
	op, ag := filepath.Join(root, "op"), filepath.Join(root, "ag")
	if code, out := t18rhRun(t, env, "operator", op, paramsPath, rendered, txindex); code != 0 || !strings.HasPrefix(out, "T18_REAL_HOST_OPERATOR_DONE ") {
		t.Fatalf("T18RH_AGENT operator phase %d\n%s", code, out)
	}
	// The operator phase reads the exact set from the account (here the
	// fixture id: -u 1201, -g and -G from FAKE_ID_G) and the real deploy-kit
	// g2-agent-groups accepts {UID, 1301}; beside it, the same account with a
	// third group 1401 is refused, so that check really runs in the no-op
	// apply mode.
	wantReal := map[string]string{
		"account-real.txt":   "uid=1201 gid=" + u + " groups=" + u + ",1301\n",
		"account-groups.txt": "G2_AGENT_GROUPS_OK observed_gid=" + u + " declared_primary_gid=" + u + " socket_gid=1301\n",
		"host-flow-mode.txt": "apply=noop activation=noop sysusers=true\n",
	}
	for name, want := range wantReal {
		if b, _ := os.ReadFile(filepath.Join(op, name)); string(b) != want {
			t.Fatalf("T18RH_AGENT operator %s %q want %q", name, b, want)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(op, "exits.txt")); !strings.Contains(string(b), "\naccount_groups_exit=0\n") {
		t.Fatalf("T18RH_AGENT operator exits %q", b)
	}
	op3 := filepath.Join(root, "op-third-group")
	env3 := append(append([]string{}, env[:2]...), "FAKE_ID_G="+u+" 1301 1401")
	if code, out := t18rhRun(t, env3, "operator", op3, paramsPath, rendered, txindex); code != 0 {
		t.Fatalf("T18RH_AGENT operator phase (third group) %d\n%s", code, out)
	}
	if b, _ := os.ReadFile(filepath.Join(op3, "account-groups.txt")); strings.Contains(string(b), "G2_AGENT_GROUPS_OK") {
		t.Fatalf("T18RH_AGENT a third group on the account was accepted: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(op3, "exits.txt")); !strings.Contains(string(b), "\naccount_groups_exit=1\n") {
		t.Fatalf("T18RH_AGENT third group exits %q", b)
	}
	if code, out := t18rhRun(t, env, "agent", ag, specPath, clientPath, g2KeyG, paramsPath); code != 0 || !strings.HasPrefix(out, "T18_REAL_HOST_AGENT_DONE ") {
		t.Fatalf("T18RH_AGENT agent phase %d\n%s", code, out)
	}
	if b, _ := os.ReadFile(filepath.Join(ag, "custody-check.out")); string(b) != "T18_FAIL\n" {
		t.Fatalf("T18RH_AGENT custody script output %q", b)
	}
	// The fixture id answers -u with 1201; the probe itself ran as the test UID.
	if b, _ := os.ReadFile(filepath.Join(ag, "custody", "exits.txt")); string(b) != "uid=1201 probe_exit=0 positive_exit=3 verify_exit=1\n" {
		t.Fatalf("T18RH_AGENT custody exits %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(ag, "custody", "positive-receipt.json")); string(b) != t18rhMarker+"\n" {
		t.Fatalf("T18RH_AGENT receipt %q", b)
	}
	// Two connections reach the socket (the probe and the peer check); neither
	// sends a byte.
	for i := 0; i < 2; i++ {
		select {
		case n := <-got:
			if n != 0 {
				t.Fatalf("T18RH_AGENT a connection sent %d bytes", n)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("T18RH_AGENT connection %d never reached the socket", i+1)
		}
	}
	select {
	case n := <-got:
		t.Fatalf("T18RH_AGENT a third connection reached the socket (%d bytes)", n)
	case <-time.After(200 * time.Millisecond):
	}

	groups := u + ",1301"
	if uid > 1301 {
		groups = "1301," + u
	}
	// The report reads the spec the agent ran with.
	os.WriteFile(filepath.Join(rendered, G2FileCustodySpec), append(specRaw, '\n'), 0600)
	code, out := t18rhRun(t, nil, "report", op, ag, rendered, paramsPath, "stand-in")
	for _, line := range []string{
		"node-txindex PASS getindexinfo={\"txindex\":{\"synced\":true,\"best_block_height\":7}}",
		"credentials PASS observed_gid=" + u + " groups=" + groups + " check=G2_AGENT_GROUPS_OK",
		"render PASS files=6 custody_spec_file_sha256=" + t18rhSha(append(specRaw, '\n')),
		"agent-inputs PASS spec,client,params=rendered",
		"denied-read:" + key + " STAND_IN observed=EACCES",
		"denied-read:" + state + " STAND_IN observed=EACCES",
		"denied-rpc:" + spec.DeniedRPC[0] + " PASS observed=REFUSED",
		t18rhApplyNoop,
		t18rhNote,
		"positive-request COVERED_BY_HOSTED pin=TestPX1CoreServiceG2FailClosed commit=" + t18rhCommit + " run=" + t18rhRunAW + " job=px1-core-gate host=not-sent positive_path=mainnet-smoke-gate",
	} {
		if !strings.Contains(out, "\n"+line+"\n") {
			t.Fatalf("T18RH_AGENT report lacks %q\n%s", line, out)
		}
	}
	for _, re := range []string{
		`(?m)^allowed-socket STAND_IN wallet=stand-in probe=CONNECTED peer_uid=` + u + ` `,
		`(?m)^custody-verify FAIL `,
		`(?m)^status-dir FAIL path=/run/swarma-wallet-status not-in-denied_reads$`,
		`(?m)^launch-form (PASS|FAIL) uid=` + u + `,` + u + `,` + u + `,` + u + ` `,
		`(?m)^account FAIL host_flow=g2_host_flow:_preflight:_`,
		`(?m)^peer-precondition PASS perl_v=This_is_perl_5,_version_\d+,_subversion_\d+_`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Fatalf("T18RH_AGENT report lacks %s\n%s", re, out)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(op, "render-cmp.txt")); strings.Count(string(b), "same ") != 6 {
		t.Fatalf("T18RH_AGENT render comparison %q", b)
	}
	if code != 1 || !strings.Contains(out, "\nOVERALL FAIL ") {
		t.Fatalf("T18RH_AGENT a fixture-path run must not pass: %d", code)
	}
}
