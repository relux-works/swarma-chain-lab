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
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	// The agent phase's exit lines on a station whose every item passes (r7:
	// verify -launch=true and -launch=false both accepted the report).
	t18rhAgentExitsOK = "custody_check_exit=1\nlaunch_true_exit=0\nlaunch_false_exit=0\npeer_exit=0\n"
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

// r10 evidence of the standard set: the pre-probe node capture, the probe
// window and the post-probe node capture, in this order in time, and the
// post-probe answer (synced, one block later than node-txindex's).
const (
	t18rhPreStart   = "2026-11-13T10:00:00.000000000Z"
	t18rhPreEnd     = "2026-11-13T10:00:00.250000000Z"
	t18rhProbeStart = "2026-11-13T10:05:00.000000000Z"
	t18rhProbeEnd   = "2026-11-13T10:05:03.000000000Z"
	t18rhPostStart  = "2026-11-13T10:06:00.000000000Z"
	t18rhPostEnd    = "2026-11-13T10:06:00.250000000Z"
	t18rhPreAnswer  = `{"txindex":{"synced":true,"best_block_height":812345}}`
	t18rhPostAnswer = `{"txindex":{"synced":true,"best_block_height":812346}}`
)

// t18rhCapture is a node-capture file: target, times, exit and answer.
func t18rhCapture(rpc, start, end, exit, answer string) string {
	return "T18-NODE-CAPTURE v1\nrpc=" + rpc + "\nstart=" + start + "\nend=" + end + "\nexit=" + exit + "\nanswer=" + answer + "\n"
}

// t18rhStat is the standard root-side stat of a denied path (synthetic).
func t18rhStat(p string) string {
	if p == G2StatusSocketDir || strings.HasPrefix(p, "/var/lib/swarma-wallet/") {
		return "exists=yes type=directory owner=1101:1101 mode=700"
	}
	return "exists=yes type=regular_file owner=0:0 mode=600"
}

// t18rhLiveFields is the r10 evidence of a live denied-rpc PASS row for target.
func t18rhLiveFields(target string) string {
	return "pre_rpc=" + target + " pre_start=" + t18rhPreStart + " pre_end=" + t18rhPreEnd + " probe_start=" + t18rhProbeStart + " probe_end=" + t18rhProbeEnd +
		" post_rpc=" + target + " post_start=" + t18rhPostStart + " post_end=" + t18rhPostEnd + " post_getindexinfo=" + t18rhPostAnswer
}

var (
	t18rhLiveRead = regexp.MustCompile(`(?m)^denied-read:(\S+) PASS observed=(EACCES|EPERM)$`)
	t18rhLiveRPC  = regexp.MustCompile(`(?m)^denied-rpc:(\S+) PASS observed=(HTTP_401|HTTP_403)$`)
)

// t18rhLive turns a stored live (wallet=real) report of r3 to r9, which
// predates the r10 evidence, into the report the composer now prints for the
// same standard evidence set: each denied-read PASS row gains its root-side
// stat, each denied-rpc PASS row its two node captures and the probe window.
// Nothing else changes (no count, no hash). A stand-in report is returned
// unchanged. The stored bytes are not changed; TestT18RealHostStoredLiveRefused
// shows that check refuses the stored live reports as they are.
func t18rhLive(text string) string {
	if !strings.HasPrefix(text, "T18-REAL-HOST v1 wallet=real ") {
		return text
	}
	text = t18rhLiveRead.ReplaceAllStringFunc(text, func(l string) string {
		return l + " " + t18rhStat(t18rhLiveRead.FindStringSubmatch(l)[1])
	})
	return t18rhLiveRPC.ReplaceAllStringFunc(text, func(l string) string {
		return l + " " + t18rhLiveFields(t18rhLiveRPC.FindStringSubmatch(l)[1])
	})
}

// t18rhLiveFile writes t18rhLive of the stored r4 report name to a temporary
// file and returns its path.
func t18rhLiveFile(t *testing.T, name string) string {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata/t18-real-host-r4", name))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), name)
	if e := os.WriteFile(path, []byte(t18rhLive(string(b))), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}

// t18rhKitDir holds the real deploy-kit, built once from this tree for the
// report and check modes (r6: their canonical spec hash comes only from
// `deploy-kit g2-custody-hash`); TestMain removes it.
var (
	t18rhKitOnce sync.Once
	t18rhKitDir  string
	t18rhKitErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if t18rhKitDir != "" {
		os.RemoveAll(t18rhKitDir)
	}
	os.Exit(code)
}

// t18rhKit returns the path of the real deploy-kit built from this tree.
func t18rhKit(t *testing.T) string {
	t.Helper()
	t18rhKitOnce.Do(func() {
		if t18rhKitDir, t18rhKitErr = os.MkdirTemp("", "t18rh-kit"); t18rhKitErr != nil {
			return
		}
		out, e := exec.Command("go", "build", "-mod=readonly", "-buildvcs=false", "-o", filepath.Join(t18rhKitDir, "deploy-kit"), "./cmd/deploy-kit").CombinedOutput()
		if e != nil {
			t18rhKitErr = errors.New(e.Error() + "\n" + string(out))
		}
	})
	if t18rhKitErr != nil {
		t.Fatal("T18RH_SETUP build deploy-kit", t18rhKitErr)
	}
	return filepath.Join(t18rhKitDir, "deploy-kit")
}

// t18rhRun runs the script with /bin/sh in this directory and returns its
// exit status and combined output. The report and check modes get the real
// deploy-kit as DEPLOY_KIT unless env names another.
func t18rhRun(t *testing.T, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{t18rhScript}, args...)...)
	cmd.Env = os.Environ()
	if len(args) > 0 && (args[0] == "report" || args[0] == "check") {
		cmd.Env = append(cmd.Env, "DEPLOY_KIT="+t18rhKit(t))
	}
	cmd.Env = append(cmd.Env, env...)
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

func t18rhID(id uint32) string { return strconv.FormatUint(uint64(id), 10) }

func t18rhLaunch(uid, gid uint32, groups string) string {
	u, g := strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10)
	return "Uid:\t" + u + "\t" + u + "\t" + u + "\t" + u + "\nGid:\t" + g + "\t" + g + "\t" + g + "\t" + g + "\nGroups:\t" + groups + " \nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n"
}

func t18rhFixture(t *testing.T) *t18rhFix {
	t.Helper()
	return t18rhFixtureFor(t, g2Params())
}

// t18rhFixtureFor is t18rhFixture for parameters p: every identity in the
// evidence (account, launch, credentials, custody exits, peer and socket
// owner) is p's, so another valid p gives another consistent all-pass run.
func t18rhFixtureFor(t *testing.T, p G2PayParameters) *t18rhFix {
	t.Helper()
	f := &t18rhFix{p: p}
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
	u, g, sg, su := t18rhID(f.p.AgentUID), t18rhID(f.primary), t18rhID(f.socket), t18rhID(f.p.ServiceUID)
	f.write(t, "op/account-real.txt", "uid="+u+" gid="+g+" groups="+g+","+sg+"\n")
	f.write(t, "op/account-groups.txt", "G2_AGENT_GROUPS_OK observed_gid="+g+" declared_primary_gid="+g+" socket_gid="+sg+"\n")
	f.write(t, "op/txindex.json", `{"txindex":{"synced":true,"best_block_height":812345}}`)
	f.write(t, "inputs.sha256", t18rhSha(files[G2FileCustodySpec])+"\n"+t18rhSha(files[G2FileClientConfig])+"\n"+t18rhSha(append(raw, '\n'))+"\n")
	f.write(t, "launch.txt", t18rhLaunch(f.p.AgentUID, f.primary, strconv.FormatUint(uint64(f.primary), 10)+" "+strconv.FormatUint(uint64(f.socket), 10)))
	f.write(t, "custody/credentials.txt", "uid="+u+" gid="+g+" groups="+g+" "+sg+"\n")
	f.write(t, "custody/credentials-check.txt", "G2_AGENT_GROUPS_OK observed_gid="+g+" declared_primary_gid="+g+" socket_gid="+sg+"\n")
	f.probes(t, nil)
	f.write(t, "custody/exits.txt", "uid="+u+" probe_exit=0 positive_exit=3 verify_exit=0\n")
	f.write(t, "custody/custody-verify.txt", "T18_CUSTODY_VERIFIED "+f.specSHA+"\n")
	f.write(t, "agent-exits.txt", t18rhAgentExitsOK)
	f.write(t, "launch-layout-on.txt", "T18_CUSTODY_VERIFIED "+f.specSHA+"\n")
	f.write(t, "launch-layout-off.txt", "T18_CUSTODY_VERIFIED "+f.specSHA+"\n")
	f.write(t, "custody/positive-request.json", `{"v":1}`)
	f.write(t, "custody/positive-receipt.json", t18rhMarker+"\n")
	f.write(t, "peer.txt", "PEER connect=ok uid="+su+" gid="+su+"\n")
	f.write(t, "socket-stat.txt", "socket|"+su+"|"+sg+"|660\n")
	f.write(t, "perl-version.txt", t18rhPerl+"\n")
	// r10: the node captures around the probe window, against the spec's
	// denied_rpc target, and the root-side stat of every denied path.
	f.write(t, "op/node-pre.txt", t18rhCapture(f.spec.DeniedRPC[0], t18rhPreStart, t18rhPreEnd, "0", t18rhPreAnswer))
	f.write(t, "probe-window.txt", "probe_start="+t18rhProbeStart+"\nprobe_end="+t18rhProbeEnd+"\n")
	f.write(t, "op/node-post.txt", t18rhCapture(f.spec.DeniedRPC[0], t18rhPostStart, t18rhPostEnd, "0", t18rhPostAnswer))
	f.writeStats(t, nil)
	return f
}

// writeStats writes the root-side stat record, one line per denied path in
// spec order; over replaces a path's stat ("" drops its line).
func (f *t18rhFix) writeStats(t *testing.T, over map[string]string) {
	t.Helper()
	var b strings.Builder
	for _, p := range f.spec.DeniedReads {
		s, ok := over[p]
		if !ok {
			s = t18rhStat(p)
		}
		if s != "" {
			b.WriteString(p + " " + s + "\n")
		}
	}
	f.write(t, "op/denied-paths-stat.txt", b.String())
}

func (f *t18rhFix) report(t *testing.T, wallet string) (int, string) {
	t.Helper()
	return t18rhRun(t, nil, "report", f.op, f.ag, f.rendered, f.params, wallet)
}

// t18rhIDs returns the item ids of a report (no header, custody_spec_sha256
// line, OVERALL, comment or the literal no-op apply line).
func t18rhIDs(out string) []string {
	var ids []string
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i == 0 || strings.HasPrefix(line, "custody_spec_sha256 ") || strings.HasPrefix(line, "OVERALL ") || strings.HasPrefix(line, "#") || line == t18rhApplyNoop {
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
// right before positive-request. The line "custody_spec_sha256 <hex>" stands
// once, right after the header, with the SHA-256 of the exact rendered
// custody-spec.json file the report was composed from (r4). Every pin names a test function present in
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
	want = append(want, "peer-precondition", "allowed-socket", "custody-verify", "launch-layout", "positive-request")
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
	specFile, e := os.ReadFile(f.renderedSpec)
	if e != nil {
		t.Fatal(e)
	}
	if hash := "custody_spec_sha256 " + t18rhSha(specFile) + "\n"; !strings.HasPrefix(out, header+hash) || strings.Count(out, "custody_spec_sha256") != 1 {
		t.Fatal("T18RH_CONTRACT the custody_spec_sha256 line is not printed once, right after the header\n", out)
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
		"proven by the separate owner-authorized, bounded mainnet smoke gate, not by T18", "valid-only-as-a-stand-in-run", "perl -v",
		`check "$RUN/T18-REPORT.txt" "$RUN/custody-spec.json"`, "custody_spec_sha256",
		`sha256sum "$RUN.tar.gz" "$RUN/custody-spec.json"`, "header-spec-sha256:differs", "render-custody-spec-file-sha256:differs") {
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
		// r9 claim: on a live run a stopped node (REFUSED: nothing listens at
		// the RPC port) is FAIL reason=node-not-listening, never PASS.
		{"rpc-node-stopped", "real", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{rpc0: "REFUSED"}) }, 1, `^denied-rpc:` + regexp.QuoteMeta(rpc0) + ` FAIL observed=REFUSED reason=node-not-listening$`},
		// r9 claim (valid neighbour): a 403 from a live node (node-txindex PASS) is PASS.
		{"rpc-403-live-node", "real", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{rpc0: "HTTP_403"}) }, 0, `^denied-rpc:` + regexp.QuoteMeta(rpc0) + ` PASS observed=HTTP_403 ` + regexp.QuoteMeta(t18rhLiveFields(rpc0)) + `$`},
		// r9 claim: a 401 without node liveness in the run (no getindexinfo
		// answer, node-txindex FAIL) is FAIL reason=node-liveness-unproven.
		{"rpc-401-node-not-live", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "op/txindex.json", "") }, 1, `^denied-rpc:` + regexp.QuoteMeta(rpc0) + ` FAIL observed=HTTP_401 reason=node-liveness-unproven$`},
		// r9 claim: on a stand-in run REFUSED is STAND_IN, never PASS, and the
		// run can still pass as a stand-in run.
		{"stand-in-rpc-refused", "stand-in", func(t *testing.T, f *t18rhFix) { f.probes(t, map[string]string{rpc0: "REFUSED"}) }, 0, `^denied-rpc:` + regexp.QuoteMeta(rpc0) + ` STAND_IN observed=REFUSED$`},
		// r9 claim (valid neighbour): on a stand-in run a 401 with node
		// liveness is PASS: nothing is planted at the RPC port, so it is not a
		// placeholder-backed item.
		{"stand-in-rpc-401-live-node", "stand-in", func(*testing.T, *t18rhFix) {}, 0, `^denied-rpc:` + regexp.QuoteMeta(rpc0) + ` PASS observed=HTTP_401$`},
		// r9 claim: a timeout aborts the product probe (no report), so the
		// row has no observation and is FAIL, never PASS.
		{"rpc-probe-aborted", "real", func(t *testing.T, f *t18rhFix) { f.write(t, "custody/custody-report.json", "") }, 1, `^denied-rpc:` + regexp.QuoteMeta(rpc0) + ` FAIL observed=none$`},
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
		}, 1, `^launch-form FAIL .* caps=CapPrm=0000000000000000,CapEff=0000000000000400,CapAmb=0000000000000000 each_line_once=1 `},
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
	// r9: a stand-in run whose RPC port refused the connection.
	f.probes(t, map[string]string{f.spec.DeniedRPC[0]: "REFUSED"})
	code, standInRefused := f.report(t, "stand-in")
	if code != 0 || !strings.Contains(standInRefused, "\ndenied-rpc:"+f.spec.DeniedRPC[0]+" STAND_IN observed=REFUSED\n") {
		t.Fatal("T18RH_CHECK setup stand-in REFUSED", standInRefused)
	}
	dir := t.TempDir()
	check := func(name, text string) (int, string) {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte(text), 0600)
		return t18rhRun(t, nil, "check", path, f.renderedSpec)
	}
	// r9 claim (valid neighbour): REFUSED as STAND_IN on a stand-in run passes check.
	for name, text := range map[string]string{"valid-real": real, "valid-stand-in": standIn, "valid-stand-in-rpc-refused": standInRefused} {
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
		{"enoent-as-denied", sub(real, `^(`+regexp.QuoteMeta(read0)+`) PASS observed=EACCES( .*)$`, "$1 PASS observed=ENOENT$2"), "read-pass-without-eacces:" + read0},
		{"status-enoent", sub(real, `^status-dir PASS path=(\S+) observed=EACCES$`, "status-dir PASS path=$1 observed=ENOENT"), "status-pass-without-eacces"},
		{"rpc-answered", sub(real, `^(denied-rpc:\S+) PASS observed=HTTP_401( .*)$`, "$1 PASS observed=HTTP_OK$2"), "rpc-pass-without-refusal:"},
		// r9 claims: a hand-edited PASS observed=REFUSED is refused by name, on
		// a real and on a stand-in report; STAND_IN for REFUSED is refused on
		// a real run, and STAND_IN for a 401 on a stand-in run; a denied-rpc
		// PASS while node-txindex is not PASS is refused.
		{"rpc-refused-as-pass", sub(real, `^(denied-rpc:\S+) PASS observed=HTTP_401( .*)$`, "$1 PASS observed=REFUSED$2"), "rpc-pass-node-not-listening:denied-rpc:"},
		{"rpc-refused-as-pass-stand-in", sub(standInRefused, `^(denied-rpc:\S+) STAND_IN observed=REFUSED$`, "$1 PASS observed=REFUSED"), "rpc-pass-node-not-listening:denied-rpc:"},
		{"rpc-stand-in-on-real", sub(real, `^(denied-rpc:\S+) PASS observed=HTTP_401 .*$`, "$1 STAND_IN observed=REFUSED"), "stand-in-misplaced:denied-rpc:"},
		{"rpc-stand-in-401", sub(standIn, `^(denied-rpc:\S+) PASS observed=HTTP_401$`, "$1 STAND_IN observed=HTTP_401"), "rpc-stand-in-without-refused:denied-rpc:"},
		{"rpc-pass-node-not-live", sub(real, `^node-txindex PASS .*$`, "node-txindex FAIL getindexinfo=missing"), "rpc-pass-without-live-node"},
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

// Claim: the dry run needs no root and no station: self-test builds the real
// deploy-kit from this checkout (a caller's DEPLOY_KIT, here a missing path,
// is not used), composes its synthetic evidence through the real report path
// and prints
// SELF_TEST PASS with exit 0 only when the valid samples pass (the real run
// with its no-op apply line, the stand-in run with its placeholders STAND_IN
// and its OVERALL line valid only as a stand-in run) and its known-bad samples
// (a placeholder reported PASS on a stand-in run, a refused real-account
// group set, ENOENT, a stand-in declared real, a sent request, STAND_IN on a
// real wallet) fail with their named lines. The r4 samples: the valid real
// report passes check with its spec, check without a spec is a usage error
// (64), and a deleted required row with the OVERALL count edited to match,
// another spec, a missing or duplicated custody_spec_sha256 line and an extra
// denied row each fail check with their named reason. The r5 samples: the
// custody_spec_sha256 line, the header's spec_sha256 and the render line's
// custody_spec_file_sha256, each changed alone, fail check with their named
// reason. The r6 samples: with no deploy-kit, or one that prints nothing,
// garbage or exits non-zero, check refuses canonical-hash-unavailable; one
// that prints another well-formed hash gives header-spec-sha256:differs; and
// the valid report with its spec behind a leading space (file hashes moved
// along) passes with the real product. The r7 sample: verify -launch=true
// refused the run's launch layout while -launch=false accepted the same
// report, so launch-layout is FAIL layout=refused and OVERALL is not PASS.
// The r9 samples: a refused RPC connection is FAIL node-not-listening on a
// real run and STAND_IN on a stand-in run, check refuses that STAND_IN
// relabeled PASS by name, and a 401 without a getindexinfo answer is FAIL
// node-liveness-unproven.
func TestT18RealHostSelfTest(t *testing.T) {
	code, out := t18rhRun(t, []string{"DEPLOY_KIT=/nonexistent/deploy-kit"}, "self-test")
	if code != 0 || !strings.HasSuffix(out, "SELF_TEST PASS\n") || strings.Count(out, " ok exit=") != 38 ||
		!strings.HasPrefix(out, "self-test build-deploy-kit ok exit=0\n") || !strings.Contains(out, "\nself-test whitespace-spec-agrees ok exit=0\n") {
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
	for _, args := range [][]string{{}, {"nonsense"}, {"report"}, {"check"}, {"check", t18rhScript}, {"agent", "x"}, {"operator", "x"}, {"--config", "c", "--request"}} {
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
// (a closed port) REFUSED and STAND_IN (r9: never PASS), the socket STAND_IN with the listener's UID, render and
// agent-inputs PASS, peer-precondition PASS from the host's real `perl -v`,
// the literal no-op apply line and positive-request COVERED_BY_HOSTED with
// host=not-sent. As a stand-in run the fixture denied reads are STAND_IN.
// Limits: id is the fixture readback adapter of
// TestPX1T18CustodyScript (no setpriv runs here); the spec uses fixture paths
// (no status directory), so custody-verify, which requires the launch layout,
// and status-dir are FAIL; launch-layout is FAIL layout=refused from the real
// verify (-launch=true refused, -launch=false accepted the same report); the account check runs against this host's account
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
	// r10: the probe window brackets the custody script: two times in the
	// nanosecond UTC form, start at or before end.
	if b, _ := os.ReadFile(filepath.Join(ag, "probe-window.txt")); !regexp.MustCompile(`^probe_start=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z)\nprobe_end=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z)\n$`).Match(b) || string(b[12:42]) > string(b[53:83]) {
		t.Fatalf("T18RH_AGENT probe window %q", b)
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
		// r9: the real probe of a closed port is REFUSED, STAND_IN on this
		// stand-in run, never PASS.
		"denied-rpc:" + spec.DeniedRPC[0] + " STAND_IN observed=REFUSED",
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
		// r7: the real verify -launch=true refused the fixture spec's layout,
		// and -launch=false accepted the same report.
		`(?m)^launch-layout FAIL launch=true verify_exit=1 verify=deploy:,invalid,policy launch_false_exit=0 layout=refused$`,
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

// t18rhR3 holds the stored reports and evidence bytes of the r3 review: the
// reviewer's witnesses, kept byte for byte, beside the valid reports they
// were planted in.
const t18rhR3 = "testdata/t18-real-host-r3"

// t18rhCheckFile runs check on a stored report given as text, against the
// custody spec file at spec.
func t18rhCheckFile(t *testing.T, name, text, spec string) (int, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if e := os.WriteFile(path, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	return t18rhRun(t, nil, "check", path, spec)
}

// t18rhWithHash inserts the r4 line "custody_spec_sha256 <sha>" right after
// the header of an r3 report, which predates that line.
func t18rhWithHash(text, sha string) string {
	i := strings.Index(text, "\n") + 1
	return text[:i] + "custody_spec_sha256 " + sha + "\n" + text[i:]
}

func t18rhRead(t *testing.T, name string) string {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(t18rhR3, name))
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

// Claim (r3): check parses a stored report once, strictly, and refuses (exit
// 1, OVERALL FAIL and the named reason) every duplicate field, every field
// that contradicts its verdict, the header or another item, and every
// trailing, unterminated or unparsable line, while the valid real and
// stand-in reports (the reviewer's baseline, which is exactly what the
// composer emits for the standard evidence set) still pass with exit 0.
// The reviewer's witnesses are refused by the planted field itself: the
// three token-preserving duplicates (host=sent after host=not-sent on
// positive-request, R2; a second real_account with a third group, R3; a
// second run= naming the Deploy kit run in which TestPX1T18CoreNodePolicy
// skipped, R6) keep the valid OVERALL line, and each relabelled PASS
// (unsynced txindex, saved UID 0, verify_exit=1, socket mode 0666) is checked
// under the OVERALL line the valid report states, so its refusal cannot come
// from a count. A duplicate is refused even when both copies agree. The r3
// reports predate the r4 custody_spec_sha256 line: each is checked with that
// line inserted after its header (the stored bytes are unchanged), against
// the fixture's rendered spec, so the planted r3 defect stays the only one.
// The row binding to the spec is TestT18RealHostSpecBoundCheck's.
func TestT18RealHostStrictCheck(t *testing.T) {
	f := t18rhFixture(t)
	specFile, e := os.ReadFile(f.renderedSpec)
	if e != nil {
		t.Fatal(e)
	}
	specHash := t18rhSha(specFile)
	r3 := func(name string) string { return t18rhLive(t18rhWithHash(t18rhRead(t, name), specHash)) }
	real, standIn := r3("valid-real.txt"), r3("valid-stand-in.txt")
	if code, out := f.report(t, "real"); code != 0 || out != real {
		t.Fatalf("T18RH_STRICT the stored valid report is not the composer's output (%d)\n%s", code, out)
	}
	for name, text := range map[string]string{"valid-real": real, "valid-stand-in": standIn} {
		code, out := t18rhCheckFile(t, name, text, f.renderedSpec)
		last := text[strings.LastIndex(strings.TrimSuffix(text, "\n"), "\n")+1:]
		if code != 0 || out != last {
			t.Fatalf("T18RH_STRICT %s refused or recomputed differently: %d\n%s", name, code, out)
		}
	}
	validOverall := "OVERALL PASS pass=21 stand_in=0 covered=11 fail=0 invalid=0 missing=0 run=real"
	overallRe := regexp.MustCompile(`(?m)^OVERALL .*$`)
	sub := func(text, re, repl string) string {
		out := regexp.MustCompile(`(?m)`+re).ReplaceAllString(text, repl)
		if out == text {
			t.Fatalf("T18RH_STRICT edit %q matched nothing", re)
		}
		return out
	}
	cases := []struct{ name, text, reason string }{
		// The reviewer's witnesses, byte for byte (R2, R3, R6).
		{"r2-duplicate-sent-wallet", r3("duplicate-sent-wallet.txt"), "duplicate-field:positive-request:host"},
		{"r2-conflicting-host-fields", r3("wallet-conflicting-host-fields.txt"), "duplicate-field:positive-request:host"},
		{"r3-duplicate-third-account-group", r3("duplicate-third-account-group.txt"), "duplicate-field:account:real_account"},
		{"r3-contradictory-duplicate-groups", r3("account-contradictory-duplicate-groups.txt"), "duplicate-field:account:real_account"},
		{"r6-duplicate-skipped-node-run", r3("duplicate-skipped-node-run.txt"), "duplicate-field:cov-core-node-policy:run"},
		{"r6-conflicting-skipped-pin", r3("hosted-node-conflicting-skipped-pin.txt"), "duplicate-field:cov-core-node-policy:run"},
		// The relabelled PASS witnesses under the valid OVERALL line.
		{"relabel-unsynced-txindex", overallRe.ReplaceAllString(r3("unsynced-node-relabeled.txt"), validOverall), "txindex-pass-without-synced-index"},
		{"relabel-saved-root", overallRe.ReplaceAllString(r3("saved-root-relabeled.txt"), validOverall), "launch-pass-other-uid"},
		{"relabel-failed-verifier", overallRe.ReplaceAllString(r3("failed-custody-verifier-relabeled.txt"), validOverall), "custody-verify-pass-contradicts-exits"},
		{"relabel-world-writable-socket", overallRe.ReplaceAllString(r3("world-writable-socket-relabeled.txt"), validOverall), "wallet-pass-socket-metadata"},
		// Duplicates, agreeing or not, on items, pins and the header.
		{"agreeing-duplicate-run", sub(real, `^(cov-core-node-policy .* job=px1-core-gate)$`, "$1 run="+t18rhRunNode), "duplicate-field:cov-core-node-policy:run"},
		{"agreeing-duplicate-host", sub(real, `^(positive-request .*)$`, "$1 host=not-sent"), "duplicate-field:positive-request:host"},
		{"duplicate-on-fail-line", sub(real, `^account PASS .*$`, "account FAIL host_flow=x host_flow=y"), "duplicate-field:account:host_flow"},
		{"duplicate-header-field", sub(real, `^(T18-REAL-HOST v1 .*)$`, "$1 agent_uid=0"), "duplicate-field:header:agent_uid"},
		{"duplicate-overall", sub(real, `^(OVERALL .*)$`, "$1\n$1"), "trailing-after-overall"},
		// Fields that contradict the verdict, the header or another item.
		{"extra-field", sub(real, `^(launch-form PASS .*)$`, "$1 note=extra"), "fields:launch-form"},
		{"fields-reordered", sub(real, `^render PASS (files=6) (\S+)$`, "render PASS $2 $1"), "fields:render"},
		{"not-run-beside-credentials-pass", sub(real, ` host=not-sent `, " host=not-run "), "positive-not-run-contradicts-credentials"},
		{"not-sent-beside-sent-exit", sub(real, `positive_exit=3,verify_exit=0 `, "positive_exit=0,verify_exit=0 "), "positive-not-sent-contradicts-exits"},
		{"status-dir-other-observation", sub(real, `^status-dir PASS (path=\S+) observed=EACCES$`, "status-dir PASS $1 observed=EPERM"), "status-dir-contradicts-denied-read"},
		{"credentials-other-groups", sub(real, `^credentials PASS observed_gid=1201 groups=1201,1301 `, "credentials PASS observed_gid=1201 groups=1201,1301,1401 "), "credentials-pass-contradicts-evidence"},
		{"verify-other-agent", sub(real, `uid=1201,probe_exit=0`, "uid=0,probe_exit=0"), "custody-verify-pass-contradicts-exits"},
		{"unknown-item", sub(real, `^(render PASS .*)$`, "$1\nshadow PASS ok=1"), "unknown-item:shadow"},
		{"header-other-commit", sub(real, `^T18-REAL-HOST v1 wallet=real commit=\S+ `, "T18-REAL-HOST v1 wallet=real commit="+t18rhNodeCommit+" "), "header"},
		{"stated-other-counts", sub(real, `^OVERALL PASS pass=21 `, "OVERALL PASS pass=22 "), "# stated OVERALL PASS disagrees"},
		// Trailing, unterminated or unparsable lines and blocks.
		{"unterminated-last-line", strings.TrimSuffix(real, "\n"), "unterminated-last-line"},
		{"trailing-line", real + "positive-request FAIL host=sent\n", "trailing-after-overall"},
		{"trailing-unterminated", real + `{"receipt":{"verdict":"executed"}}`, "unterminated-last-line"},
		{"missing-overall", strings.TrimSuffix(real, validOverall+"\n"), "missing:OVERALL"},
		{"blank-line", sub(real, `^(render PASS .*)$`, "$1\n"), "malformed-line:"},
		{"other-comment", sub(real, `^(render PASS .*)$`, "$1\n# host=sent"), "malformed-line:"},
		{"double-space", sub(real, `^render PASS `, "render PASS  "), "malformed-line:"},
		{"trailing-space", sub(real, `^(render PASS .*)$`, "$1 "), "malformed-line:"},
		{"carriage-return", sub(real, `^(render PASS .*)$`, "$1\r"), "malformed-line:"},
	}
	for _, c := range cases {
		code, out := t18rhCheckFile(t, c.name, c.text, f.renderedSpec)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, c.reason) {
			t.Fatalf("T18RH_STRICT %s: exit %d, want 1 with %q\n%s", c.name, code, c.reason, out)
		}
	}
}

// Claim (r3): the composer reads the no-request receipt as the whole file,
// byte for byte, and inspects client error output in both covered branches:
// the reviewer's receipt (the marker, a newline, then an unterminated
// executed receipt) and a refused-credentials run whose client error output
// says a frame was sent both turn positive-request FAIL and OVERALL FAIL with
// exit 1, beside their valid neighbours (the exact marker receipt, and a
// refused-credentials run with no client output, both COVERED_BY_HOSTED). The
// marker without its newline and the marker twice are refused too.
func TestT18RealHostReceiptBytes(t *testing.T) {
	refuse := func(t *testing.T, f *t18rhFix) {
		f.write(t, "custody/exits.txt", "credentials=refused\n")
		for _, n := range []string{"positive-request.json", "positive-receipt.json"} {
			os.Remove(filepath.Join(f.ag, "custody", n))
		}
	}
	cases := []struct {
		name string
		edit func(*testing.T, *t18rhFix)
		line string
	}{
		{"marker-then-executed", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/positive-receipt.json", t18rhRead(t, "receipt-marker-then-executed.json"))
		}, "positive-request FAIL host=request-sent-or-unknown"},
		{"marker-unterminated", func(t *testing.T, f *t18rhFix) { f.write(t, "custody/positive-receipt.json", t18rhMarker) }, "positive-request FAIL host=request-sent-or-unknown"},
		{"marker-twice", func(t *testing.T, f *t18rhFix) {
			f.write(t, "custody/positive-receipt.json", t18rhMarker+"\n"+t18rhMarker+"\n")
		}, "positive-request FAIL host=request-sent-or-unknown"},
		{"refused-credentials-sent-error", func(t *testing.T, f *t18rhFix) {
			refuse(t, f)
			f.write(t, "custody/positive.err", t18rhRead(t, "refused-credentials-sent.err"))
		}, "positive-request FAIL host=request-sent-or-unknown"},
		{"valid-marker", func(*testing.T, *t18rhFix) {}, "positive-request COVERED_BY_HOSTED pin=TestPX1CoreServiceG2FailClosed commit=" + t18rhCommit + " run=" + t18rhRunAW + " job=px1-core-gate host=not-sent positive_path=mainnet-smoke-gate"},
		{"valid-refused-credentials", refuse, "positive-request COVERED_BY_HOSTED pin=TestPX1CoreServiceG2FailClosed commit=" + t18rhCommit + " run=" + t18rhRunAW + " job=px1-core-gate host=not-run positive_path=mainnet-smoke-gate"},
	}
	for _, c := range cases {
		f := t18rhFixture(t)
		c.edit(t, f)
		code, out := f.report(t, "real")
		want := 1 // the refused-credentials neighbour fails on credentials, not on positive-request
		if c.name == "valid-marker" {
			want = 0
		}
		if code != want || !strings.Contains(out, "\n"+c.line+"\n") {
			t.Fatalf("T18RH_RECEIPT %s: exit %d (want %d), want line %q\n%s", c.name, code, want, c.line, out)
		}
	}
}

// Claim (r3): launch-form PASS needs each of Uid, Gid, Groups, CapPrm, CapEff
// and CapAmb exactly once in the launch evidence: removing any one capability
// line (the reviewer's plants) or repeating one is launch-form FAIL with exit
// 1, although every remaining line reads zero; the complete evidence passes.
func TestT18RealHostLaunchLinesOnce(t *testing.T) {
	full := t18rhLaunch(1201, 1201, "1201 1301")
	cases := map[string]string{
		"missing-CapPrm": strings.Replace(full, "CapPrm:\t0000000000000000\n", "", 1),
		"missing-CapEff": strings.Replace(full, "CapEff:\t0000000000000000\n", "", 1),
		"missing-CapAmb": strings.Replace(full, "CapAmb:\t0000000000000000\n", "", 1),
		"twice-CapEff":   full + "CapEff:\t0000000000000000\n",
		"twice-Uid":      full + "Uid:\t1201\t1201\t1201\t1201\n",
		"valid":          full,
	}
	for name, launch := range cases {
		if name != "valid" && launch == full {
			t.Fatalf("T18RH_LAUNCH %s edit matched nothing", name)
		}
		f := t18rhFixture(t)
		f.write(t, "launch.txt", launch)
		code, out := f.report(t, "real")
		ok := code == 1 && regexp.MustCompile(`(?m)^launch-form FAIL .* each_line_once=0 `).MatchString(out)
		if name == "valid" {
			ok = code == 0 && strings.Contains(out, "\nlaunch-form PASS uid=1201,1201,1201,1201 gid=1201,1201,1201,1201 groups=1201,1301 caps=0\n")
		}
		if !ok {
			t.Fatalf("T18RH_LAUNCH %s: exit %d\n%s", name, code, out)
		}
	}
}

// t18rhR4 holds the r4 stored reports: the valid real report, the rendered
// custody spec it was composed from, another spec, and the planted reports.
const t18rhR4 = "testdata/t18-real-host-r4"

// Claim (r4): check is bound to the spec file the run used. It refuses to run
// without that file (usage, exit 64, no OVERALL line). The valid real report,
// which is exactly the composer's output for the standard evidence set, passes
// with its spec (exit 0), and so does the stand-in report composed from the
// same spec. Each stored plant is the valid report with exactly its stated
// edit, and is refused with exit 1 and exactly its named reason (beside the
// stated OVERALL line, which keeps the valid counts and so disagrees): a
// required denied-read row deleted with the OVERALL count edited to match (the
// F3/R8 repro, which r3 accepted), the valid report against another spec (same
// rows, another file: since r5 all three spec hashes differ, each by name),
// the custody_spec_sha256 line missing or
// twice, and a denied row that is not in the spec. Neighbours: an extra or
// missing denied-rpc row, a duplicated denied row, a malformed hash line and a
// spec without denied_rpc are refused; a denied row whose verdict is FAIL is
// still its row (OVERALL FAIL from that item alone, nothing missing). Limit:
// the spec file's own content is not validated here beyond its two lists; its
// identity is the hash the report recorded.
func TestT18RealHostSpecBoundCheck(t *testing.T) {
	spec, other := filepath.Join(t18rhR4, "custody-spec.json"), filepath.Join(t18rhR4, "other-custody-spec.json")
	read := func(name string) string {
		b, e := os.ReadFile(filepath.Join(t18rhR4, name))
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	// The stored spec is the fixture's rendered spec, and the stored valid
	// report is the composer's output for it.
	f := t18rhFixture(t)
	rendered, _ := os.ReadFile(f.renderedSpec)
	if read("custody-spec.json") != string(rendered) {
		t.Fatal("T18RH_SPEC the stored spec is not the rendered launch spec")
	}
	// r10: the stored r4 report predates the r10 evidence; the composer prints
	// it with that evidence (t18rhLive). The stored plants are checked the same way.
	validRaw := read("valid-real.txt")
	valid := t18rhLive(validRaw)
	if code, out := f.report(t, "real"); code != 0 || out != valid {
		t.Fatalf("T18RH_SPEC the stored valid report is not the composer's output (%d)\n%s", code, out)
	}
	f.write(t, "peer.txt", "PEER connect=ok uid=0 gid=0\n")
	_, standIn := f.report(t, "stand-in")
	overall := valid[strings.LastIndex(strings.TrimSuffix(valid, "\n"), "\n")+1:]
	for name, text := range map[string]string{"valid-real": valid, "valid-stand-in": standIn} {
		last := text[strings.LastIndex(strings.TrimSuffix(text, "\n"), "\n")+1:]
		if code, out := t18rhCheckFile(t, name, text, spec); code != 0 || out != last {
			t.Fatalf("T18RH_SPEC %s refused with its spec: %d\n%s", name, code, out)
		}
	}

	// No spec, a missing spec file or an extra argument: check does not run.
	reportPath := filepath.Join(t18rhR4, "valid-real.txt")
	for _, args := range [][]string{{"check", reportPath}, {"check", reportPath, filepath.Join(t18rhR4, "absent.json")}, {"check", reportPath, spec, spec}} {
		if code, out := t18rhRun(t, nil, args...); code != 64 || strings.Contains(out, "OVERALL") {
			t.Fatalf("T18RH_SPEC check %q ran: exit %d\n%s", args[1:], code, out)
		}
	}

	// The other spec has the same rows; only the file differs.
	osp, e1 := ParseCustodySpec([]byte(strings.TrimSuffix(read("other-custody-spec.json"), "\n")))
	vsp, e2 := ParseCustodySpec([]byte(strings.TrimSuffix(read("custody-spec.json"), "\n")))
	if e1 != nil || e2 != nil || strings.Join(osp.DeniedReads, " ") != strings.Join(vsp.DeniedReads, " ") ||
		strings.Join(osp.DeniedRPC, " ") != strings.Join(vsp.DeniedRPC, " ") || read("other-custody-spec.json") == read("custody-spec.json") {
		t.Fatal("T18RH_SPEC the other spec must differ from the valid spec only outside its rows", e1, e2)
	}

	edit := func(text, re, repl string) string {
		out := regexp.MustCompile(`(?m)`+re).ReplaceAllString(text, repl)
		if out == text {
			t.Fatalf("T18RH_SPEC edit %q matched nothing", re)
		}
		return out
	}
	const wallet = "denied-read:/etc/swarma/wallet/wallet.json"
	const extra = "denied-read:/etc/swarma/wallet/extra.json PASS observed=EACCES"
	hashLine := `^custody_spec_sha256 [0-9a-f]{64}\n`
	stored := []struct{ file, made, reason string }{
		{"row-deleted-overall-edited.txt", edit(edit(validRaw, `^`+regexp.QuoteMeta(wallet)+` .*\n`, ""), `^OVERALL PASS pass=21 `, "OVERALL PASS pass=20 "), "missing:denied-read:/etc/swarma/wallet/wallet.json"},
		{"missing-hash.txt", edit(validRaw, hashLine, ""), "custody-spec-sha256:missing"},
		{"duplicate-hash.txt", edit(validRaw, `^(custody_spec_sha256 [0-9a-f]{64}\n)`, "$1$1"), "custody-spec-sha256:duplicate"},
		{"extra-denied-row.txt", edit(edit(validRaw, `^(denied-rpc:)`, extra+"\n$1"), `^OVERALL PASS pass=21 `, "OVERALL PASS pass=22 "), "extra-row:denied-read:/etc/swarma/wallet/extra.json"},
	}
	for _, c := range stored {
		text := read(c.file)
		if text != c.made {
			t.Fatalf("T18RH_SPEC %s is not the valid report with exactly its stated edit", c.file)
		}
		code, out := t18rhCheckFile(t, c.file, t18rhLive(text), spec)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, "\n# reasons: "+c.reason+" stated-overall-disagrees\n") {
			t.Fatalf("T18RH_SPEC %s: exit %d, want 1 with exactly %q\n%s", c.file, code, c.reason, out)
		}
	}
	if code, out := t18rhCheckFile(t, "other-spec", valid, other); code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") ||
		!strings.Contains(out, "\n# reasons: header-spec-sha256:differs header-agent-uid-not-spec header-primary-gid-not-spec render-custody-spec-file-sha256:differs custody-spec-sha256:differs stated-overall-disagrees\n") {
		t.Fatalf("T18RH_SPEC the valid report against another spec: exit %d\n%s", code, out)
	}

	noRPC := filepath.Join(t.TempDir(), "no-rpc.json")
	os.WriteFile(noRPC, []byte(edit(read("custody-spec.json"), `"denied_rpc":\[[^]]*\],`, "")), 0600)
	neighbours := []struct{ name, text, spec, reason string }{
		{"extra-rpc-row", edit(edit(valid, `^(peer-precondition )`, "denied-rpc:127.0.0.1:8337 PASS observed=HTTP_401\n$1"), `^OVERALL PASS pass=21 `, "OVERALL PASS pass=22 "), spec, "extra-row:denied-rpc:127.0.0.1:8337"},
		{"missing-rpc-row", edit(edit(valid, `^denied-rpc:.*\n`, ""), `^OVERALL PASS pass=21 `, "OVERALL PASS pass=20 "), spec, "missing:denied-rpc:127.0.0.1:8336"},
		{"duplicate-denied-row", edit(edit(valid, `^(`+regexp.QuoteMeta(wallet)+` .*\n)`, "$1$1"), `^OVERALL PASS pass=21 `, "OVERALL PASS pass=22 "), spec, "duplicate:" + wallet},
		{"hash-uppercase", edit(valid, `^custody_spec_sha256 8d1820c3`, "custody_spec_sha256 8D1820C3"), spec, "custody-spec-sha256:malformed:line2"},
		{"hash-short", edit(valid, `^(custody_spec_sha256 [0-9a-f]{63})[0-9a-f]$`, "$1"), spec, "custody-spec-sha256:malformed:line2"},
		{"spec-without-rpc", valid, noRPC, "custody-spec-unreadable"},
	}
	for _, c := range neighbours {
		code, out := t18rhCheckFile(t, c.name, c.text, c.spec)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, c.reason) {
			t.Fatalf("T18RH_SPEC %s: exit %d, want 1 with %q\n%s", c.name, code, c.reason, out)
		}
	}
	// A FAIL row is still the spec entry's row: the report fails on that item
	// alone, with nothing missing and nothing invalid.
	failRow := edit(edit(valid, `^(`+regexp.QuoteMeta(wallet)+`) PASS observed=EACCES .*$`, "$1 FAIL observed=ENOENT"),
		`^OVERALL PASS pass=21 stand_in=0 covered=11 fail=0 `, "OVERALL FAIL pass=20 stand_in=0 covered=11 fail=1 ")
	want := strings.Replace(overall, "OVERALL PASS pass=21 stand_in=0 covered=11 fail=0 ", "OVERALL FAIL pass=20 stand_in=0 covered=11 fail=1 ", 1)
	if code, out := t18rhCheckFile(t, "fail-row", failRow, spec); code != 1 || out != want {
		t.Fatalf("T18RH_SPEC a FAIL row: exit %d, want exactly %q\n%s", code, want, out)
	}
}

// t18rhR5 holds the r5 plants: the r4 valid real report with exactly one of
// its three spec hashes changed to the other spec's value.
const t18rhR5 = "testdata/t18-real-host-r5"

// Claim (r5): no spec hash in a report is a free field. check refuses unless
// all three equal the given spec's: the custody_spec_sha256 line and the
// render line's custody_spec_file_sha256 the SHA-256 of the spec file, and the
// header's spec_sha256 the spec's canonical hash. The expected values are
// computed here from the spec bytes and the product's CustodySpecSHA256 (the
// hash g2-custody-verify reports), not taken from the runner. The valid report
// names its spec in all three and passes (exit 0). Each stored plant is that
// report with one of the three changed alone to the other spec's value, and
// is refused with exit 1 and exactly its named reason beside the stated
// OVERALL line; the header plant also contradicts custody-verify's and (r7)
// launch-layout's verified=, which equal the header in a valid report. Neighbours: the header and
// verified= changed together are refused by the header comparison alone, and
// the given spec with one more trailing newline (same canonical hash, another
// file, which the product's spec reader accepts) is refused by the two file
// hashes and not by the header. r6: check takes
// the canonical hash only from `deploy-kit g2-custody-hash` (the real one,
// built from this tree); TestT18RealHostCanonicalHashFromProduct holds the
// controls around that source.
func TestT18RealHostAllSpecHashesBound(t *testing.T) {
	spec, other := filepath.Join(t18rhR4, "custody-spec.json"), filepath.Join(t18rhR4, "other-custody-spec.json")
	read := func(path string) string {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	canon := func(path string) string {
		sp, e := ParseCustodySpec([]byte(strings.TrimSuffix(read(path), "\n")))
		if e != nil {
			t.Fatal(e)
		}
		return CustodySpecSHA256(sp)
	}
	fileSHA, canonSHA := t18rhSha([]byte(read(spec))), canon(spec)
	otherFile, otherCanon := t18rhSha([]byte(read(other))), canon(other)
	if fileSHA == canonSHA || otherFile == fileSHA || otherCanon == canonSHA {
		t.Fatal("T18RH_HASHES the file and canonical hashes of the two specs must all differ")
	}
	valid := t18rhLive(read(filepath.Join(t18rhR4, "valid-real.txt")))
	header := valid[:strings.Index(valid, "\n")]
	if !strings.Contains(header, " spec_sha256="+canonSHA+" ") || strings.Count(valid, canonSHA) != 3 ||
		strings.Count(valid, "\ncustody_spec_sha256 "+fileSHA+"\n") != 1 ||
		strings.Count(valid, "\nrender PASS files=6 custody_spec_file_sha256="+fileSHA+"\n") != 1 || strings.Count(valid, fileSHA) != 2 {
		t.Fatal("T18RH_HASHES the valid report does not name its spec in all three fields\n", valid)
	}
	last := valid[strings.LastIndex(strings.TrimSuffix(valid, "\n"), "\n")+1:]
	if code, out := t18rhCheckFile(t, "valid-real", valid, spec); code != 0 || out != last {
		t.Fatalf("T18RH_HASHES the valid report refused with its spec: %d\n%s", code, out)
	}
	edit := func(text, re, repl string) string {
		out := regexp.MustCompile(`(?m)`+re).ReplaceAllString(text, repl)
		if out == text {
			t.Fatalf("T18RH_HASHES edit %q matched nothing", re)
		}
		return out
	}
	headerRe, headerTo := `^(T18-REAL-HOST v1 .* spec_sha256=)`+canonSHA+` `, "${1}"+otherCanon+" "
	plants := []struct{ file, made, reasons string }{
		{"custody-hash-differs.txt", edit(valid, `^custody_spec_sha256 `+fileSHA+`$`, "custody_spec_sha256 "+otherFile), "custody-spec-sha256:differs"},
		{"header-hash-differs.txt", edit(valid, headerRe, headerTo), "header-spec-sha256:differs custody-verify-pass-other-spec launch-layout-pass-contradicts-verify"},
		{"render-hash-differs.txt", edit(valid, `^(render PASS files=6 custody_spec_file_sha256=)`+fileSHA+`$`, "${1}"+otherFile), "render-custody-spec-file-sha256:differs"},
	}
	for _, c := range plants {
		text := t18rhLive(read(filepath.Join(t18rhR5, c.file)))
		if text != c.made {
			t.Fatalf("T18RH_HASHES %s is not the valid report with exactly its stated edit", c.file)
		}
		code, out := t18rhCheckFile(t, c.file, text, spec)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, "\n# reasons: "+c.reasons+" stated-overall-disagrees\n") {
			t.Fatalf("T18RH_HASHES %s: exit %d, want 1 with exactly %q\n%s", c.file, code, c.reasons, out)
		}
	}
	// The header and both verified= (custody-verify, r7 launch-layout) moved
	// together: only the header comparison sees it.
	both := edit(edit(edit(valid, headerRe, headerTo), `^(custody-verify PASS .* verified=)`+canonSHA+`$`, "${1}"+otherCanon), `^(launch-layout PASS .* verified=)`+canonSHA+`$`, "${1}"+otherCanon)
	if code, out := t18rhCheckFile(t, "header-and-verified", both, spec); code != 1 || !strings.Contains(out, "\n# reasons: header-spec-sha256:differs stated-overall-disagrees\n") {
		t.Fatalf("T18RH_HASHES header and verified= moved together: exit %d\n%s", code, out)
	}
	// One more trailing newline: the canonical hash agrees, the file does not.
	nl := filepath.Join(t.TempDir(), "custody-spec.json")
	if e := os.WriteFile(nl, []byte(read(spec)+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if code, out := t18rhCheckFile(t, "spec-extra-newline", valid, nl); code != 1 ||
		!strings.Contains(out, "\n# reasons: render-custody-spec-file-sha256:differs custody-spec-sha256:differs stated-overall-disagrees\n") {
		t.Fatalf("T18RH_HASHES the spec with one more newline: exit %d\n%s", code, out)
	}
}

// Claim (r6): check and report take the canonical spec hash only from
// `$DEPLOY_KIT g2-custody-hash -spec SPEC` and read its output strictly.
// Positive controls: the stored r4 valid report passes check with the real
// deploy-kit, and with a stand-in that prints exactly the product's line only
// for the exact arguments `g2-custody-hash -spec SPEC`. check refuses with
// exactly canonical-hash-unavailable (exit 1; the header is not compared)
// when DEPLOY_KIT names no file, when it is empty and no deploy-kit is on
// PATH, and when the stand-in prints nothing, garbage, the right line twice,
// in upper case, with a trailing space or without its newline, or the right
// line with exit 1; a stand-in printing another well-formed hash gives
// exactly header-spec-sha256:differs. The two whitespace variants of the r4
// spec (a leading space; a trailing space before the newline), whose shell
// hash (bytes without the trailing newline) differs from the canonical hash,
// agree with the product: the valid report with their file hashes moved
// along passes. report refuses to compose without the product (REFUSED
// canonical-hash-unavailable, exit 1, no header), and composes a passing
// report on the fixture with a leading-space spec, whose header carries the
// canonical hash. Limit: the stand-ins are shell scripts; the product's
// standard error is not read.
func TestT18RealHostCanonicalHashFromProduct(t *testing.T) {
	spec := filepath.Join(t18rhR4, "custody-spec.json")
	raw, e := os.ReadFile(spec)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(t18rhR4, "valid-real.txt"))
	if e != nil {
		t.Fatal(e)
	}
	valid := t18rhLive(string(b))
	last := valid[strings.LastIndex(strings.TrimSuffix(valid, "\n"), "\n")+1:]
	sp, e := ParseCustodySpec(raw[:len(raw)-1])
	if e != nil {
		t.Fatal(e)
	}
	canon := CustodySpecSHA256(sp)
	if !strings.HasPrefix(valid, "T18-REAL-HOST v1 wallet=real commit="+t18rhCommit+" spec_sha256="+canon+" ") {
		t.Fatal("T18RH_CANON setup: the valid report's header does not carry the canonical hash")
	}
	check := func(name, text, specPath string, env ...string) (int, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		os.WriteFile(path, []byte(text), 0600)
		return t18rhRun(t, env, "check", path, specPath)
	}
	if code, out := check("real-kit", valid, spec); code != 0 || out != last {
		t.Fatalf("T18RH_CANON the valid report with the real deploy-kit: %d\n%s", code, out)
	}
	dir := t.TempDir()
	fake := func(name, body string) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0700); e != nil {
			t.Fatal(e)
		}
		return p
	}
	line := "T18_CUSTODY_SPEC_SHA256 " + canon
	args := `[ "$#" = 3 ] && [ "$1" = g2-custody-hash ] && [ "$2" = -spec ] && [ "$3" = '` + spec + `' ] && `
	exact := fake("exact", args+`printf '%s\n' '`+line+`' || echo wrong-arguments`)
	if code, out := check("exact-stand-in", valid, spec, "DEPLOY_KIT="+exact); code != 0 || out != last {
		t.Fatalf("T18RH_CANON a stand-in printing exactly the product's line: %d\n%s", code, out)
	}
	unavailable := "\n# reasons: canonical-hash-unavailable stated-overall-disagrees\n"
	for _, c := range []struct{ name, kit, reasons string }{
		{"kit-missing", filepath.Join(dir, "absent", "deploy-kit"), unavailable},
		{"kit-wrong-hash", fake("wrong", "echo T18_CUSTODY_SPEC_SHA256 "+strings.Repeat("0", 64)), "\n# reasons: header-spec-sha256:differs stated-overall-disagrees\n"},
		{"kit-garbage", fake("garbage", "echo T18_CUSTODY_SPEC_SHA256 not-a-hash"), unavailable},
		{"kit-empty", fake("empty", "exit 0"), unavailable},
		{"kit-nonzero-exit", fake("exit1", "echo "+line+"; exit 1"), unavailable},
		{"kit-two-lines", fake("two", "echo "+line+"; echo "+line), unavailable},
		{"kit-upper-case", fake("upper", "echo "+strings.ToUpper(line)), unavailable},
		{"kit-trailing-space", fake("space", "echo '"+line+" '"), unavailable},
		{"kit-no-newline", fake("nonl", "printf '%s' '"+line+"'"), unavailable},
		{"kit-wrong-arguments", fake("args", args+"exit 0; echo "+line), unavailable},
	} {
		if code, out := check(c.name, valid, spec, "DEPLOY_KIT="+c.kit); code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, c.reasons) {
			t.Fatalf("T18RH_CANON %s: exit %d, want 1 with exactly %q\n%s", c.name, code, c.reasons, out)
		}
	}
	// DEPLOY_KIT empty: the default name, deploy-kit, is looked up on PATH.
	if p, e := exec.LookPath("deploy-kit"); e == nil && (filepath.Dir(p) == "/usr/bin" || filepath.Dir(p) == "/bin") {
		t.Log("T18RH_CANON a system deploy-kit exists; the PATH case did not run")
	} else if code, out := check("kit-not-on-path", valid, spec, "DEPLOY_KIT=", "PATH=/usr/bin:/bin"); code != 1 || !strings.Contains(out, unavailable) {
		t.Fatalf("T18RH_CANON no deploy-kit on PATH: exit %d\n%s", code, out)
	}
	// The whitespace variants are the same spec to the product.
	for name, variant := range map[string][]byte{
		"lead-space":  append([]byte(" "), raw...),
		"trail-space": append(append(append([]byte{}, raw[:len(raw)-1]...), ' '), '\n'),
	} {
		path := filepath.Join(dir, name+".json")
		os.WriteFile(path, variant, 0600)
		if shell := t18rhSha(variant[:len(variant)-1]); shell == canon {
			t.Fatalf("T18RH_CANON setup: %s shell hash equals the canonical hash", name)
		}
		file := t18rhSha(variant)
		moved := strings.Replace(strings.Replace(valid, "\ncustody_spec_sha256 "+t18rhSha(raw)+"\n", "\ncustody_spec_sha256 "+file+"\n", 1),
			"\nrender PASS files=6 custody_spec_file_sha256="+t18rhSha(raw)+"\n", "\nrender PASS files=6 custody_spec_file_sha256="+file+"\n", 1)
		if strings.Count(moved, file) != 2 {
			t.Fatalf("T18RH_CANON setup: %s file hashes not moved", name)
		}
		if code, out := check(name, moved, path); code != 0 || out != last {
			t.Fatalf("T18RH_CANON the %s spec disagrees with the product: %d\n%s", name, code, out)
		}
	}

	// report: no product, no report; with the product, a leading-space spec
	// composes the header from the canonical hash.
	f := t18rhFixture(t)
	if code, out := t18rhRun(t, []string{"DEPLOY_KIT=" + filepath.Join(dir, "absent", "deploy-kit")}, "report", f.op, f.ag, f.rendered, f.params, "real"); code != 1 ||
		!strings.HasPrefix(out, "REFUSED canonical-hash-unavailable: ") || strings.Contains(out, "T18-REAL-HOST") || strings.Contains(out, "OVERALL") {
		t.Fatalf("T18RH_CANON report without the product: %d\n%s", code, out)
	}
	rendered, _ := os.ReadFile(f.renderedSpec)
	lead := append([]byte(" "), rendered...)
	os.WriteFile(f.renderedSpec, lead, 0600)
	inputs, _ := os.ReadFile(filepath.Join(f.ag, "inputs.sha256"))
	f.write(t, "inputs.sha256", strings.Replace(string(inputs), t18rhSha(rendered), t18rhSha(lead), 1))
	code, out := f.report(t, "real")
	if code != 0 || !strings.HasPrefix(out, "T18-REAL-HOST v1 wallet=real commit="+t18rhCommit+" spec_sha256="+f.specSHA+" ") ||
		!strings.Contains(out, "\ncustody_spec_sha256 "+t18rhSha(lead)+"\n") || !strings.Contains(out, "\nOVERALL PASS ") {
		t.Fatalf("T18RH_CANON report on a leading-space spec: %d\n%s", code, out)
	}
}

// Claim (r7): the launch layout, which g2-custody-verify enforces per run with
// -launch=true, is its own required item. On the all-pass evidence it is
// PASS with verify_exit=0 and verified= the header's canonical hash (OVERALL
// PASS). The planted control, verify -launch=true refusing the run's layout
// (`deploy: invalid policy`, exit 1) while -launch=false accepted the same
// report, makes launch-layout FAIL layout=refused and OVERALL FAIL with that
// item the only failure, even though custody-verify's own evidence is
// unchanged. Neighbours: both refusing is layout=unknown; a repeated or
// missing exit line, a second output line, another hash, and missing output
// are FAIL. check refuses a stored report without the item (missing) and a
// PASS line that contradicts verify (exit 1, launch=false, another hash).
// Limit: the evidence files are synthetic here; the real verify's refusal of
// a non-launch spec is TestT18RealHostAgentPhase's.
func TestT18RealHostLaunchLayoutItem(t *testing.T) {
	refused := "custody_check_exit=1\nlaunch_true_exit=1\nlaunch_false_exit=0\npeer_exit=0\n"
	for _, c := range []struct {
		name  string
		plant func(f *t18rhFix)
		code  int
		want  string
	}{
		{"valid", func(f *t18rhFix) {}, 0, `^launch-layout PASS verify=g2-custody-verify launch=true verify_exit=0 verified=%s$`},
		{"layout-refused", func(f *t18rhFix) {
			f.write(t, "agent-exits.txt", refused)
			f.write(t, "launch-layout-on.txt", "deploy: invalid policy\n")
		}, 1, `^launch-layout FAIL launch=true verify_exit=1 verify=deploy:,invalid,policy launch_false_exit=0 layout=refused$`},
		{"both-refused", func(f *t18rhFix) {
			f.write(t, "agent-exits.txt", "custody_check_exit=1\nlaunch_true_exit=1\nlaunch_false_exit=1\npeer_exit=0\n")
			f.write(t, "launch-layout-on.txt", "deploy: G2 custody check refused\n")
			f.write(t, "launch-layout-off.txt", "deploy: G2 custody check refused\n")
		}, 1, `^launch-layout FAIL launch=true verify_exit=1 .* launch_false_exit=1 layout=unknown$`},
		{"exit-line-twice", func(f *t18rhFix) {
			f.write(t, "agent-exits.txt", t18rhAgentExitsOK+"launch_true_exit=0\n")
		}, 1, `^launch-layout FAIL launch=true verify_exit=none `},
		{"exit-line-missing", func(f *t18rhFix) {
			f.write(t, "agent-exits.txt", "custody_check_exit=1\nlaunch_false_exit=0\npeer_exit=0\n")
		}, 1, `^launch-layout FAIL launch=true verify_exit=none .* layout=refused$`},
		{"second-output-line", func(f *t18rhFix) {
			f.write(t, "launch-layout-on.txt", "T18_CUSTODY_VERIFIED "+f.specSHA+"\nextra\n")
		}, 1, `^launch-layout FAIL launch=true verify_exit=0 `},
		{"other-hash", func(f *t18rhFix) {
			f.write(t, "launch-layout-on.txt", "T18_CUSTODY_VERIFIED "+strings.Repeat("0", 64)+"\n")
		}, 1, `^launch-layout FAIL launch=true verify_exit=0 `},
		{"no-output", func(f *t18rhFix) {
			os.Remove(filepath.Join(f.ag, "launch-layout-on.txt"))
		}, 1, `^launch-layout FAIL launch=true verify_exit=0 verify=none `},
	} {
		f := t18rhFixture(t)
		c.plant(f)
		code, out := f.report(t, "real")
		want := c.want
		if c.name == "valid" {
			want = strings.Replace(want, "%s", f.specSHA, 1)
		}
		if code != c.code || !regexp.MustCompile(`(?m)`+want).MatchString(out) {
			t.Fatalf("T18RH_LAUNCH %s: exit %d, want %d and %s\n%s", c.name, code, c.code, want, out)
		}
		if c.code == 0 && !strings.Contains(out, "\nOVERALL PASS ") {
			t.Fatalf("T18RH_LAUNCH %s: OVERALL is not PASS\n%s", c.name, out)
		}
		if c.code != 0 && (strings.Contains(out, "\nOVERALL PASS ") || !strings.Contains(out, " fail=1 ")) {
			t.Fatalf("T18RH_LAUNCH %s: OVERALL must be FAIL from launch-layout alone\n%s", c.name, out)
		}
	}
	spec := filepath.Join(t18rhR4, "custody-spec.json")
	b, e := os.ReadFile(filepath.Join(t18rhR4, "valid-real.txt"))
	if e != nil {
		t.Fatal(e)
	}
	valid := t18rhLive(string(b))
	edit := func(text, re, repl string) string {
		out := regexp.MustCompile(`(?m)`+re).ReplaceAllString(text, repl)
		if out == text {
			t.Fatalf("T18RH_LAUNCH edit %q matched nothing", re)
		}
		return out
	}
	if code, out := t18rhCheckFile(t, "valid", valid, spec); code != 0 || !strings.HasPrefix(out, "OVERALL PASS pass=21 ") {
		t.Fatalf("T18RH_LAUNCH the stored valid report: %d\n%s", code, out)
	}
	for _, c := range []struct{ name, text, reason string }{
		{"item-missing", edit(edit(valid, `^launch-layout .*\n`, ""), `^OVERALL PASS pass=21 `, "OVERALL PASS pass=20 "), "missing:launch-layout"},
		{"pass-with-exit-1", edit(valid, `^(launch-layout PASS .*) verify_exit=0 `, "$1 verify_exit=1 "), "launch-layout-pass-contradicts-verify"},
		{"pass-launch-false", edit(valid, `^(launch-layout PASS .*) launch=true `, "$1 launch=false "), "launch-layout-pass-contradicts-verify"},
		{"pass-other-hash", edit(valid, `^(launch-layout PASS .* verified=)[0-9a-f]+$`, "${1}"+strings.Repeat("0", 64)), "launch-layout-pass-contradicts-verify"},
		{"pass-other-verifier", edit(valid, `^(launch-layout PASS) verify=g2-custody-verify `, "$1 verify=other "), "launch-layout-pass-contradicts-verify"},
	} {
		code, out := t18rhCheckFile(t, c.name, c.text, spec)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, c.reason) {
			t.Fatalf("T18RH_LAUNCH check %s: exit %d, want 1 with %s\n%s", c.name, code, c.reason, out)
		}
	}
}

// Claim (r7): the hash step refuses a failing product on its own exit-status
// check, not because errexit happens to stop the command substitution. The
// runner is copied with its one `set -eu` line changed to `set -u` (errexit
// OFF, nothing else changed) and given a product that prints the correct
// canonical line and exits 1: check still refuses canonical-hash-unavailable
// and report still composes nothing (REFUSED canonical-hash-unavailable).
// Positive control: the same errexit-off copy with the real deploy-kit passes
// check on the valid report and composes a passing report.
func TestT18RealHostHashStepErrexitOff(t *testing.T) {
	src, e := os.ReadFile(t18rhScript)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(src), "\nset -eu\n") != 1 {
		t.Fatal("T18RH_ERREXIT setup: the runner has not exactly one `set -eu` line")
	}
	dir := t.TempDir()
	copyPath := filepath.Join(dir, "t18-real-host-report.sh")
	if e := os.WriteFile(copyPath, []byte(strings.Replace(string(src), "\nset -eu\n", "\nset -u\n", 1)), 0700); e != nil {
		t.Fatal(e)
	}
	spec := filepath.Join(t18rhR4, "custody-spec.json")
	raw, e := os.ReadFile(spec)
	if e != nil {
		t.Fatal(e)
	}
	sp, e := ParseCustodySpec(raw[:len(raw)-1])
	if e != nil {
		t.Fatal(e)
	}
	failing := filepath.Join(dir, "deploy-kit-exit1")
	if e := os.WriteFile(failing, []byte("#!/bin/sh\necho T18_CUSTODY_SPEC_SHA256 "+CustodySpecSHA256(sp)+"\nexit 1\n"), 0700); e != nil {
		t.Fatal(e)
	}
	run := func(kit string, args ...string) (int, string) {
		t.Helper()
		cmd := exec.Command("/bin/sh", append([]string{copyPath}, args...)...)
		cmd.Env = append(os.Environ(), "DEPLOY_KIT="+kit)
		out, e := cmd.CombinedOutput()
		if _, ok := e.(*exec.ExitError); e != nil && !ok {
			t.Fatal("T18RH_ERREXIT", e)
		}
		return cmd.ProcessState.ExitCode(), string(out)
	}
	valid := t18rhLiveFile(t, "valid-real.txt")
	if code, out := run(t18rhKit(t), "check", valid, spec); code != 0 || !strings.HasPrefix(out, "OVERALL PASS ") {
		t.Fatalf("T18RH_ERREXIT control: errexit-off check with the real deploy-kit: %d\n%s", code, out)
	}
	if code, out := run(failing, "check", valid, spec); code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") ||
		!strings.Contains(out, "\n# reasons: canonical-hash-unavailable stated-overall-disagrees\n") {
		t.Fatalf("T18RH_ERREXIT errexit-off check with a product that exits 1: %d\n%s", code, out)
	}
	f := t18rhFixture(t)
	if code, out := run(t18rhKit(t), "report", f.op, f.ag, f.rendered, f.params, "real"); code != 0 || !strings.Contains(out, "\nOVERALL PASS ") {
		t.Fatalf("T18RH_ERREXIT control: errexit-off report with the real deploy-kit: %d\n%s", code, out)
	}
	if code, out := run(failing, "report", f.op, f.ag, f.rendered, f.params, "real"); code != 1 ||
		!strings.HasPrefix(out, "REFUSED canonical-hash-unavailable: ") || strings.Contains(out, "T18-REAL-HOST") || strings.Contains(out, "OVERALL") {
		t.Fatalf("T18RH_ERREXIT errexit-off report with a product that exits 1: %d\n%s", code, out)
	}
}

// t18rhLastLine is the last line of a report, its OVERALL line.
func t18rhLastLine(text string) string {
	return text[strings.LastIndex(strings.TrimSuffix(text, "\n"), "\n")+1:]
}

// Claim (r8, check-unvalidated-pass-evidence): check binds every displayed
// identity to the supplied spec the product accepted. With the r4 spec and
// all three spec hashes unchanged, the stored r4 valid report is refused
// (exit 1, OVERALL FAIL, exactly the named reasons) when its displayed agent
// identity (header, account, launch UIDs and GIDs, credentials,
// custody-verify) is root 0 (reserved and not the spec's agent_uid) or the
// nonreserved 2201 (only header-agent-uid-not-spec and
// header-primary-gid-not-spec: the spec comparison, not the reserved-ID rule,
// refuses it), and when the service UID, peer UID and socket owner are root 0
// or the nonreserved 2101. Positive control, not hardcoded r4 identities: an
// alternate spec rendered by the product for agent 2201, socket GID 2301 and
// service 2101 composes a consistent report that is OVERALL PASS and passes
// check against that spec; crossed over, that report against the r4 spec and
// the r4 report against the alternate spec are refused as identity
// contradictions. Limit: the spec carries no socket GID, so socket_gid is
// bound to the items, not to the spec; and a report whose every identity
// agrees with its spec is self-consistent: check does not authenticate it.
func TestT18RealHostHeaderIdentityMatchesSpec(t *testing.T) {
	spec := filepath.Join(t18rhR4, "custody-spec.json")
	b, e := os.ReadFile(filepath.Join(t18rhR4, "valid-real.txt"))
	if e != nil {
		t.Fatal(e)
	}
	valid := t18rhLive(string(b))
	if code, out := t18rhCheckFile(t, "valid", valid, spec); code != 0 || out != t18rhLastLine(valid) {
		t.Fatalf("T18RH_IDENTITY control: the stored r4 report: %d\n%s", code, out)
	}
	hashLines := regexp.MustCompile(`(?m)^(T18-REAL-HOST v1 wallet=real commit=\S+ spec_sha256=[0-9a-f]{64} |custody_spec_sha256 [0-9a-f]{64}$|render PASS files=6 custody_spec_file_sha256=[0-9a-f]{64}$)`)
	for _, c := range []struct{ name, from, to, reasons string }{
		{"agent-root", "1201", "0", "header-reserved-id:agent_uid header-reserved-id:primary_gid header-agent-uid-not-spec header-primary-gid-not-spec"},
		{"agent-other-nonreserved", "1201", "2201", "header-agent-uid-not-spec header-primary-gid-not-spec"},
		{"service-owners-root", "1101", "0", "header-reserved-id:service_uid header-service-uid-not-spec"},
		{"service-owners-other-nonreserved", "1101", "2101", "header-service-uid-not-spec"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := strings.ReplaceAll(valid, c.from, c.to)
			if text == valid || strings.Join(hashLines.FindAllString(text, -1), "") != strings.Join(hashLines.FindAllString(valid, -1), "") ||
				len(hashLines.FindAllString(text, -1)) != 3 {
				t.Fatalf("T18RH_IDENTITY setup %s: the spec hashes must stay unchanged", c.name)
			}
			code, out := t18rhCheckFile(t, c.name, text, spec)
			if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, "\n# reasons: "+c.reasons+" stated-overall-disagrees\n") {
				t.Fatalf("T18RH_IDENTITY %s: exit %d, want 1 with exactly %q\n%s", c.name, code, c.reasons, out)
			}
		})
	}
	t.Run("alternate-spec-control", func(t *testing.T) {
		p := g2Params()
		p.AgentUID, p.AgentSocketGID, p.ServiceUID = 2201, 2301, 2101
		f := t18rhFixtureFor(t, p)
		if f.primary != 2201 || f.socket != 2301 || f.spec.AgentUID != 2201 || f.spec.ServiceUID != 2101 {
			t.Fatalf("T18RH_IDENTITY setup: alternate identities %d %d %+v", f.primary, f.socket, f.spec)
		}
		code, out := f.report(t, "real")
		if code != 0 || !strings.HasPrefix(out, "T18-REAL-HOST v1 wallet=real commit="+t18rhCommit+" spec_sha256="+f.specSHA+" agent_uid=2201 primary_gid=2201 socket_gid=2301 service_uid=2101\n") ||
			!strings.HasSuffix(out, "\nOVERALL PASS pass=21 stand_in=0 covered=11 fail=0 invalid=0 missing=0 run=real\n") {
			t.Fatalf("T18RH_IDENTITY the alternate spec's consistent run: %d\n%s", code, out)
		}
		if code, got := t18rhCheckFile(t, "alternate", out, f.renderedSpec); code != 0 || got != t18rhLastLine(out) {
			t.Fatalf("T18RH_IDENTITY check of the alternate report against its spec: %d\n%s", code, got)
		}
		want := "header-agent-uid-not-spec header-primary-gid-not-spec header-service-uid-not-spec"
		for name, pair := range map[string][2]string{"alternate-report-r4-spec": {out, spec}, "r4-report-alternate-spec": {valid, f.renderedSpec}} {
			code, got := t18rhCheckFile(t, name, pair[0], pair[1])
			if code != 1 || !strings.Contains(got, " "+want+" ") {
				t.Fatalf("T18RH_IDENTITY %s: exit %d, want 1 with %q\n%s", name, code, want, got)
			}
		}
	})
}

// t18rhRunScript runs the runner at script (a copy) with DEPLOY_KIT=kit.
func t18rhRunScript(t *testing.T, script, kit string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), "DEPLOY_KIT="+kit)
	out, e := cmd.CombinedOutput()
	if _, ok := e.(*exec.ExitError); e != nil && !ok {
		t.Fatal("T18RH_SETUP", e)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// Claim (r8, evidence-bytes-lost-in-command-substitution): the product's
// canonical-hash output and the verifier outputs are judged on their raw
// bytes, before any shell normalization. A product stand-in that exits 0 and
// prints the exact canonical line with a NUL before or after the newline or
// inside the line, with CR before the newline, with an extra trailing
// newline, without the newline, or binary garbage is refused by name: check
// gives exactly canonical-hash-unavailable and report composes nothing
// (REFUSED canonical-hash-unavailable, no header), with errexit on and with
// the runner's one `set -eu` changed to `set -u`. The stand-in printing
// exactly the line and one newline passes check and composes OVERALL PASS in
// both modes. The same byte variants of the launch=true verifier output
// turn launch-layout FAIL, and of the custody verifier output turn
// custody-verify FAIL, each the only failure (OVERALL FAIL, exit 1), beside
// the exact output's PASS. Limit: the stand-ins replay fixed bytes; readSpec
// itself is the product's and is not changed or exercised here beyond the
// real deploy-kit controls of the other tests.
func TestT18RealHostRawProductBytes(t *testing.T) {
	src, e := os.ReadFile(t18rhScript)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(src), "\nset -eu\n") != 1 {
		t.Fatal("T18RH_RAW setup: the runner has not exactly one `set -eu` line")
	}
	dir := t.TempDir()
	errexitOff := filepath.Join(dir, "errexit-off.sh")
	if e := os.WriteFile(errexitOff, []byte(strings.Replace(string(src), "\nset -eu\n", "\nset -u\n", 1)), 0700); e != nil {
		t.Fatal(e)
	}
	spec := filepath.Join(t18rhR4, "custody-spec.json")
	validPath := t18rhLiveFile(t, "valid-real.txt")
	b, e := os.ReadFile(validPath)
	if e != nil {
		t.Fatal(e)
	}
	valid := string(b)
	raw, e := os.ReadFile(spec)
	if e != nil {
		t.Fatal(e)
	}
	sp, e := ParseCustodySpec(raw[:len(raw)-1])
	if e != nil {
		t.Fatal(e)
	}
	line := "T18_CUSTODY_SPEC_SHA256 " + CustodySpecSHA256(sp)
	// stand-in replays fixed stdout bytes and exits 0.
	stand := func(name string, out []byte) string {
		payload := filepath.Join(dir, name+".out")
		if e := os.WriteFile(payload, out, 0600); e != nil {
			t.Fatal(e)
		}
		kit := filepath.Join(dir, name)
		if e := os.WriteFile(kit, []byte("#!/bin/sh\ncat '"+payload+"'\n"), 0700); e != nil {
			t.Fatal(e)
		}
		return kit
	}
	bad := map[string][]byte{
		"nul-before-newline": []byte(line + "\x00\n"),
		"nul-after-newline":  []byte(line + "\n\x00"),
		"nul-inside-line":    []byte(line[:30] + "\x00" + line[30:] + "\n"),
		"cr-before-newline":  []byte(line + "\r\n"),
		"extra-newline":      []byte(line + "\n\n"),
		"no-newline":         []byte(line),
		"binary-garbage":     {0xff, 0xfe, 0x00, 'T', '1', '8', 0x80, 0x1b, '\n'},
	}
	for _, mode := range []struct{ name, script string }{{"errexit-on", t18rhScript}, {"errexit-off", errexitOff}} {
		t.Run(mode.name+"/exact-control", func(t *testing.T) {
			kit := stand("exact", []byte(line+"\n"))
			if code, out := t18rhRunScript(t, mode.script, kit, "check", validPath, spec); code != 0 || out != t18rhLastLine(valid) {
				t.Fatalf("T18RH_RAW the exact product line: %d\n%s", code, out)
			}
			f := t18rhFixture(t)
			if code, out := t18rhRunScript(t, mode.script, kit, "report", f.op, f.ag, f.rendered, f.params, "real"); code != 0 || !strings.Contains(out, "\nOVERALL PASS ") {
				t.Fatalf("T18RH_RAW report with the exact product line: %d\n%s", code, out)
			}
		})
		for name, out := range bad {
			t.Run(mode.name+"/hash-"+name, func(t *testing.T) {
				kit := stand(name, out)
				code, got := t18rhRunScript(t, mode.script, kit, "check", validPath, spec)
				if code != 1 || !strings.HasPrefix(got, "OVERALL FAIL ") || !strings.Contains(got, "\n# reasons: canonical-hash-unavailable stated-overall-disagrees\n") {
					t.Fatalf("T18RH_RAW check with product output %q: exit %d\n%s", out, code, got)
				}
				f := t18rhFixture(t)
				code, got = t18rhRunScript(t, mode.script, kit, "report", f.op, f.ag, f.rendered, f.params, "real")
				if code != 1 || !strings.HasPrefix(got, "REFUSED canonical-hash-unavailable: ") || strings.Contains(got, "T18-REAL-HOST") || strings.Contains(got, "OVERALL") {
					t.Fatalf("T18RH_RAW report with product output %q: exit %d\n%s", out, code, got)
				}
			})
		}
	}
	// The verifier outputs, byte for byte.
	for _, item := range []struct{ file, want string }{
		{"launch-layout-on.txt", `(?m)^launch-layout FAIL launch=true verify_exit=0 `},
		{"custody/custody-verify.txt", `(?m)^custody-verify FAIL `},
	} {
		t.Run(item.file+"/exact-control", func(t *testing.T) {
			f := t18rhFixture(t)
			f.write(t, item.file, "T18_CUSTODY_VERIFIED "+f.specSHA+"\n")
			if code, out := f.report(t, "real"); code != 0 || !strings.Contains(out, "\nOVERALL PASS ") {
				t.Fatalf("T18RH_RAW the exact verifier output in %s: %d\n%s", item.file, code, out)
			}
		})
		for _, v := range []struct{ name, suffix string }{
			{"nul-before-newline", "\x00\n"}, {"nul-after-newline", "\n\x00"}, {"cr-before-newline", "\r\n"},
			{"extra-newline", "\n\n"}, {"no-newline", ""}, {"binary-garbage", "\n\xff\xfe\x00\x80"},
		} {
			t.Run(item.file+"/"+v.name, func(t *testing.T) {
				f := t18rhFixture(t)
				f.write(t, item.file, "T18_CUSTODY_VERIFIED "+f.specSHA+v.suffix)
				code, out := f.report(t, "real")
				if code != 1 || !regexp.MustCompile(item.want).MatchString(out) || strings.Contains(out, "\nOVERALL PASS ") || !strings.Contains(out, " fail=1 invalid=0 ") {
					t.Fatalf("T18RH_RAW %s with %q: exit %d, want 1 with %s alone\n%s", item.file, v.suffix, code, item.want, out)
				}
			})
		}
	}
}

// Claim (r8, account-group-order-regression): the real account's group
// list, as `id -G` printed it, is the exact set {primary GID, socket GID} of
// CheckG2AgentGroups, in either order, with the primary GID below the socket
// GID (r4 parameters: 1201 < 1301) and above it (2201 > 1301). Both orders
// compose account PASS and OVERALL PASS, and the composed report passes
// check. A third group, a missing group, a repeated GID (beside both, or in
// place of the other) and an empty list are refused by the composer (account
// FAIL, the only failure) and, written into the account PASS line of the
// valid report, by check (account-pass-without-real-account). The launch-form
// and credentials group lists of a stored report follow the same set rule:
// the reversed pair passes check; a repeated GID or a third group is refused.
// Limit: the composer's list comes from the account-real.txt evidence file;
// the real `id -G` is exercised by TestT18RealHostAgentPhase.
func TestT18RealHostAccountGroupSet(t *testing.T) {
	below := g2Params()
	above := g2Params()
	above.AgentUID = 2201
	for _, side := range []struct {
		name string
		p    G2PayParameters
	}{{"primary-below-socket", below}, {"primary-above-socket", above}} {
		f := t18rhFixtureFor(t, side.p)
		g, s := t18rhID(f.primary), t18rhID(f.socket)
		if (side.name == "primary-below-socket") != (f.primary < f.socket) {
			t.Fatalf("T18RH_GROUPS setup %s: primary %d socket %d", side.name, f.primary, f.socket)
		}
		var composed string
		for _, order := range []string{g + "," + s, s + "," + g} {
			t.Run(side.name+"/accept-"+order, func(t *testing.T) {
				f.write(t, "op/account-real.txt", "uid="+g+" gid="+g+" groups="+order+"\n")
				code, out := f.report(t, "real")
				if code != 0 || !strings.Contains(out, " real_account=uid="+g+"_gid="+g+"_groups="+order+" group_set=G2_AGENT_GROUPS_OK\n") || !strings.Contains(out, "\nOVERALL PASS ") {
					t.Fatalf("T18RH_GROUPS %s groups=%s: %d\n%s", side.name, order, code, out)
				}
				if code, got := t18rhCheckFile(t, "accept", out, f.renderedSpec); code != 0 || got != t18rhLastLine(out) {
					t.Fatalf("T18RH_GROUPS check %s groups=%s: %d\n%s", side.name, order, code, got)
				}
				if composed == "" {
					composed = out
				}
			})
		}
		f.write(t, "op/account-real.txt", "uid="+g+" gid="+g+" groups="+g+","+s+"\n")
		for name, groups := range map[string]string{
			"third-group":       g + "," + s + ",1401",
			"missing-socket":    g,
			"missing-primary":   s,
			"duplicate-primary": g + "," + g + "," + s,
			"duplicate-socket":  s + "," + g + "," + s,
			"primary-twice":     g + "," + g,
			"empty":             "",
		} {
			t.Run(side.name+"/refuse-"+name, func(t *testing.T) {
				f.write(t, "op/account-real.txt", "uid="+g+" gid="+g+" groups="+groups+"\n")
				defer f.write(t, "op/account-real.txt", "uid="+g+" gid="+g+" groups="+g+","+s+"\n")
				code, out := f.report(t, "real")
				if code != 1 || !strings.Contains(out, "\naccount FAIL ") || strings.Contains(out, "\nOVERALL PASS ") || !strings.Contains(out, " fail=1 invalid=0 ") {
					t.Fatalf("T18RH_GROUPS composer %s groups=%q: %d\n%s", side.name, groups, code, out)
				}
				old := " real_account=uid=" + g + "_gid=" + g + "_groups=" + g + "," + s + " "
				if strings.Count(composed, old) != 1 {
					t.Fatalf("T18RH_GROUPS setup: the valid report's account line\n%s", composed)
				}
				stored := strings.Replace(composed, old, " real_account=uid="+g+"_gid="+g+"_groups="+groups+" ", 1)
				code, got := t18rhCheckFile(t, name, stored, f.renderedSpec)
				if code != 1 || !strings.Contains(got, "\n# reasons: account-pass-without-real-account stated-overall-disagrees\n") {
					t.Fatalf("T18RH_GROUPS check %s groups=%q: %d\n%s", side.name, groups, code, got)
				}
			})
		}
		t.Run(side.name+"/stored-launch-and-credentials-sets", func(t *testing.T) {
			// The composer prints these two lists in numeric order.
			lo, hi := g, s
			if f.primary > f.socket {
				lo, hi = s, g
			}
			for _, c := range []struct{ name, old, new, reason string }{
				{"launch-reversed", " groups=" + lo + "," + hi + " caps=0\n", " groups=" + hi + "," + lo + " caps=0\n", ""},
				{"credentials-reversed", " groups=" + lo + "," + hi + " check=", " groups=" + hi + "," + lo + " check=", ""},
				{"launch-repeated", " groups=" + lo + "," + hi + " caps=0\n", " groups=" + g + "," + g + "," + s + " caps=0\n", "launch-pass-other-groups"},
				{"launch-third", " groups=" + lo + "," + hi + " caps=0\n", " groups=" + g + "," + s + ",1401 caps=0\n", "launch-pass-other-groups"},
				{"credentials-repeated", " groups=" + lo + "," + hi + " check=", " groups=" + s + "," + s + "," + g + " check=", "credentials-pass-contradicts-evidence"},
			} {
				if strings.Count(composed, c.old) != 1 {
					t.Fatalf("T18RH_GROUPS setup %s", c.name)
				}
				code, got := t18rhCheckFile(t, c.name, strings.Replace(composed, c.old, c.new, 1), f.renderedSpec)
				if c.reason == "" && (code != 0 || got != t18rhLastLine(composed)) {
					t.Fatalf("T18RH_GROUPS check %s %s: %d\n%s", side.name, c.name, code, got)
				}
				if c.reason != "" && (code != 1 || !strings.Contains(got, "\n# reasons: "+c.reason+" stated-overall-disagrees\n")) {
					t.Fatalf("T18RH_GROUPS check %s %s: %d, want %s\n%s", side.name, c.name, code, c.reason, got)
				}
			}
		})
	}
}

// Claim (r9, mutants of the denied-rpc liveness rule): every control below
// passes on this runner, and each mutant, one textual edit that reverts or
// narrows one part of the rule, is killed by its named control (the control
// fails on the mutant). A mutant whose edit matches the source other than
// exactly once fails the test, so a mutant cannot silently vanish. The full
// kill matrix is logged. Limit: one mutant per rule part; this shows the
// controls detect these regressions, not every possible one.
func TestT18RealHostRPCLivenessMutants(t *testing.T) {
	kit := t18rhKit(t)
	src, e := os.ReadFile(t18rhScript)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	f := t18rhFixture(t)
	target := f.spec.DeniedRPC[0]
	rpc := "denied-rpc:" + target
	code, real := f.report(t, "real")
	code2, standIn := f.report(t, "stand-in")
	if code != 0 || code2 != 0 {
		t.Fatal("T18RH_MUTANT setup", real, standIn)
	}
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	edit := func(text, old, repl string) string {
		if strings.Count(text, old) != 1 {
			t.Fatalf("T18RH_MUTANT setup edit %q", old)
		}
		return strings.Replace(text, old, repl, 1)
	}
	live := " " + t18rhLiveFields(target)
	refusedPass := write("refused-pass.txt", edit(real, "\n"+rpc+" PASS observed=HTTP_401"+live+"\n", "\n"+rpc+" PASS observed=REFUSED"+live+"\n"))
	notLive := write("not-live.txt", regexp.MustCompile(`(?m)^node-txindex PASS .*$`).ReplaceAllString(real, "node-txindex FAIL getindexinfo=missing"))
	standIn401 := write("stand-in-401.txt", edit(standIn, "\n"+rpc+" PASS observed=HTTP_401\n", "\n"+rpc+" STAND_IN observed=HTTP_401\n"))
	refused := t18rhFixture(t)
	refused.probes(t, map[string]string{target: "REFUSED"})
	dead := t18rhFixture(t)
	dead.write(t, "op/txindex.json", "")
	report := func(script string, g *t18rhFix, wallet string) (int, string) {
		return t18rhRunScript(t, script, kit, "report", g.op, g.ag, g.rendered, g.params, wallet)
	}
	check := func(script, path string) (int, string) {
		return t18rhRunScript(t, script, kit, "check", path, f.renderedSpec)
	}
	controls := []struct {
		name string
		ok   func(script string) bool
	}{
		{"report/real-node-stopped", func(s string) bool {
			c, out := report(s, refused, "real")
			return c == 1 && strings.Contains(out, "\n"+rpc+" FAIL observed=REFUSED reason=node-not-listening\n")
		}},
		{"report/stand-in-refused", func(s string) bool {
			c, out := report(s, refused, "stand-in")
			return c == 0 && strings.Contains(out, "\n"+rpc+" STAND_IN observed=REFUSED\n")
		}},
		{"report/401-node-not-live", func(s string) bool {
			c, out := report(s, dead, "real")
			return c == 1 && strings.Contains(out, "\n"+rpc+" FAIL observed=HTTP_401 reason=node-liveness-unproven\n")
		}},
		{"check/refused-as-pass", func(s string) bool {
			c, out := check(s, refusedPass)
			return c == 1 && strings.Contains(out, " rpc-pass-node-not-listening:"+rpc)
		}},
		{"check/pass-node-not-live", func(s string) bool {
			c, out := check(s, notLive)
			return c == 1 && strings.Contains(out, " rpc-pass-without-live-node")
		}},
		{"check/stand-in-401", func(s string) bool {
			c, out := check(s, standIn401)
			return c == 1 && strings.Contains(out, " rpc-stand-in-without-refused:"+rpc)
		}},
	}
	mutants := []struct{ name, old, repl, killer string }{
		// The r8 mapping: REFUSED is PASS on a live run.
		{"report-refused-pass", `echo "denied-rpc:$rpc FAIL observed=$o reason=node-not-listening"`, `echo "denied-rpc:$rpc PASS observed=$o"`, "report/real-node-stopped"},
		// REFUSED is PASS on a stand-in run.
		{"report-stand-in-refused-pass", `echo "denied-rpc:$rpc STAND_IN observed=$o"`, `echo "denied-rpc:$rpc PASS observed=$o"`, "report/stand-in-refused"},
		// A 401 or 403 passes without node liveness.
		{"report-no-liveness", `if [ "$node_live" != 1 ]; then`, `if false; then`, "report/401-node-not-live"},
		// The r8 check rule: a PASS may show REFUSED.
		{"check-accepts-refused", "if (o == \"REFUSED\") bad(\"rpc-pass-node-not-listening:\" id)\n\t\t\t\telse if (o != \"HTTP_401\" && o != \"HTTP_403\")", "if (o != \"HTTP_401\" && o != \"HTTP_403\" && o != \"REFUSED\")", "check/refused-as-pass"},
		// check drops the liveness binding to node-txindex.
		{"check-no-liveness", `if (rpc_pass && vv["node-txindex"] != "PASS") bad("rpc-pass-without-live-node")`, ``, "check/pass-node-not-live"},
		// check lets a denied-rpc row be STAND_IN for any observation.
		{"check-stand-in-any", `if (v == "STAND_IN" && o != "REFUSED") bad("rpc-stand-in-without-refused:" id)`, ``, "check/stand-in-401"},
	}
	for _, c := range controls {
		if !c.ok(t18rhScript) {
			t.Fatalf("T18RH_MUTANT control %s fails on the runner itself", c.name)
		}
	}
	for _, m := range mutants {
		if strings.Count(string(src), m.old) != 1 {
			t.Fatalf("T18RH_MUTANT %s: the edit matches the runner %d times, want 1", m.name, strings.Count(string(src), m.old))
		}
		script := write(m.name+".sh", strings.Replace(string(src), m.old, m.repl, 1))
		var killed []string
		for _, c := range controls {
			if !c.ok(script) {
				killed = append(killed, c.name)
			}
		}
		t.Logf("T18RH_MUTANT %s killed by %s", m.name, strings.Join(killed, ","))
		found := false
		for _, k := range killed {
			found = found || k == m.killer
		}
		if !found {
			t.Fatalf("T18RH_MUTANT %s survived its control %s", m.name, m.killer)
		}
	}
}

// t18rhLiveCases are the r10 controls on the standard evidence set, shared by
// the control and mutant tests: each edit of the evidence (report) or of the
// valid live report (check) and the line or reason that must name it.
type t18rhLiveCase struct {
	name, wallet string
	edit         func(*testing.T, *t18rhFix)
	code         int
	line         string // regexp that must match a whole line of the report
}

func t18rhLiveReportCases(rpc0, read0 string) []t18rhLiveCase {
	rpcRe, readRe := regexp.QuoteMeta("denied-rpc:"+rpc0), regexp.QuoteMeta("denied-read:"+read0)
	post := func(rpc, start, end, exit, answer string) func(*testing.T, *t18rhFix) {
		return func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/node-post.txt", t18rhCapture(rpc, start, end, exit, answer))
		}
	}
	return []t18rhLiveCase{
		// Claim (valid neighbour): both captures at the target around the
		// probe window, synced, and every denied path in the root-side record
		// with exists=yes: the live run passes, each denied row carrying it.
		{"valid-live", "real", func(*testing.T, *t18rhFix) {}, 0, `^` + rpcRe + ` PASS observed=HTTP_401 ` + regexp.QuoteMeta(t18rhLiveFields(rpc0)) + `$`},
		{"valid-live-stat", "real", func(*testing.T, *t18rhFix) {}, 0, `^` + readRe + ` PASS observed=EACCES ` + regexp.QuoteMeta(t18rhStat(read0)) + `$`},
		// Claim: a post-probe capture on another port does not tie the 401 to
		// a node at the probed target: FAIL capture-port-mismatch.
		{"post-capture-other-port", "real", post("127.0.0.1:8337", t18rhPostStart, t18rhPostEnd, "0", t18rhPostAnswer), 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-port-mismatch pre_rpc=` + regexp.QuoteMeta(rpc0) + ` .* post_rpc=127\.0\.0\.1:8337 `},
		// Claim (neighbour): so does a pre-probe capture on another host.
		{"pre-capture-other-host", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/node-pre.txt", t18rhCapture("127.0.0.2:"+strings.SplitN(rpc0, ":", 2)[1], t18rhPreStart, t18rhPreEnd, "0", t18rhPreAnswer))
		}, 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-port-mismatch pre_rpc=127\.0\.0\.2:`},
		// Claim: a post-probe capture taken before the probe ended (inside the
		// window) does not show the node after the probe: window-not-bracketed.
		{"post-capture-inside-window", "real", post(rpc0, "2026-11-13T10:05:02.000000000Z", "2026-11-13T10:05:02.100000000Z", "0", t18rhPostAnswer), 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=window-not-bracketed `},
		// Claim (neighbour): a pre-probe capture that ended after the probe
		// started is not before it: window-not-bracketed.
		{"pre-capture-after-probe-start", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/node-pre.txt", t18rhCapture(rpc0, t18rhPreStart, "2026-11-13T10:05:00.000000001Z", "0", t18rhPreAnswer))
		}, 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=window-not-bracketed `},
		// Claim: missing times are FAIL capture-time-missing: no probe window,
		// a post capture without its start, a pre answer saved bare (r9 form,
		// no capture), times without nanoseconds.
		{"probe-window-missing", "real", func(t *testing.T, f *t18rhFix) { os.Remove(filepath.Join(f.ag, "probe-window.txt")) }, 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-time-missing .* probe_start=none probe_end=none `},
		{"post-start-missing", "real", func(t *testing.T, f *t18rhFix) {
			f.write(t, "op/node-post.txt", strings.Replace(t18rhCapture(rpc0, t18rhPostStart, t18rhPostEnd, "0", t18rhPostAnswer), "start="+t18rhPostStart+"\n", "", 1))
		}, 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-time-missing .* post_start=none `},
		{"pre-capture-bare-answer", "real", func(t *testing.T, f *t18rhFix) { os.Remove(filepath.Join(f.op, "node-pre.txt")) }, 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-time-missing pre_rpc=none pre_start=none pre_end=none `},
		{"post-times-in-seconds", "real", post(rpc0, "2026-11-13T10:06:00Z", "2026-11-13T10:06:01Z", "0", t18rhPostAnswer), 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-time-missing `},
		// Claim: a post-probe answer that is not synced, or a failed call, is
		// FAIL capture-not-synced.
		{"post-capture-not-synced", "real", post(rpc0, t18rhPostStart, t18rhPostEnd, "0", `{"txindex":{"synced":false,"best_block_height":812346}}`), 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-not-synced `},
		{"post-capture-failed-call", "real", post(rpc0, t18rhPostStart, t18rhPostEnd, "1", ""), 1, `^` + rpcRe + ` FAIL observed=HTTP_401 reason=capture-not-synced .* post_getindexinfo=none$`},
		// Claim: a denied path the root-side record lists as absent is FAIL
		// path-absent; for the status directory status-dir FAILs with it.
		{"path-absent", "real", func(t *testing.T, f *t18rhFix) { f.writeStats(t, map[string]string{read0: "exists=no"}) }, 1, `^` + readRe + ` FAIL observed=EACCES reason=path-absent$`},
		{"status-dir-absent", "real", func(t *testing.T, f *t18rhFix) { f.writeStats(t, map[string]string{G2StatusSocketDir: "exists=no"}) }, 1, `^status-dir FAIL path=/run/swarma-wallet-status observed=EACCES reason=path-absent$`},
		// Claim: a denied path missing from the record (its line dropped, the
		// record absent, or the line twice) is FAIL path-not-in-stat-record.
		{"path-missing-from-record", "real", func(t *testing.T, f *t18rhFix) { f.writeStats(t, map[string]string{read0: ""}) }, 1, `^` + readRe + ` FAIL observed=EACCES reason=path-not-in-stat-record$`},
		{"record-missing", "real", func(t *testing.T, f *t18rhFix) { os.Remove(filepath.Join(f.op, "denied-paths-stat.txt")) }, 1, `^` + readRe + ` FAIL observed=EACCES reason=path-not-in-stat-record$`},
		{"path-twice-in-record", "real", func(t *testing.T, f *t18rhFix) {
			b, _ := os.ReadFile(filepath.Join(f.op, "denied-paths-stat.txt"))
			f.write(t, "op/denied-paths-stat.txt", string(b)+read0+" "+t18rhStat(read0)+"\n")
		}, 1, `^` + readRe + ` FAIL observed=EACCES reason=path-not-in-stat-record$`},
	}
}

// Claim (r10, QA decisions 1 and 2): on a live run (`real`) the composer
// passes a denied-rpc row only with both node captures at the row's target,
// bracketing the probe window, the post-probe answer synced; and a
// denied-read row only when the root-side record lists its path once with
// exists=yes. Every case of t18rhLiveReportCases (each with its own claim)
// gives its named line, exit 1 and OVERALL FAIL, beside the valid live
// neighbours (exit 0, OVERALL PASS). Stand-in unaffected: on a stand-in run
// the r10 evidence is not read: with it removed, or with a capture on another
// port and every path recorded absent, the stand-in report is byte for byte
// the same, still OVERALL PASS with every denial STAND_IN and none PASS.
// Limit: the times are synthetic here; that the agent phase writes the probe
// window is TestT18RealHostAgentPhase's, node-capture's and denied-stat's own
// behaviour TestT18RealHostCaptureAndStatModes'.
func TestT18RealHostLiveAtProbe(t *testing.T) {
	f0 := t18rhFixture(t)
	rpc0, read0 := f0.spec.DeniedRPC[0], f0.spec.DeniedReads[0]
	for _, c := range t18rhLiveReportCases(rpc0, read0) {
		f := t18rhFixture(t)
		c.edit(t, f)
		code, out := f.report(t, c.wallet)
		if code != c.code || !regexp.MustCompile(`(?m)`+c.line).MatchString(out) {
			t.Fatalf("T18RH_LIVE %s: exit %d (want %d), want line %s\n%s", c.name, code, c.code, c.line, out)
		}
		want := "\nOVERALL PASS "
		if c.code != 0 {
			want = "\nOVERALL FAIL "
		}
		if !strings.Contains(out, want) {
			t.Fatalf("T18RH_LIVE %s: no %q\n%s", c.name, want, out)
		}
	}
	// Stand-in unaffected.
	base := t18rhFixture(t)
	code, standIn := base.report(t, "stand-in")
	if code != 0 || !strings.Contains(standIn, "\nOVERALL PASS ") || regexp.MustCompile(`(?m)^(denied-read:\S+|status-dir|allowed-socket) PASS `).MatchString(standIn) ||
		strings.Contains(standIn, " exists=") || strings.Contains(standIn, " pre_rpc=") {
		t.Fatalf("T18RH_LIVE stand-in setup: %d\n%s", code, standIn)
	}
	for name, edit := range map[string]func(*t18rhFix){
		"stand-in-without-r10-evidence": func(f *t18rhFix) {
			for _, p := range []string{filepath.Join(f.op, "node-pre.txt"), filepath.Join(f.op, "node-post.txt"), filepath.Join(f.op, "denied-paths-stat.txt"), filepath.Join(f.ag, "probe-window.txt")} {
				os.Remove(p)
			}
		},
		"stand-in-bad-r10-evidence": func(f *t18rhFix) {
			f.write(t, "op/node-post.txt", t18rhCapture("127.0.0.1:8337", t18rhPostStart, t18rhPostEnd, "0", t18rhPostAnswer))
			over := map[string]string{}
			for _, p := range f.spec.DeniedReads {
				over[p] = "exists=no"
			}
			f.writeStats(t, over)
		},
	} {
		f := t18rhFixture(t)
		edit(f)
		if code, out := f.report(t, "stand-in"); code != 0 || out != standIn {
			t.Fatalf("T18RH_LIVE %s: the stand-in report changed (%d)\n%s", name, code, out)
		}
	}
}

// t18rhLiveCheckCases are the r10 check controls: the valid live report with
// one hand edit, and the named reason check must give.
func t18rhLiveCheckCases(t *testing.T, real, rpc0, read0 string) []struct{ name, text, reason string } {
	t.Helper()
	sub := func(old, repl string) string {
		if strings.Count(real, old) != 1 {
			t.Fatalf("T18RH_LIVE_CHECK edit %q matches %d times", old, strings.Count(real, old))
		}
		return strings.Replace(real, old, repl, 1)
	}
	rpcRow, readRow := "denied-rpc:"+rpc0+" PASS observed=HTTP_401 ", "denied-read:"+read0+" PASS observed=EACCES "
	return []struct{ name, text, reason string }{
		// Claim: a post-probe capture on another port is refused by name.
		{"post-other-port", sub(" post_rpc="+rpc0+" ", " post_rpc=127.0.0.1:8337 "), "rpc-pass-capture-port-mismatch:denied-rpc:" + rpc0},
		// Claim: a post-probe capture taken before the probe ended is refused.
		{"window-not-bracketed", sub(" post_start="+t18rhPostStart+" ", " post_start=2026-11-13T10:05:02.000000000Z "), "rpc-pass-window-not-bracketed:denied-rpc:" + rpc0},
		// Claim: a PASS row without the times (the r9 row) or with a time in
		// another form is refused as capture-time-missing.
		{"times-missing", sub(rpcRow+t18rhLiveFields(rpc0)+"\n", "denied-rpc:"+rpc0+" PASS observed=HTTP_401\n"), "rpc-pass-capture-time-missing:denied-rpc:" + rpc0},
		{"time-in-seconds", sub(" probe_end="+t18rhProbeEnd+" ", " probe_end=2026-11-13T10:05:03Z "), "rpc-pass-capture-time-missing:denied-rpc:" + rpc0},
		// Claim: an unsynced post-probe answer is refused.
		{"post-not-synced", sub(`post_getindexinfo={"txindex":{"synced":true,`, `post_getindexinfo={"txindex":{"synced":false,`), "rpc-pass-capture-not-synced:denied-rpc:" + rpc0},
		// Claim: a denied path recorded absent is refused.
		{"path-absent", sub(readRow+t18rhStat(read0)+"\n", readRow+"exists=no type=regular_file owner=0:0 mode=600\n"), "read-pass-path-absent:denied-read:" + read0},
		// Claim: a denied path without its stat (missing from the record, the
		// r9 row) is refused.
		{"path-not-in-record", sub(readRow+t18rhStat(read0)+"\n", "denied-read:"+read0+" PASS observed=EACCES\n"), "read-pass-not-in-stat-record:denied-read:" + read0},
	}
}

// Claim (r10): check, on a stored live report, refuses each r10 contradiction
// of t18rhLiveCheckCases by its named reason (exit 1, OVERALL FAIL), beside
// the valid live report (exit 0) and the valid stand-in report, which carries
// no r10 field and passes unchanged; the stat record cannot upgrade a stand-in
// denial: a stand-in row relabelled PASS with its stat fields is refused
// (stand-in-placeholder-pass). Limit: check reads the report, not the
// evidence files; that the composer reads the files is TestT18RealHostLiveAtProbe's.
func TestT18RealHostLiveAtProbeCheck(t *testing.T) {
	f := t18rhFixture(t)
	rpc0, read0 := f.spec.DeniedRPC[0], f.spec.DeniedReads[0]
	code, real := f.report(t, "real")
	code2, standIn := f.report(t, "stand-in")
	if code != 0 || code2 != 0 {
		t.Fatal("T18RH_LIVE_CHECK setup", real, standIn)
	}
	for name, text := range map[string]string{"valid-live": real, "valid-stand-in": standIn} {
		if code, out := t18rhCheckFile(t, name, text, f.renderedSpec); code != 0 || out != t18rhLastLine(text) {
			t.Fatalf("T18RH_LIVE_CHECK %s refused: %d\n%s", name, code, out)
		}
	}
	upgraded := strings.Replace(standIn, "\ndenied-read:"+read0+" STAND_IN observed=EACCES\n", "\ndenied-read:"+read0+" PASS observed=EACCES "+t18rhStat(read0)+"\n", 1)
	if upgraded == standIn {
		t.Fatal("T18RH_LIVE_CHECK stand-in edit matched nothing")
	}
	if code, out := t18rhCheckFile(t, "stand-in-upgraded", upgraded, f.renderedSpec); code != 1 || !strings.Contains(out, " stand-in-placeholder-pass:denied-read:"+read0) {
		t.Fatalf("T18RH_LIVE_CHECK a stand-in denial relabelled PASS with its stat: %d\n%s", code, out)
	}
	for _, c := range t18rhLiveCheckCases(t, real, rpc0, read0) {
		code, out := t18rhCheckFile(t, c.name, c.text, f.renderedSpec)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.Contains(out, " "+c.reason) {
			t.Fatalf("T18RH_LIVE_CHECK %s: exit %d, want 1 with %q\n%s", c.name, code, c.reason, out)
		}
	}
}

// Claim (r10, stored testdata): the stored live reports, which predate the
// r10 evidence (testdata/t18-real-host-r3/valid-real.txt with the r4 hash line
// inserted, and testdata/t18-real-host-r4/valid-real.txt), are refused by
// check as stored, exit 1, with exactly these r10 reasons: every denied-read
// row read-pass-not-in-stat-record, and the denied-rpc row
// rpc-pass-capture-port-mismatch, rpc-pass-capture-time-missing and
// rpc-pass-capture-not-synced (it carries no capture at all), each row beside
// fields: (it lacks its r10 fields), and the stated OVERALL PASS disagrees. The stored stand-in report (r3) still passes: stand-in runs
// are unchanged. The same reports with the r10 evidence (t18rhLive) pass.
func TestT18RealHostStoredLiveRefused(t *testing.T) {
	f := t18rhFixture(t)
	specFile, e := os.ReadFile(f.renderedSpec)
	if e != nil {
		t.Fatal(e)
	}
	r4, e := os.ReadFile(filepath.Join(t18rhR4, "valid-real.txt"))
	if e != nil {
		t.Fatal(e)
	}
	var want strings.Builder
	want.WriteString("# reasons:")
	for _, p := range f.spec.DeniedReads {
		want.WriteString(" fields:denied-read:" + p + " read-pass-not-in-stat-record:denied-read:" + p)
	}
	rpc := "denied-rpc:" + f.spec.DeniedRPC[0]
	want.WriteString(" fields:" + rpc + " rpc-pass-capture-port-mismatch:" + rpc + " rpc-pass-capture-time-missing:" + rpc + " rpc-pass-capture-not-synced:" + rpc + " stated-overall-disagrees\n")
	for name, text := range map[string]string{
		"r3/valid-real.txt": t18rhWithHash(t18rhRead(t, "valid-real.txt"), t18rhSha(specFile)),
		"r4/valid-real.txt": string(r4),
	} {
		code, out := t18rhCheckFile(t, "stored", text, f.renderedSpec)
		t.Logf("T18RH_STORED %s as stored: exit %d\n%s", name, code, out)
		if code != 1 || !strings.HasPrefix(out, "OVERALL FAIL ") || !strings.HasSuffix(out, want.String()+"# stated OVERALL PASS disagrees\n") {
			t.Fatalf("T18RH_STORED %s as stored: exit %d, want 1 with %q\n%s", name, code, want.String(), out)
		}
		if code, out := t18rhCheckFile(t, "live", t18rhLive(text), f.renderedSpec); code != 0 {
			t.Fatalf("T18RH_STORED %s with the r10 evidence: exit %d\n%s", name, code, out)
		}
	}
	standIn := t18rhWithHash(t18rhRead(t, "valid-stand-in.txt"), t18rhSha(specFile))
	if code, out := t18rhCheckFile(t, "stored-stand-in", standIn, f.renderedSpec); code != 0 {
		t.Fatalf("T18RH_STORED r3/valid-stand-in.txt: exit %d\n%s", code, out)
	}
}

// Claim (r10, mutants of the liveness-at-probe and denied-path existence
// rules): every control below passes on this runner, and each mutant, one
// textual edit that drops the port check, the bracket check or the
// stat-record check from the composer or from check, is killed by its named
// control. A mutant whose edit matches the source other than exactly once
// fails the test. The kill matrix is logged. Limit: one mutant per rule part
// and side; the capture-time and not-synced reasons are covered by the
// control tests, not by a mutant here.
func TestT18RealHostLiveAtProbeMutants(t *testing.T) {
	kit := t18rhKit(t)
	src, e := os.ReadFile(t18rhScript)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	f := t18rhFixture(t)
	rpc0, read0 := f.spec.DeniedRPC[0], f.spec.DeniedReads[0]
	code, real := f.report(t, "real")
	if code != 0 {
		t.Fatal("T18RH_LIVE_MUTANT setup", real)
	}
	checks := map[string]string{}
	for _, c := range t18rhLiveCheckCases(t, real, rpc0, read0) {
		path := filepath.Join(dir, c.name+".txt")
		if e := os.WriteFile(path, []byte(c.text), 0600); e != nil {
			t.Fatal(e)
		}
		checks[c.name] = path
	}
	reports := map[string]*t18rhFix{}
	lines := map[string]string{}
	for _, c := range t18rhLiveReportCases(rpc0, read0) {
		g := t18rhFixture(t)
		c.edit(t, g)
		reports[c.name], lines[c.name] = g, c.line
	}
	reportCtl := func(name string, want int) func(string) bool {
		return func(s string) bool {
			g := reports[name]
			c, out := t18rhRunScript(t, s, kit, "report", g.op, g.ag, g.rendered, g.params, "real")
			return c == want && regexp.MustCompile(`(?m)`+lines[name]).MatchString(out)
		}
	}
	checkCtl := func(name, reason string) func(string) bool {
		return func(s string) bool {
			c, out := t18rhRunScript(t, s, kit, "check", checks[name], f.renderedSpec)
			return c == 1 && strings.Contains(out, " "+reason)
		}
	}
	controls := []struct {
		name string
		ok   func(string) bool
	}{
		{"report/valid-live", reportCtl("valid-live", 0)},
		{"report/post-capture-other-port", reportCtl("post-capture-other-port", 1)},
		{"report/post-capture-inside-window", reportCtl("post-capture-inside-window", 1)},
		{"report/path-absent", reportCtl("path-absent", 1)},
		{"report/path-missing-from-record", reportCtl("path-missing-from-record", 1)},
		{"check/post-other-port", checkCtl("post-other-port", "rpc-pass-capture-port-mismatch:denied-rpc:"+rpc0)},
		{"check/window-not-bracketed", checkCtl("window-not-bracketed", "rpc-pass-window-not-bracketed:denied-rpc:"+rpc0)},
		{"check/path-absent", checkCtl("path-absent", "read-pass-path-absent:denied-read:"+read0)},
		{"check/path-not-in-record", checkCtl("path-not-in-record", "read-pass-not-in-stat-record:denied-read:"+read0)},
	}
	mutants := []struct{ name, old, repl, killer string }{
		// The composer drops the port check: a capture at another port passes.
		{"report-no-port", `if [ -z "$why" ] && { [ "$l_pr" != "$rpc" ] || [ "$l_qr" != "$rpc" ]; }; then`, `if false; then`, "report/post-capture-other-port"},
		// The composer drops the bracket check: any capture time passes.
		{"report-no-bracket", `if [ -z "$why" ] && ! ordered`, `if false && ! ordered`, "report/post-capture-inside-window"},
		// The composer drops the stat record: every denial is taken as existing.
		{"report-no-stat", `sr=$(stat_rec "$p" "$statrec")`, `sr="exists=yes type=regular_file owner=0:0 mode=600"`, "report/path-absent"},
		// check drops the port check.
		{"check-no-port", `if (fv["pre_rpc"] != tgt || fv["post_rpc"] != tgt) bad("rpc-pass-capture-port-mismatch:" id)`, ``, "check/post-other-port"},
		// check drops the bracket check.
		{"check-no-bracket", `else if (!(fv["pre_start"] <= fv["pre_end"] && fv["pre_end"] <= fv["probe_start"] && fv["probe_start"] <= fv["probe_end"] && fv["probe_end"] <= fv["post_start"] && fv["post_start"] <= fv["post_end"])) bad("rpc-pass-window-not-bracketed:" id)`, ``, "check/window-not-bracketed"},
		// check drops the stat-record check (the schema still asks for the fields).
		{"check-no-stat", "if (wallet == \"real\" && v == \"PASS\") {\n\t\t\t\tif (!(\"exists\" in fv))", "if (0) {\n\t\t\t\tif (!(\"exists\" in fv))", "check/path-absent"},
	}
	for _, c := range controls {
		if !c.ok(t18rhScript) {
			t.Fatalf("T18RH_LIVE_MUTANT control %s fails on the runner itself", c.name)
		}
	}
	for _, m := range mutants {
		if n := strings.Count(string(src), m.old); n != 1 {
			t.Fatalf("T18RH_LIVE_MUTANT %s: the edit matches the runner %d times, want 1", m.name, n)
		}
		path := filepath.Join(dir, m.name+".sh")
		if e := os.WriteFile(path, []byte(strings.Replace(string(src), m.old, m.repl, 1)), 0600); e != nil {
			t.Fatal(e)
		}
		var killed []string
		for _, c := range controls {
			if !c.ok(path) {
				killed = append(killed, c.name)
			}
		}
		t.Logf("T18RH_LIVE_MUTANT %s killed by %s", m.name, strings.Join(killed, ","))
		found := false
		for _, k := range killed {
			found = found || k == m.killer
		}
		if !found {
			t.Fatalf("T18RH_LIVE_MUTANT %s survived its control %s", m.name, m.killer)
		}
	}
}

// Claim (r10, the operator modes): node-capture makes exactly one node call,
// `CLI <allowed options> -rpcconnect=HOST -rpcport=PORT getindexinfo txindex`,
// against the spec's one denied_rpc target, and writes the capture (header,
// rpc, start <= end in the nanosecond UTC form, exit, the answer without white
// space); a failed call is kept with its exit and the mode exits 1. It refuses
// (64, no call, no file) any other option, a positional argument (a method),
// -getinfo, the operator's own -rpcport, an existing output file and a spec
// with two denied_rpc entries, and never prints a refused option's value.
// The operator phase keeps a capture whole as node-pre.txt and takes its
// answer as txindex.json only when the call exited 0. denied-stat prints one
// line per denied path in spec order: exists=yes with type, owner and mode
// for a file and a directory, exists=no for a missing path and a dangling
// link. Limit: the CLI is a stand-in script; a real namecoin-cli's option
// precedence (the last -rpcport wins) is Bitcoin Core's documented
// command-line behaviour, not exercised here.
func TestT18RealHostCaptureAndStatModes(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "custody-spec.json")
	file, sub, missing, dangling := filepath.Join(dir, "secret"), filepath.Join(dir, "state"), filepath.Join(dir, "absent"), filepath.Join(dir, "link")
	os.WriteFile(file, []byte("x"), 0600)
	os.Mkdir(sub, 0700)
	os.Symlink(filepath.Join(dir, "nowhere"), dangling)
	writeSpec := func(path string, rpcs string) {
		os.WriteFile(path, []byte(`{"v":1,"agent_uid":1201,"service_uid":1101,"denied_reads":["`+file+`","`+sub+`","`+missing+`","`+dangling+`"],"denied_rpc":[`+rpcs+`],"allowed_socket":"/run/swarma-wallet/wallet.sock"}`+"\n"), 0600)
	}
	writeSpec(spec, `"127.0.0.1:8336"`)
	argv := filepath.Join(dir, "argv")
	cli := filepath.Join(dir, "namecoin-cli")
	os.WriteFile(cli, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >\""+argv+"\"\nprintf '{\\n  \"txindex\": {\"synced\": true, \"best_block_height\": 9}\\n}\\n'\nexit ${FAKE_EXIT:-0}\n"), 0700)
	out := filepath.Join(dir, "pre.txt")
	code, msg := t18rhRun(t, nil, "node-capture", out, spec, "--", cli, "-datadir=/var/lib/namecoind-main", "-rpccookiefile=/var/lib/namecoind-main/.cookie")
	b, _ := os.ReadFile(out)
	m := regexp.MustCompile(`^T18-NODE-CAPTURE v1\nrpc=127\.0\.0\.1:8336\nstart=(\S+)\nend=(\S+)\nexit=0\nanswer=\{"txindex":\{"synced":true,"best_block_height":9\}\}\n$`).FindStringSubmatch(string(b))
	ts := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$`)
	if code != 0 || m == nil || !ts.MatchString(m[1]) || !ts.MatchString(m[2]) || m[1] > m[2] || !strings.HasPrefix(msg, "T18_REAL_HOST_NODE_CAPTURE_DONE exit=0 ") {
		t.Fatalf("T18RH_MODES node-capture: %d %q\n%s", code, msg, b)
	}
	if a, _ := os.ReadFile(argv); string(a) != "-datadir=/var/lib/namecoind-main\n-rpccookiefile=/var/lib/namecoind-main/.cookie\n-rpcconnect=127.0.0.1\n-rpcport=8336\ngetindexinfo\ntxindex\n" {
		t.Fatalf("T18RH_MODES node-capture call %q", a)
	}
	// The operator phase keeps the capture and takes its answer.
	kit := t18rhKit(t)
	files, _ := RenderG2PayTemplates(g2Params())
	rendered, params := filepath.Join(dir, "rendered"), filepath.Join(dir, "parameters.json")
	os.Mkdir(rendered, 0700)
	for name, c := range files {
		os.WriteFile(filepath.Join(rendered, name), c, 0600)
	}
	rawParams, _ := json.Marshal(g2Params())
	os.WriteFile(params, append(rawParams, '\n'), 0600)
	op := filepath.Join(dir, "op")
	if code, msg := t18rhRun(t, []string{"DEPLOY_KIT=" + kit}, "operator", op, params, rendered, out); code != 0 {
		t.Fatalf("T18RH_MODES operator phase: %d\n%s", code, msg)
	}
	if pre, _ := os.ReadFile(filepath.Join(op, "node-pre.txt")); string(pre) != string(b) {
		t.Fatalf("T18RH_MODES node-pre.txt %q", pre)
	}
	if tx, _ := os.ReadFile(filepath.Join(op, "txindex.json")); string(tx) != `{"txindex":{"synced":true,"best_block_height":9}}` {
		t.Fatalf("T18RH_MODES txindex.json %q", tx)
	}
	// A failed call: kept with its exit, mode exit 1, and no answer for node-txindex.
	failed := filepath.Join(dir, "failed.txt")
	if code, _ := t18rhRun(t, []string{"FAKE_EXIT=1"}, "node-capture", failed, spec, "--", cli); code != 1 {
		t.Fatalf("T18RH_MODES failed call exit %d", code)
	}
	if fb, _ := os.ReadFile(failed); !strings.Contains(string(fb), "\nexit=1\n") {
		t.Fatalf("T18RH_MODES failed capture %q", fb)
	}
	op2 := filepath.Join(dir, "op2")
	t18rhRun(t, []string{"DEPLOY_KIT=" + kit}, "operator", op2, params, rendered, failed)
	if tx, e := os.ReadFile(filepath.Join(op2, "txindex.json")); e != nil || len(tx) != 0 {
		t.Fatalf("T18RH_MODES a failed pre capture gave txindex.json %q %v", tx, e)
	}
	// Refusals: nothing runs, nothing is written, the value is not printed.
	two := filepath.Join(dir, "two-rpc.json")
	writeSpec(two, `"127.0.0.1:8336","127.0.0.1:8337"`)
	for name, args := range map[string][]string{
		"password-option": {spec, "--", cli, "-rpcpassword=hunter2-not-a-secret"},
		"method":          {spec, "--", cli, "getbalance"},
		"getinfo":         {spec, "--", cli, "-getinfo"},
		"own-port":        {spec, "--", cli, "-rpcport=18336"},
		"no-separator":    {spec, cli},
		"two-targets":     {two, "--", cli},
	} {
		os.Remove(argv)
		o := filepath.Join(dir, "refused-"+name+".txt")
		code, msg := t18rhRun(t, nil, append([]string{"node-capture", o}, args...)...)
		if _, e := os.Stat(argv); code != 64 || e == nil || strings.Contains(msg, "hunter2") {
			t.Fatalf("T18RH_MODES %s: exit %d, called=%v\n%s", name, code, e == nil, msg)
		}
		if _, e := os.Stat(o); e == nil {
			t.Fatalf("T18RH_MODES %s wrote %s", name, o)
		}
	}
	if code, _ := t18rhRun(t, nil, "node-capture", out, spec, "--", cli); code != 64 {
		t.Fatalf("T18RH_MODES an existing capture was not refused: %d", code)
	}
	if after, _ := os.ReadFile(out); string(after) != string(b) {
		t.Fatal("T18RH_MODES an existing capture was overwritten")
	}
	// denied-stat.
	code, stat := t18rhRun(t, nil, "denied-stat", spec)
	u, g := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	want := file + " exists=yes type=regular_file owner=" + u + ":" + g + " mode=600\n" + sub + " exists=yes type=directory owner=" + u + ":" + g + " mode=700\n" + missing + " exists=no\n" + dangling + " exists=no\n"
	if code != 0 || stat != want {
		t.Fatalf("T18RH_MODES denied-stat: %d\n got %q\nwant %q", code, stat, want)
	}
}
