//go:build linux

package g2run

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"golang.org/x/sys/unix"
)

// portHostFixture models E2 capabilities; actual file bytes/modes are exercised,
// while uid/gid effects are modeled because this suite runs without root. This
// is orchestration evidence, not qualification of the unavailable E2 adapters.
type portHostFixture struct {
	t                         *testing.T
	fs                        PortFS
	events                    []string
	lookup                    map[PortLookup]Result
	groupSet                  []PortNamedID
	unit                      map[string]PortUnitInfo
	rows                      []PortUnitRow
	uids                      []uint32
	listeners                 []string
	owners                    map[string][2]uint32
	fail                      string
	verifyRC, engineRC        int
	engineOutput              string
	keepPID, ignoreMembership bool
	status                    string
	a                         *Activation
}

func newPortHost(t *testing.T, fs PortFS) *portHostFixture {
	return &portHostFixture{t: t, fs: fs, lookup: map[PortLookup]Result{}, groupSet: []PortNamedID{{Name: "operator", ID: 1000}}, unit: map[string]PortUnitInfo{}, uids: []uint32{0, 1000}, listeners: []string{"127.0.0.1:9000", "/run/example.sock", "127.0.0.1:9000"}, owners: map[string][2]uint32{}}
}
func (h *portHostFixture) event(s string) error {
	h.events = append(h.events, s)
	if h.fail == s {
		return errors.New("FIXTURE_FAILURE " + s)
	}
	return nil
}
func (h *portHostFixture) Lookup(_ *Ctx, q PortLookup) (Result, error) {
	if e := h.event("lookup " + string(q.Database) + " " + q.Key); e != nil {
		return Result{}, e
	}
	if r, ok := h.lookup[q]; ok {
		return r, nil
	}
	return Result{RC: 2}, nil
}
func (h *portHostFixture) addUser(name string, id, gid uint32) {
	r := Result{Stdout: []byte(fmt.Sprintf("%s:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", name, id, gid))}
	h.lookup[PortLookup{PortPasswd, name}] = r
	h.lookup[PortLookup{PortPasswd, strconv.FormatUint(uint64(id), 10)}] = r
}
func (h *portHostFixture) addGroup(name string, id uint32) {
	r := Result{Stdout: []byte(fmt.Sprintf("%s:x:%d:\n", name, id))}
	h.lookup[PortLookup{PortGroup, name}] = r
	h.lookup[PortLookup{PortGroup, strconv.FormatUint(uint64(id), 10)}] = r
}
func (h *portHostFixture) Groups(_ *Ctx, user string) ([]PortNamedID, error) {
	if e := h.event("groups " + user); e != nil {
		return nil, e
	}
	return append([]PortNamedID(nil), h.groupSet...), nil
}
func (h *portHostFixture) UnitInfo(_ *Ctx, u string) (PortUnitInfo, error) {
	if e := h.event("unit " + u); e != nil {
		return PortUnitInfo{}, e
	}
	if s, ok := h.unit[u]; ok {
		return s, nil
	}
	return PortUnitInfo{LoadState: "not-found", ActiveState: "inactive"}, nil
}
func (h *portHostFixture) Start(_ *Ctx, u string) error {
	if h.a != nil {
		info, e := os.Stat(h.a.Stage + "/started-" + u)
		if e != nil || info.Mode().Perm() != 0600 || info.Size() != 0 {
			h.t.Fatal("start before durable private receipt")
		}
	}
	if e := h.event("start " + u); e != nil {
		return e
	}
	s := h.unit[u]
	s.ActiveState = "active"
	s.MainPID = 42
	h.unit[u] = s
	return nil
}
func (h *portHostFixture) Stop(_ *Ctx, u string) error {
	if e := h.event("stop " + u); e != nil {
		return e
	}
	if !h.keepPID {
		s := h.unit[u]
		s.ActiveState = "inactive"
		s.MainPID = 0
		h.unit[u] = s
	}
	return nil
}
func (h *portHostFixture) Reload(_ *Ctx) error { return h.event("reload") }
func (h *portHostFixture) Listeners(_ *Ctx) ([]string, error) {
	if e := h.event("listeners"); e != nil {
		return nil, e
	}
	return h.listeners, nil
}
func (h *portHostFixture) Units(_ *Ctx) ([]PortUnitRow, error) {
	if e := h.event("units"); e != nil {
		return nil, e
	}
	return h.rows, nil
}
func (h *portHostFixture) ProcessUIDs(_ *Ctx) ([]uint32, error) {
	if e := h.event("processes"); e != nil {
		return nil, e
	}
	return h.uids, nil
}
func (h *portHostFixture) Verify(_ *Ctx, _ string) (int, error) {
	e := h.event("verify")
	return h.verifyRC, e
}
func (h *portHostFixture) Rollback(_ *Ctx, _, mode string, out io.Writer) (int, error) {
	if e := h.event("engine " + mode); e != nil {
		return 0, e
	}
	_, e := io.WriteString(out, h.engineOutput)
	return h.engineRC, e
}
func (h *portHostFixture) Apply(_ *Ctx, _ string, v PortLedgerChange) error {
	if e := v.Validate(); e != nil {
		return e
	}
	if e := h.event("ledger " + v.Kind + " " + v.Path); e != nil {
		return e
	}
	if v.Kind == "add-member" {
		if !h.ignoreMembership {
			h.groupSet = append(h.groupSet, PortNamedID{Name: v.Group, ID: h.a.StatusGID})
		}
		return nil
	}
	if v.Kind == "create-dir" {
		if _, e := os.Lstat(v.Path); errors.Is(e, os.ErrNotExist) {
			if e = os.Mkdir(v.Path, os.FileMode(v.Mode)); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if e := os.Chmod(v.Path, os.FileMode(v.Mode)); e != nil {
			return e
		}
	} else {
		raw, e := h.fs.read(v.Source)
		if e != nil {
			return e
		}
		if e = h.fs.writeAtomic(v.Path, raw, v.Mode); e != nil {
			return e
		}
	}
	h.owners[v.Path] = [2]uint32{v.UID, v.GID}
	return nil
}
func (h *portHostFixture) Expect(_ *Ctx, s PortStatExpectation) error {
	if e := h.event("stat " + s.Path); e != nil {
		return e
	}
	f, e := h.fs.open(s.Path, unix.O_RDONLY, s.Directory)
	if e != nil {
		return e
	}
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &st); e != nil {
		return e
	}
	if h.owners[s.Path] != [2]uint32{s.UID, s.GID} || st.Mode&07777 != s.Mode || s.Links != 0 && st.Nlink != s.Links || s.NonEmpty && st.Size == 0 {
		return errors.New("FIXTURE_STAT_MISMATCH")
	}
	return nil
}
func (h *portHostFixture) Create(_ *Ctx, _ string) error {
	if e := h.event("tmpfiles"); e != nil {
		return e
	}
	if h.a == nil {
		return errors.New("fixture activation missing")
	}
	portMkdir(h.t, h.a.Status)
	if e := os.Chmod(h.a.Status, 0750); e != nil {
		return e
	}
	h.owners[h.a.Status] = [2]uint32{h.a.ServiceUID, h.a.StatusGID}
	return nil
}
func (h *portHostFixture) CheckInstalled(c *Ctx, q PortInstalledCheck) error {
	if e := h.event("installed"); e != nil {
		return e
	}
	if e := h.fs.writeAtomic(c.State+"/"+q.Output, nil, 0600); e != nil {
		return e
	}
	if c.Exec == nil {
		return errors.New("fixture executor missing")
	}
	_, e := c.Exec.Run(Cmd{Program: "agent-walletd", Args: []string{"--check-installed"}, Stdout: q.Output, Merge: true, Cred: &q.Credential})
	return e
}

type portExecRecorder struct {
	commands []Cmd
	failure  error
}

func (r *portExecRecorder) Run(c Cmd) (Result, error) {
	r.commands = append(r.commands, c)
	return Result{}, r.failure
}
func portContains(events []string, event string) bool {
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}
func requirePortError(t *testing.T, e error, want string) {
	t.Helper()
	if e == nil || e.Error() != want {
		t.Fatalf("error=%v want=%s", e, want)
	}
}

func baselineFixture(t *testing.T, purpose string) (Baseline, *Ctx, *portHostFixture) {
	fs, root := portFS(t)
	portMkdir(t, root+"/state")
	portMkdir(t, root+"/live/directory")
	portWrite(t, root+"/live/directory/entry", []byte("evidence"))
	h := newPortHost(t, fs)
	h.addUser("operator", 1000, 1000)
	h.addGroup("operator", 1000)
	b := Baseline{FS: fs, Out: root + "/state/baseline", Purpose: purpose, Operator: "operator", Dirs: []string{root + "/live/directory", root + "/live/absent"}, Users: []string{"service"}, Groups: []string{"service"}, IDs: []uint32{17}, Units: []string{"wallet.service", "slot.service"}, Deps: BaselineDeps{h, h, h, h}}
	if purpose == "station" {
		portWrite(t, root+"/live/node.conf", []byte("rpcauth=example\n"))
		portWrite(t, root+"/live/node-cli", []byte("not executed\n"))
		if e := os.Chmod(root+"/live/node-cli", 0755); e != nil {
			t.Fatal(e)
		}
		b.Node = &BaselineNode{Unit: "node.service", Config: root + "/live/node.conf", CLI: root + "/live/node-cli"}
		h.unit["node.service"] = PortUnitInfo{LoadState: "loaded", ActiveState: "active", MainPID: 42}
	}
	return b, &Ctx{State: root + "/state", Out: io.Discard}, h
}

// Claim: the source's baseline positive, first-failure and node-exclusion rules
// hold. Evidence filenames/modes and sorted listeners are checked on real files;
// station config with a plaintext credential is refused before any copy.
func TestBaselinePort(t *testing.T) {
	for _, tc := range []struct{ name, purpose, mutation, refusal string }{{"POS-D15-2-baseline-rehearsal-completes", "rehearsal", "", ""}, {"NEG-D15-2-baseline-stops-at-first-failure", "rehearsal", "lookup", "LOOKUP_READ"}, {"NEG-D16-1-rehearsal-no-node-read", "rehearsal", "", ""}, {"POS-baseline-station-evidence", "station", "", ""}, {"NEG-baseline-plaintext-config", "station", "credential", "BASELINE_PLAINTEXT_CREDENTIAL"}, {"NEG-baseline-unit-read-failure", "rehearsal", "unit", "UNIT_READ"}, {"NEG-baseline-listeners-failure", "rehearsal", "listeners", "BASELINE_LISTENERS"}, {"NEG-baseline-inventory-failure", "rehearsal", "units", "UNIT_INVENTORY"}} {
		t.Run(tc.name, func(t *testing.T) {
			b, c, h := baselineFixture(t, tc.purpose)
			if tc.mutation == "lookup" {
				h.fail = "lookup passwd 17"
			}
			if tc.mutation == "unit" {
				h.fail = "unit wallet.service"
			}
			if tc.mutation == "listeners" {
				h.fail = "listeners"
			}
			if tc.mutation == "units" {
				h.fail = "units"
			}
			if tc.mutation == "credential" {
				portWrite(t, b.Node.Config, []byte(" \tmain.rpcpassword = forbidden-test-fixture\n"))
			}
			e := b.Do(c)
			if tc.refusal != "" {
				requirePortError(t, e, tc.refusal)
				if _, err := os.Lstat(b.Out + "/taken-at.txt"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failure wrote completion timestamp")
				}
				raw, _ := os.ReadFile(b.Out + "/errors.txt")
				if !bytes.Contains(raw, []byte("BASELINE_INCOMPLETE")) {
					t.Fatal("failure not recorded")
				}
				if tc.mutation == "lookup" && (portContains(h.events, "listeners") || portContains(h.events, "units")) {
					t.Fatal("continued after first failed read")
				}
				if tc.mutation == "credential" {
					if _, e := os.Lstat(b.Out + "/namecoin.conf"); !errors.Is(e, os.ErrNotExist) {
						t.Fatal("plaintext copied")
					}
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"errors.txt", "accounts.txt", "listen-local.txt", "units.txt", "taken-at.txt", "ls/" + baselineName(b.Dirs[0]), "ls/" + baselineName(b.Dirs[1]), "meta/" + baselineName(b.Dirs[0])} {
				st, e := os.Stat(b.Out + "/" + name)
				if e != nil || st.Mode().Perm() != 0600 {
					t.Fatal(name, st, e)
				}
			}
			raw, e := os.ReadFile(b.Out + "/errors.txt")
			if e != nil || len(raw) != 0 {
				t.Fatal("success errors", e)
			}
			raw, _ = os.ReadFile(b.Out + "/listen-local.txt")
			if string(raw) != "/run/example.sock\n127.0.0.1:9000\n" {
				t.Fatal(string(raw))
			}
			if tc.purpose == "rehearsal" {
				for _, event := range h.events {
					if strings.Contains(event, "node") {
						t.Fatal("rehearsal read node", event)
					}
				}
				if _, e := os.Stat(b.Out + "/meta/node-skipped.txt"); e != nil {
					t.Fatal(e)
				}
			} else {
				for _, name := range []string{"namecoin.conf", "namecoin.conf.meta", "namecoin.conf.sha256", "meta/unit-node.service.txt", "meta/node-user.txt", "meta/node-cli.txt"} {
					if _, e := os.Stat(b.Out + "/" + name); e != nil {
						t.Fatal(name, e)
					}
				}
			}
		})
	}
}

// Claim: getent absence is only exit 2 with empty stdout, and neither malformed
// records, operational errors, wrong keys nor non-decimal IDs count as absence.
func TestPortLookupContract(t *testing.T) {
	for _, tc := range []struct {
		name         string
		rc           int
		out, refusal string
		absent       bool
	}{{"present", 0, "service:x:17:18::/nonexistent:/usr/sbin/nologin\n", "", false}, {"absent", 2, "", "", true}, {"status", 97, "", "LOOKUP_STATUS", false}, {"valid-output-then-failure", 97, "service:x:17:18::/nonexistent:/usr/sbin/nologin\n", "LOOKUP_STATUS", false}, {"absence-with-output", 2, "service\n", "LOOKUP_STATUS", false}, {"multiple", 0, "service:x:17:18::/:/bin/false\nsecond\n", "LOOKUP_RECORD_COUNT", false}, {"shape", 0, "service:x:17\n", "LOOKUP_SHAPE", false}, {"wrong-key", 0, "other:x:17:18::/:/bin/false\n", "LOOKUP_KEY_MISMATCH", false}, {"expression", 0, "service:x:17+1:18::/:/bin/false\n", "LOOKUP_ID", false}, {"negative-gid", 0, "service:x:17:-1::/:/bin/false\n", "LOOKUP_GID", false}} {
		t.Run(tc.name, func(t *testing.T) {
			fs, _ := portFS(t)
			h := newPortHost(t, fs)
			q := PortLookup{PortPasswd, "service"}
			h.lookup[q] = Result{RC: tc.rc, Stdout: []byte(tc.out)}
			got, e := lookupPort(&Ctx{}, h, q)
			if tc.refusal != "" {
				requirePortError(t, e, tc.refusal)
				return
			}
			if e != nil || (got == nil) != tc.absent {
				t.Fatal(got, e)
			}
		})
	}
}

func activationFixture(t *testing.T, purpose string) (Activation, *Ctx, *portHostFixture, *portExecRecorder) {
	fs, root := portFS(t)
	for _, d := range []string{"release/templates/systemd", "release/bin", "state/stage", "state/log", "state/ledger", "rendered", "live/config/wallet", "live/status-parent", "live/keys", "live/unit", "live/opt", "live/data"} {
		portMkdir(t, root+"/"+d)
	}
	a := Activation{FS: fs, Purpose: purpose, Release: root + "/release", Stage: root + "/state/stage", Log: root + "/state/log", Ledger: root + "/state/ledger", Rendered: root + "/rendered", ConfigParent: root + "/live/config", Wallet: root + "/live/config/wallet", Status: root + "/live/status-parent/status", AgentKey: root + "/live/keys/agent.key", StationAgentKey: root + "/live/keys/agent.key", RehearsalAgentKey: root + "/live/keys/rehearsal.key", TmpfilesConf: root + "/live/tmpfiles.conf", VersionParent: root + "/live/opt/app", VersionRoot: root + "/live/opt/app/wallet", UnitDirectory: root + "/live/unit", Unit: "wallet.service", DataDirs: []string{root + "/live/data"}, ServiceUser: "service", PeerGroup: "peer", StatusGroup: "status", AgentUser: "client", Operator: "operator", ServiceUID: 17, ServiceGID: 18, PeerGID: 19, StatusGID: 20, AgentUID: 21, AgentGID: 21}
	if purpose == "rehearsal" {
		a.AgentKey = a.RehearsalAgentKey
	}
	h := newPortHost(t, fs)
	h.a = &a
	h.addUser(a.ServiceUser, a.ServiceUID, a.ServiceGID)
	h.addUser(a.AgentUser, a.AgentUID, a.AgentGID)
	h.addGroup(a.PeerGroup, a.PeerGID)
	h.addGroup(a.StatusGroup, a.StatusGID)
	h.status = a.Status
	a.Deps = ActivationDeps{h, h, h, h, h, h, h}
	h.a = &a
	for _, v := range []struct {
		p        string
		mode     os.FileMode
		uid, gid uint32
	}{{a.ConfigParent, 0755, 0, 0}, {a.Wallet, 0750, 0, a.ServiceGID}, {a.DataDirs[0], 0700, a.ServiceUID, a.ServiceGID}, {filepath.Dir(a.AgentKey), 0755, 0, 0}} {
		if e := os.Chmod(v.p, v.mode); e != nil {
			t.Fatal(e)
		}
		h.owners[v.p] = [2]uint32{v.uid, v.gid}
	}
	for _, n := range []string{"receipt.key", "wallet.json"} {
		portWrite(t, a.Wallet+"/"+n, []byte(n))
		if e := os.Chmod(a.Wallet+"/"+n, 0640); e != nil {
			t.Fatal(e)
		}
		h.owners[a.Wallet+"/"+n] = [2]uint32{0, a.ServiceGID}
	}
	portWrite(t, a.AgentKey, []byte("fixture-only-key"))
	h.owners[a.AgentKey] = [2]uint32{a.AgentUID, a.AgentGID}
	portWrite(t, a.Rendered+"/service.json", []byte("service.json"))
	portWrite(t, a.Rendered+"/tmpfiles.conf", []byte("fixture tmpfiles configuration\n"))
	commit := strings.Repeat("a", 40)
	h12 := commit[:12]
	binary := a.VersionRoot + "/" + h12 + "/bin/agent-walletd"
	unit := []byte("[Service]\nExecStart=" + a.VersionRoot + "/@VERSION@/bin/agent-walletd\n[Install]\nWantedBy=multi-user.target\n")
	status := []byte("[Service]\nExecStart=" + a.VersionRoot + "/@VERSION@/bin/agent-walletd -status-socket " + a.Status + "/status.sock -status-gid @OPERATOR_GID@\n")
	files := map[string][]byte{"templates/systemd/swarma-wallet.service.in": unit, "templates/systemd/swarma-wallet-g2-status.conf.in": status, "bin/agent-walletd": []byte("fixture binary; never executed\n")}
	var sums strings.Builder
	keys := []string{}
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		portWrite(t, a.Release+"/"+key, files[key])
		fmt.Fprintf(&sums, "%s  %s\n", portDigestBytes(files[key]), key)
	}
	portWrite(t, a.Release+"/SHA256SUMS", []byte(sums.String()))
	manifest, _ := json.Marshal(map[string]any{"commit": commit, "artifacts": []any{map[string]string{"binary": "bin/agent-walletd", "sha256": portDigestBytes(files["bin/agent-walletd"])}}})
	portWrite(t, a.Release+"/manifest.json", manifest)
	portWrite(t, a.Stage+"/"+a.Unit, bytes.ReplaceAll(unit, []byte("@VERSION@"), []byte(h12)))
	approved := map[string]string{}
	for _, n := range []string{"receipt.key", "service.json", "wallet.json"} {
		approved[a.Wallet+"/"+n] = portDigestBytes([]byte(n))
	}
	raw, _ := json.Marshal(approved)
	portWrite(t, a.Stage+"/approved-hashes.json", raw)
	h.unit[a.Unit] = PortUnitInfo{LoadState: "loaded", ActiveState: "inactive", ExecStartPre: "{ path=" + binary + " ; argv[]=" + binary + " --check-installed ; }", ExecStart: "{ path=" + binary + " ; argv[]=" + binary + " -status-socket " + a.Status + "/status.sock -status-gid " + strconv.FormatUint(uint64(a.StatusGID), 10) + " ; }"}
	exec := &portExecRecorder{}
	c := &Ctx{State: root + "/state", Exec: exec, Out: io.Discard}
	return a, c, h, exec
}

// Claim: activation installs only through the modeled ledger, verifies approved
// bytes, signs and verifies the installed manifest, preserves the run-as identity
// and writes a receipt before start. Rehearsal never changes membership or starts.
func TestActivationPortPositive(t *testing.T) {
	for _, purpose := range []string{"station", "rehearsal"} {
		t.Run(purpose, func(t *testing.T) {
			a, c, h, exec := activationFixture(t, purpose)
			if e := a.Do(c); e != nil {
				t.Fatal(e)
			}
			if len(exec.commands) != 1 {
				t.Fatal(exec.commands)
			}
			cmd := exec.commands[0]
			if !reflect.DeepEqual(cmd.Args, []string{"--check-installed"}) || len(cmd.Operands) != 0 || cmd.Cred.UID != a.ServiceUID || cmd.Cred.GID != a.PeerGID || !reflect.DeepEqual(cmd.Cred.Groups, []uint32{a.ServiceGID, a.StatusGID}) || !cmd.Merge || cmd.Stdout != "log/s8-1-check-installed.out" {
				t.Fatalf("wrong service check: %+v", cmd)
			}
			raw, e := a.FS.read(a.Wallet + "/install-manifest.json")
			if e != nil {
				t.Fatal(e)
			}
			signature, e := a.FS.read(a.Wallet + "/install-manifest.json.sig")
			if e != nil {
				t.Fatal(e)
			}
			public, e := a.FS.read(a.Stage + "/install.pub.b64")
			if e != nil {
				t.Fatal(e)
			}
			var sig configguard.Signature
			if e = json.Unmarshal(signature, &sig); e != nil {
				t.Fatal(e)
			}
			sigBytes, e := base64.StdEncoding.DecodeString(sig.Value)
			if e != nil {
				t.Fatal(e)
			}
			der, e := base64.StdEncoding.DecodeString(string(public))
			if e != nil {
				t.Fatal(e)
			}
			key, e := x509.ParsePKIXPublicKey(der)
			if e != nil {
				t.Fatal(e)
			}
			if !ed25519.Verify(key.(ed25519.PublicKey), raw, sigBytes) {
				t.Fatal("signature does not verify")
			}
			if purpose == "station" {
				if !portContains(h.events, "start "+a.Unit) {
					t.Fatal("not started")
				}
			} else {
				for _, event := range h.events {
					if strings.HasPrefix(event, "start ") || strings.HasPrefix(event, "groups ") || strings.HasPrefix(event, "ledger add-member") {
						t.Fatal("rehearsal host mutation", event)
					}
				}
				if _, e := os.Lstat(a.Stage + "/started-" + a.Unit); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("rehearsal receipt")
				}
			}
			for _, p := range []string{"install-manifest.json", "install-manifest.json.sig", "install.pub.b64", "10-install.conf", "g2-status.conf"} {
				st, e := os.Stat(a.Stage + "/" + p)
				if e != nil || st.Mode().Perm() != 0600 {
					t.Fatal(p, e)
				}
			}
		})
	}
}

// Claim: each activation gate refuses its own invalid neighbor and forbids start;
// an installed-check failure also leaves no start receipt. These tests exercise
// orchestration and real file boundaries, not the pending E2 native adapters.
func TestActivationPortRefusals(t *testing.T) {
	for _, tc := range []struct{ name, mutation, refusal string }{{"release digest", "release", "ACTIVATION_RELEASE_DIGEST"}, {"account mismatch", "account", "ACTIVATION_ACCOUNT_MISMATCH"}, {"agent-key purpose", "key", "ACTIVATION_AGENT_KEY_PURPOSE"}, {"approved hashes", "approved", "MANIFEST_APPROVED_HASHES"}, {"staged unit changed", "staged", "ACTIVATION_STAGED_UNIT_CHANGED"}, {"unfilled status token", "token", "ACTIVATION_UNFILLED_TOKEN"}, {"extra Install link", "install", "ACTIVATION_INSTALL_SECTION"}, {"operator peer group", "peer", "ACTIVATION_OPERATOR_PEER_GROUP"}, {"ineffective membership", "membership", "ACTIVATION_OPERATOR_STATUS_GROUP"}, {"second ExecStart", "multiple", "ACTIVATION_EXEC_ENTRY_COUNT"}, {"wrong ExecStartPre", "pre", "ACTIVATION_EXEC_PRE"}, {"wrong ExecStart", "main", "ACTIVATION_EXEC_MAIN"}, {"failed check-installed", "check", "fixture installed failure"}, {"failed output open", "output", ""}, {"missing E2 adapter", "dependency", "ACTIVATION_E2_DEPENDENCIES"}} {
		t.Run(tc.name, func(t *testing.T) {
			a, c, h, exec := activationFixture(t, "station")
			switch tc.mutation {
			case "release":
				portWrite(t, a.Release+"/bin/agent-walletd", []byte("changed"))
			case "account":
				h.addUser(a.ServiceUser, 99, a.ServiceGID)
			case "key":
				a.AgentKey = a.RehearsalAgentKey
			case "approved":
				portWrite(t, a.Stage+"/approved-hashes.json", []byte("{}"))
			case "staged":
				portWrite(t, a.Stage+"/"+a.Unit, []byte("changed"))
			case "token", "install":
				path := a.Release + "/templates/systemd/swarma-wallet-g2-status.conf.in"
				if tc.mutation == "install" {
					path = a.Release + "/templates/systemd/swarma-wallet.service.in"
				}
				raw, e := a.FS.read(path)
				if e != nil {
					t.Fatal(e)
				}
				if tc.mutation == "token" {
					raw = append(raw, []byte("@UNKNOWN@\n")...)
				} else {
					raw = append(raw, []byte("Alias=other.service\n")...)
				}
				portWrite(t, path, raw)
				sums, e := a.FS.read(a.Release + "/SHA256SUMS")
				if e != nil {
					t.Fatal(e)
				}
				parts := strings.Split(string(sums), "\n")
				rel := strings.TrimPrefix(path, a.Release+"/")
				for i, line := range parts {
					if strings.HasSuffix(line, "  "+rel) {
						parts[i] = portDigestBytes(raw) + "  " + rel
					}
				}
				portWrite(t, a.Release+"/SHA256SUMS", []byte(strings.Join(parts, "\n")))
				if tc.mutation == "install" {
					portWrite(t, a.Stage+"/"+a.Unit, bytes.ReplaceAll(raw, []byte("@VERSION@"), []byte(strings.Repeat("a", 12))))
				}
			case "peer":
				h.groupSet = append(h.groupSet, PortNamedID{Name: a.PeerGroup, ID: a.PeerGID})
			case "membership":
				h.ignoreMembership = true
			case "multiple":
				s := h.unit[a.Unit]
				s.ExecStart += " { path=/another ; }"
				h.unit[a.Unit] = s
			case "pre":
				s := h.unit[a.Unit]
				s.ExecStartPre = "{ path=/wrong ; argv[]=--check-installed ; }"
				h.unit[a.Unit] = s
			case "main":
				s := h.unit[a.Unit]
				s.ExecStart = "{ path=/wrong ; argv[]=--status ; }"
				h.unit[a.Unit] = s
			case "check":
				exec.failure = errors.New("fixture installed failure")
			case "output":
				portMkdir(t, a.Log+"/s8-1-check-installed.out")
			case "dependency":
				a.Deps.Ledger = nil
			}
			e := a.Do(c)
			if tc.refusal != "" {
				requirePortError(t, e, tc.refusal)
			} else if !errors.Is(e, os.ErrExist) {
				t.Fatalf("wanted output collision, got %v", e)
			}
			if portContains(h.events, "start "+a.Unit) {
				t.Fatal("start after failed gate")
			}
			if _, e := os.Lstat(a.Stage + "/started-" + a.Unit); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("receipt before check success")
			}
			if tc.mutation == "output" && len(exec.commands) != 0 {
				t.Fatal("executed before output open")
			}
		})
	}
}

func rollbackFixture(t *testing.T, purpose string) (RollbackPort, *Ctx, *portHostFixture) {
	fs, root := portFS(t)
	for _, d := range []string{"state/ledger", "state/log", "state/stage", "units", "release"} {
		portMkdir(t, root+"/"+d)
	}
	raw := []byte("{\"commit\":\"fixture\"}\n")
	portWrite(t, root+"/release/manifest.json", raw)
	portWrite(t, root+"/RELEASE-VERIFIED", []byte(portDigestBytes(raw)+"\n"))
	h := newPortHost(t, fs)
	r := RollbackPort{FS: fs, Purpose: purpose, VerifiedMarker: root + "/RELEASE-VERIFIED", ReleaseManifest: root + "/release/manifest.json", Ledger: root + "/state/ledger", Log: root + "/state/log", LogName: "rollback.out", UnitDirectory: root + "/units", ReceiptDirectory: root + "/state/stage", WalletUnit: "wallet.service", SlotUnit: "slot.service", SlotUnitPrefix: "slot-", DriftTarget: root + "/service.json", DriftState: root + "/state/stage/drift-state.json", SlotUIDMin: 200000, SlotUIDMax: 209999, Deps: RollbackDeps{h, h, h, h}}
	return r, &Ctx{State: root + "/state", Out: io.Discard}, h
}

// Claim: all original D13-1 stop-authority vectors agree on refusal and exact
// stop count. A malformed ledger never becomes authority. Stop success requires
// MainPID zero; failed stop/readback cannot reach the engine or daemon reload.
func TestAttemptUnitStopOriginalVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name, Load, Active, Fragment string
			PID                          uint32
			OwnsRC                       int `json:"owns_rc"`
			Receipt, OK                  bool
			Stops                        int
		}
	}
	portFixture(t, "unit_stop", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			r, c, h := rollbackFixture(t, "rehearsal")
			target := r.UnitDirectory + "/" + r.WalletUnit
			portWrite(t, target, []byte("[Service]\n"))
			records := ownsRecords(t, r.FS, target, tc.OwnsRC == 1)
			if tc.OwnsRC == 2 {
				records = []byte("{bad\n")
			}
			portWrite(t, r.Ledger+"/records.jsonl", records)
			if tc.Receipt {
				portWrite(t, r.ReceiptDirectory+"/started-"+r.WalletUnit, nil)
			}
			h.unit[r.WalletUnit] = PortUnitInfo{LoadState: tc.Load, ActiveState: tc.Active, MainPID: tc.PID, FragmentPath: strings.ReplaceAll(tc.Fragment, "@UNITDIR@", r.UnitDirectory)}
			e := r.stopAttemptUnit(c, r.WalletUnit)
			if (e == nil) != tc.OK {
				t.Fatalf("ok=%v error=%v", tc.OK, e)
			}
			count := 0
			for _, event := range h.events {
				if event == "stop "+r.WalletUnit {
					count++
				}
			}
			if count != tc.Stops {
				t.Fatalf("stops=%d want=%d", count, tc.Stops)
			}
		})
	}
	t.Run("stop-failed-readback", func(t *testing.T) {
		r, c, h := rollbackFixture(t, "rehearsal")
		p := r.UnitDirectory + "/" + r.WalletUnit
		portWrite(t, p, []byte("unit"))
		portWrite(t, r.Ledger+"/records.jsonl", ownsRecords(t, r.FS, p, false))
		portWrite(t, r.ReceiptDirectory+"/started-"+r.WalletUnit, nil)
		h.unit[r.WalletUnit] = PortUnitInfo{LoadState: "loaded", ActiveState: "active", MainPID: 42, FragmentPath: p}
		h.keepPID = true
		requirePortError(t, r.stopAttemptUnit(c, r.WalletUnit), "ROLLBACK_PID_AFTER_STOP")
	})
}

// Claim: the relocated shell caller's precondition and ROLLBACK_OK vectors
// agree, with no E2 call before failed preconditions and no reload after an
// engine failure or wrong/duplicate success line. Engine output is retained.
func TestRollbackOriginalVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name, Purpose, Mutation, Output string
			EngineRC                        int `json:"engine_rc"`
			OK                              bool
		}
	}
	portFixture(t, "rollback", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			r, c, h := rollbackFixture(t, tc.Purpose)
			h.engineOutput = tc.Output
			h.engineRC = tc.EngineRC
			switch tc.Mutation {
			case "marker":
				if e := os.Remove(r.VerifiedMarker); e != nil {
					t.Fatal(e)
				}
			case "ledger":
				if e := os.Remove(r.Ledger); e != nil {
					t.Fatal(e)
				}
			case "manifest":
				portWrite(t, r.ReleaseManifest, []byte("changed"))
			}
			e := r.Do(c)
			if tc.EngineRC != 0 {
				var status *PortEngineStatusError
				if !errors.As(e, &status) || status.Code != tc.EngineRC {
					t.Fatalf("engine status not preserved: %v", e)
				}
			}
			if (e == nil) != tc.OK {
				t.Fatalf("ok=%v error=%v", tc.OK, e)
			}
			if tc.Mutation != "" && len(h.events) != 0 {
				t.Fatal("dependency called before preconditions", h.events)
			}
			if !tc.OK && portContains(h.events, "reload") {
				t.Fatal("reload after refusal")
			}
			if tc.OK && !portContains(h.events, "reload") {
				t.Fatal("reload not called")
			}
			if portContains(h.events, "engine "+tc.Purpose) {
				raw, e := os.ReadFile(r.Log + "/" + r.LogName)
				if e != nil || string(raw) != tc.Output {
					t.Fatal("engine output not preserved", e)
				}
			}
		})
	}
}

// Claim: verification, inventory and log-open failures stop before engine work;
// verified status 3 is accepted, rehearsal restores retained drift before verify
// and never queries slot inventory. A process on either UID boundary blocks.
func TestRollbackPortBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, mutation, refusal string }{{"verify status", "verify", "ROLLBACK_LEDGER_VERIFY"}, {"verify error", "verify-error", "ROLLBACK_LEDGER_VERIFY"}, {"slot unit", "slot-unit", "ROLLBACK_SLOT_UNITS_REMAIN"}, {"empty process inventory", "empty-process", "ROLLBACK_PROCESS_INVENTORY"}, {"lower UID", "lower", "ROLLBACK_SLOT_PROCESSES_REMAIN"}, {"upper UID", "upper", "ROLLBACK_SLOT_PROCESSES_REMAIN"}, {"log exists", "log", ""}, {"verify status 3", "status3", ""}, {"outside UID range", "outside", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			r, c, h := rollbackFixture(t, "station")
			h.engineOutput = "ROLLBACK_OK node=stopped config=baseline-verified retry=reconciled\n"
			switch tc.mutation {
			case "verify":
				h.verifyRC = 1
			case "verify-error":
				h.fail = "verify"
			case "slot-unit":
				h.rows = []PortUnitRow{{Name: "slot-example.service", Line: "slot-example.service loaded active running example"}}
			case "empty-process":
				h.uids = nil
			case "lower":
				h.uids = []uint32{r.SlotUIDMin}
			case "upper":
				h.uids = []uint32{r.SlotUIDMax}
			case "log":
				portWrite(t, r.Log+"/"+r.LogName, []byte("keep"))
			case "status3":
				h.verifyRC = 3
			case "outside":
				h.uids = []uint32{r.SlotUIDMin - 1, r.SlotUIDMax + 1}
			}
			e := r.Do(c)
			if tc.refusal != "" {
				requirePortError(t, e, tc.refusal)
			} else if tc.mutation == "log" {
				if !errors.Is(e, os.ErrExist) {
					t.Fatal(e)
				}
			} else if e != nil {
				t.Fatal(e)
			}
			if e != nil && (portContains(h.events, "engine station") || portContains(h.events, "reload")) {
				t.Fatal("continued after failure", h.events)
			}
		})
	}
	t.Run("rehearsal-drift-first-no-slot-read", func(t *testing.T) {
		r, c, h := rollbackFixture(t, "rehearsal")
		portWrite(t, r.DriftTarget, []byte("SERVICE"))
		before, e := ReadDriftIdentity(r.FS, r.DriftTarget)
		if e != nil {
			t.Fatal(e)
		}
		if e = FlipDrift(r.FS, r.DriftTarget, r.DriftState); e != nil {
			t.Fatal(e)
		}
		h.engineOutput = "ROLLBACK_OK node=not-applicable config=not-applicable retry=reconciled\n"
		if e = r.Do(c); e != nil {
			t.Fatal(e)
		}
		after, e := ReadDriftIdentity(r.FS, r.DriftTarget)
		if e != nil || after != before {
			t.Fatal("drift not restored", e)
		}
		if len(h.events) == 0 || h.events[0] != "verify" || portContains(h.events, "units") || portContains(h.events, "processes") {
			t.Fatal(h.events)
		}
	})
}

// Claim: these ports satisfy E1's operation contract, and missing E2 adapters
// are named refusals rather than a successful no-op implementation.
func TestHostPortsRequireE2(t *testing.T) {
	fs, root := portFS(t)
	for _, op := range []Op{Baseline{FS: fs, Purpose: "rehearsal", Operator: "operator", Out: root + "/baseline"}, Activation{FS: fs, Purpose: "station", Unit: "wallet.service"}, RollbackPort{FS: fs, Purpose: "station", WalletUnit: "wallet.service"}} {
		e := op.Validate()
		if e == nil || !strings.HasSuffix(e.Error(), "E2_DEPENDENCIES") {
			t.Fatal(op.Kind(), e)
		}
	}
}

// Claim: the original F1 group-set vectors agree on required status membership,
// forbidden peer membership and a similar longer name. The port additionally
// rejects peer GID aliases, since kernel credentials authorize by numeric ID.
func TestOperatorGroupsOriginalVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name     string
			Groups   []string
			Need, OK bool
		}
	}
	portFixture(t, "operator_groups", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			a, c, h, _ := activationFixture(t, "station")
			h.groupSet = nil
			for _, name := range tc.Groups {
				id := uint32(1000)
				switch name {
				case "status":
					id = a.StatusGID
				case "peer":
					id = a.PeerGID
				case "peer-x":
					id = 1001
				}
				h.groupSet = append(h.groupSet, PortNamedID{Name: name, ID: id})
			}
			e := a.operatorGroups(c, tc.Need)
			if (e == nil) != tc.OK {
				t.Fatalf("ok=%v error=%v", tc.OK, e)
			}
			if !tc.OK {
				want := "ACTIVATION_OPERATOR_STATUS_GROUP"
				for _, g := range tc.Groups {
					if g == "peer" {
						want = "ACTIVATION_OPERATOR_PEER_GROUP"
					}
				}
				requirePortError(t, e, want)
			}
		})
	}
	t.Run("numeric-peer-alias", func(t *testing.T) {
		a, c, h, _ := activationFixture(t, "station")
		h.groupSet = []PortNamedID{{Name: "alias", ID: a.PeerGID}}
		requirePortError(t, a.operatorGroups(c, false), "ACTIVATION_OPERATOR_PEER_GROUP")
	})
}

// Claim: O_PATH metadata reads succeed for a plain file, preserve an old atime,
// report absence as ENOENT, and identify a symlink without following it. This
// regresses the invalid O_PATH|O_NONBLOCK flag combination caught by baseline.
func TestPortMetadataOpenFlags(t *testing.T) {
	fs, root := portFS(t)
	p := root + "/plain"
	portWrite(t, p, []byte("metadata"))
	times := []unix.Timespec{unix.NsecToTimespec(1577934245111111111), unix.NsecToTimespec(1577934245222222222)}
	if e := unix.UtimesNanoAt(unix.AT_FDCWD, p, times, 0); e != nil {
		t.Fatal(e)
	}
	got, e := fs.stat(p)
	if e != nil || !got.Mode().IsRegular() {
		t.Fatal(got, e)
	}
	id, e := ReadDriftIdentity(fs, p)
	if e != nil || id.AtimeNS != times[0].Nano() {
		t.Fatal(id, e)
	}
	if _, e = fs.stat(root + "/absent"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	if e = os.Symlink("plain", root+"/link"); e != nil {
		t.Fatal(e)
	}
	got, e = fs.stat(root + "/link")
	if e != nil || got.Mode()&os.ModeSymlink == 0 {
		t.Fatal(got, e)
	}
}

// Claim: every activation capability failure stops the operation at that exact
// call. A failed start retains its already-durable receipt for recovery; failures
// before start create none. No subsequent capability call is made after failure.
func TestActivationCapabilityFailures(t *testing.T) {
	for _, phase := range []string{"lookup", "tmpfiles-ledger", "tmpfiles", "directory-stat", "config-ledger", "key-stat", "manifest-ledger", "signature-ledger", "dropin-dir", "binary-ledger", "groups", "membership", "reload", "unit", "installed", "start"} {
		t.Run(phase, func(t *testing.T) {
			a, c, h, _ := activationFixture(t, "station")
			event := ""
			want := ""
			switch phase {
			case "lookup":
				event = "lookup passwd " + a.ServiceUser
				want = "LOOKUP_READ"
			case "tmpfiles-ledger":
				event = "ledger create-file " + a.TmpfilesConf
			case "tmpfiles":
				event = "tmpfiles"
			case "directory-stat":
				event = "stat " + a.ConfigParent
			case "config-ledger":
				event = "ledger create-file " + a.Wallet + "/service.json"
			case "key-stat":
				event = "stat " + a.AgentKey
			case "manifest-ledger":
				event = "ledger create-file " + a.Wallet + "/install-manifest.json"
			case "signature-ledger":
				event = "ledger create-file " + a.Wallet + "/install-manifest.json.sig"
			case "dropin-dir":
				event = "ledger create-dir " + a.UnitDirectory + "/" + a.Unit + ".d"
			case "binary-ledger":
				event = "ledger create-file " + a.VersionRoot + "/" + strings.Repeat("a", 12) + "/bin/agent-walletd"
			case "groups":
				event = "groups " + a.Operator
				want = "GROUP_READ"
			case "membership":
				event = "ledger add-member "
			case "reload":
				event = "reload"
			case "unit":
				event = "unit " + a.Unit
				want = "UNIT_READ"
			case "installed":
				event = "installed"
			case "start":
				event = "start " + a.Unit
			}
			h.fail = event
			if want == "" {
				want = "FIXTURE_FAILURE " + event
			}
			requirePortError(t, a.Do(c), want)
			if len(h.events) == 0 || h.events[len(h.events)-1] != event {
				t.Fatalf("continued after failed capability: %v", h.events)
			}
			info, e := os.Lstat(a.Stage + "/started-" + a.Unit)
			if phase == "start" {
				if e != nil || info.Size() != 0 || info.Mode().Perm() != 0600 {
					t.Fatal("failed start lost recovery receipt", e)
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				t.Fatal("premature start receipt")
			}
		})
	}
}

// Claim: an unloaded-but-running unit and an owned unit with a linked or
// malformed receipt are refused without a stop; a real empty 0600 receipt is
// already exercised by the original positive authority vector.
func TestAttemptStopReceiptBoundaries(t *testing.T) {
	for _, mutation := range []string{"unloaded-running", "linked-receipt", "nonempty-receipt", "wrong-mode"} {
		t.Run(mutation, func(t *testing.T) {
			r, c, h := rollbackFixture(t, "rehearsal")
			p := r.UnitDirectory + "/" + r.WalletUnit
			portWrite(t, p, []byte("unit"))
			portWrite(t, r.Ledger+"/records.jsonl", ownsRecords(t, r.FS, p, false))
			receipt := r.ReceiptDirectory + "/started-" + r.WalletUnit
			s := PortUnitInfo{LoadState: "loaded", ActiveState: "active", MainPID: 42, FragmentPath: p}
			want := "ROLLBACK_RECEIPT_SHAPE"
			switch mutation {
			case "unloaded-running":
				s.LoadState = "not-found"
				want = "ROLLBACK_UNLOADED_RUNNING"
			case "linked-receipt":
				portWrite(t, r.ReceiptDirectory+"/real", nil)
				if e := os.Symlink("real", receipt); e != nil {
					t.Fatal(e)
				}
				want = "ROLLBACK_RECEIPT_READ"
			case "nonempty-receipt":
				portWrite(t, receipt, []byte("foreign"))
			case "wrong-mode":
				portWrite(t, receipt, nil)
				if e := os.Chmod(receipt, 0644); e != nil {
					t.Fatal(e)
				}
			}
			h.unit[r.WalletUnit] = s
			requirePortError(t, r.stopAttemptUnit(c, r.WalletUnit), want)
			if portContains(h.events, "stop "+r.WalletUnit) {
				t.Fatal("forbidden stop")
			}
		})
	}
}
