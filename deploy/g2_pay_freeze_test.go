package deploy

// PX1 FROZEN contract test (owner S0): the deploy mirror of the G2 operator
// block marshals to the same bytes agent-wallet pins.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Bytes of experiments/agent-wallet/testdata/px1/g2-operator.json.
const px1OperatorGolden = `{"require_terms_version":2,"allow_single_use":false,"allow_any_recipients":false,"max_transfer_sat":100000,"max_day_sat":300000,"max_day_count":10,"max_fee_sat":100000,"max_float_sat":2000000,"low_float_sat":500000,"canary":{"outpoint":{"txid":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","vout":0},"value_sat":10000},"confirmations_k":2,"conflict_blocks_n":6,"read_rate_per_hour":60,"journal_spend_capacity":2048}`

func px1OperatorParameters() G2OperatorParameters {
	return G2OperatorParameters{RequireTermsVersion: 2, MaxTransferSat: 100000, MaxDaySat: 300000, MaxDayCount: 10, MaxFeeSat: 100000, MaxFloatSat: 2000000, LowFloatSat: 500000, Canary: G2CanaryParameters{Outpoint: G2Outpoint{TxID: strings.Repeat("c", 64)}, ValueSat: 10000}, ConfirmationsK: 2, ConflictBlocksN: 6, ReadRatePerHour: 60, JournalSpendCapacity: 2048}
}

// Claim: the mirror's bytes and SHA-256 equal agent-wallet's frozen operator
// golden; a changed ceiling no longer matches (negative control).
func TestPX1OperatorMirrorGolden(t *testing.T) {
	got, _ := json.Marshal(px1OperatorParameters())
	sum := sha256.Sum256([]byte(px1OperatorGolden))
	if string(got) != px1OperatorGolden || hex.EncodeToString(sum[:]) != "ed001683d2751865d4b339214bc668edfa977d1d0d50e5e0005354dc07df2dde" {
		t.Fatalf("operator mirror drifted\n got %s\nwant %s", got, px1OperatorGolden)
	}
	bumped := px1OperatorParameters()
	bumped.MaxDaySat++
	if b, _ := json.Marshal(bumped); string(b) == px1OperatorGolden {
		t.Fatal("value change not detected")
	}
}

// px1IdentityParameters is a valid identity block (freeze amendment 1); the
// other members are irrelevant to the identity helpers.
func px1IdentityParameters() G2PayParameters {
	return G2PayParameters{Network: "main", AgentUID: 1201, AgentSocketGID: 1301, OperatorGID: 1401, ServiceUID: 1101, AgentUser: "cedar", AgentKeyFile: "/home/cedar/.config/swarma/agent.key", NodeDataDir: "/var/lib/namecoin", FeeRateSatVB: 110, G2: px1OperatorParameters()}
}

// px1AccountDB is a fixture target-host account database. A non-nil
// nameErr/uidErr/groupErr is an outage of that lookup; a missing entry is
// ErrG2AccountAbsent.
type px1AccountDB struct {
	users                     map[string]uint32
	groups                    map[string][]uint32
	nameErr, uidErr, groupErr error
}

func (d px1AccountDB) UserUID(n string) (uint32, error) {
	if d.nameErr != nil {
		return 0, d.nameErr
	}
	if u, ok := d.users[n]; ok {
		return u, nil
	}
	return 0, fmt.Errorf("user %q: %w", n, ErrG2AccountAbsent)
}

func (d px1AccountDB) UIDUser(id uint32) (string, error) {
	if d.uidErr != nil {
		return "", d.uidErr
	}
	for n, u := range d.users {
		if u == id {
			return n, nil
		}
	}
	return "", fmt.Errorf("uid %d: %w", id, ErrG2AccountAbsent)
}

func (d px1AccountDB) UserGroups(n string) ([]uint32, error) {
	if d.groupErr != nil {
		return nil, d.groupErr
	}
	if _, ok := d.users[n]; !ok {
		return nil, fmt.Errorf("user %q: %w", n, ErrG2AccountAbsent)
	}
	return d.groups[n], nil
}

// px1Accounts: cedar has UID 1201 in groups 1201 and 1301 (agent socket
// group); mallory has UID 1202.
func px1Accounts() px1AccountDB {
	return px1AccountDB{users: map[string]uint32{"cedar": 1201, "mallory": 1202}, groups: map[string][]uint32{"cedar": {1201, 1301}, "mallory": {1202}}}
}

// Claim (A3): the parameters gain service_uid, agent_user, agent_key_file and
// node_datadir after operator_gid, in that canonical JSON order.
func TestPX1PayParametersOrder(t *testing.T) {
	var tags []string
	ty := reflect.TypeOf(G2PayParameters{})
	for i := 0; i < ty.NumField(); i++ {
		tags = append(tags, ty.Field(i).Tag.Get("json"))
	}
	want := "network genesis agent_uid agent_socket_gid operator_gid service_uid agent_user agent_key_file node_datadir grantee receipt_pubkey fee_rate_sat_vb hot_wallet_name node_rpc_port g2"
	if got := strings.Join(tags, " "); got != want {
		t.Fatalf("G2PayParameters order drifted:\n got %s\nwant %s", got, want)
	}
}

// Claim (A3): a valid identity block passes, and each single violation of the
// UID/GID domain (0, 65534, 65535, 2^32-1 on any of the four IDs), the Q9
// separation, the sysusers name rule and its reserved names, or the absolute
// clean path rule refuses ErrPolicy. Boundary neighbours 65533 and 65536 pass.
func TestPX1PayIdentityDomain(t *testing.T) {
	if e := ValidateG2PayIdentityDomain(px1IdentityParameters()); e != nil {
		t.Fatal("positive control refused", e)
	}
	ids := map[string]func(*G2PayParameters) *uint32{
		"agent_uid":        func(p *G2PayParameters) *uint32 { return &p.AgentUID },
		"service_uid":      func(p *G2PayParameters) *uint32 { return &p.ServiceUID },
		"agent_socket_gid": func(p *G2PayParameters) *uint32 { return &p.AgentSocketGID },
		"operator_gid":     func(p *G2PayParameters) *uint32 { return &p.OperatorGID },
	}
	for name, field := range ids {
		for _, id := range []uint32{0, 65534, 65535, 1<<32 - 1} {
			p := px1IdentityParameters()
			*field(&p) = id
			if e := ValidateG2PayIdentityDomain(p); !errors.Is(e, ErrPolicy) {
				t.Fatalf("%s=%d accepted (reserved id domain)", name, id)
			}
		}
		for _, id := range []uint32{65533, 65536} {
			p := px1IdentityParameters()
			*field(&p) = id
			if e := ValidateG2PayIdentityDomain(p); e != nil {
				t.Fatalf("%s=%d refused (valid neighbour): %v", name, id, e)
			}
		}
	}
	same := px1IdentityParameters()
	same.ServiceUID = same.AgentUID
	if !errors.Is(ValidateG2PayIdentityDomain(same), ErrPolicy) {
		t.Fatal("service_uid == agent_uid accepted (Q9)")
	}
	long := strings.Repeat("a", 31)
	for _, c := range []struct {
		user string
		ok   bool
	}{{"cedar", true}, {"_c3d-ar", true}, {long, true}, {long + "a", false}, {"", false}, {"1cedar", false}, {"-cedar", false}, {"ced ar", false}, {"ced.ar", false}, {"<PLACEHOLDER:AGENT_USER>", false}, {"root", false}, {"nobody", false}, {"swarma-wallet", false}, {"swarma-wallet-peer", false}, {"swarma-wallet-status", false}} {
		p := px1IdentityParameters()
		p.AgentUser = c.user
		e := ValidateG2PayIdentityDomain(p)
		if c.ok != (e == nil) || !c.ok && !errors.Is(e, ErrPolicy) {
			t.Fatalf("agent_user %q: got %v, want ok=%v", c.user, e, c.ok)
		}
	}
	for _, c := range []struct {
		key, dir string
		ok       bool
	}{
		{"/k", "/d", true},
		{"relative/agent.key", "/var/lib/namecoin", false},
		{"/home/cedar/agent.key", "var/lib/namecoin", false},
		{"/", "/var/lib/namecoin", false},
		{"/home/cedar/agent.key", "/var/lib/namecoin/", false},
		{"/home/cedar/../cedar/agent.key", "/var/lib/namecoin", false},
		{"/home/cedar//agent.key", "/var/lib/namecoin", false},
		{"/home/cedar/agent key", "/var/lib/namecoin", false},
		{"/home/cedar/agent.key", "/var/lib/name\ncoin", false},
		{"/home/cedar/agent.key", "PLACEHOLDER_NODE_DATADIR", false},
		{"/" + strings.Repeat("a", 4094), "/d", true},
		{"/" + strings.Repeat("a", 4095), "/d", false},
		{"/same", "/same", false},
	} {
		p := px1IdentityParameters()
		p.AgentKeyFile, p.NodeDataDir = c.key, c.dir
		if e := ValidateG2PayIdentityDomain(p); c.ok != (e == nil) {
			t.Fatalf("paths %q %q: got %v, want ok=%v", c.key, c.dir, e, c.ok)
		}
	}
	// Every entry point carries the domain: a domain refusal also refuses the
	// preflight, the declaration and the post-apply check, even over a
	// database that agrees with the parameters.
	bad := px1IdentityParameters()
	bad.AgentUID = 65535
	agree := px1AccountDB{users: map[string]uint32{"cedar": 65535}, groups: map[string][]uint32{"cedar": {1301}}}
	if _, e := G2AgentSysusers(bad); !errors.Is(e, ErrPolicy) || !errors.Is(ValidateG2PayIdentity(bad, agree), ErrPolicy) || !errors.Is(VerifyG2AgentAccount(bad, agree), ErrPolicy) {
		t.Fatal("agent_uid=65535 accepted by an entry point (reserved id domain)")
	}
}

// Claim (A3, R1, rev 2): the target-host preflight admits exactly two account
// states. Existing: agent_user must have exactly agent_uid. First install:
// agent_user is genuinely absent AND no other name owns agent_uid. A lookup
// outage of either lookup, and a missing database, refuse; an outage is never
// absence. Each branch has a passing neighbour. Limit: fixture database; the
// os/user classification is TestPX1HostAccounts.
func TestPX1PayIdentityBinding(t *testing.T) {
	db := px1Accounts()
	p := px1IdentityParameters()
	// existing branch
	if e := ValidateG2PayIdentity(p, db); e != nil {
		t.Fatal("positive control: existing bound name refused", e)
	}
	p.AgentUser = "mallory"
	if !errors.Is(ValidateG2PayIdentity(p, db), ErrPolicy) {
		t.Fatal("agent_user bound to another UID accepted")
	}
	// first-install branch: absent name, free UID passes; a UID owned by
	// another name refuses (sysusers would substitute another UID).
	first := px1IdentityParameters()
	first.AgentUser, first.AgentUID = "newagent", 1210
	if e := ValidateG2PayIdentity(first, db); e != nil {
		t.Fatal("first install refused: absent agent_user with a free agent_uid", e)
	}
	for _, c := range []struct {
		user string
		uid  uint32
	}{{"newagent", 1202}, {"cedr", 1201}} {
		q := px1IdentityParameters()
		q.AgentUser, q.AgentUID = c.user, c.uid
		if !errors.Is(ValidateG2PayIdentity(q, db), ErrPolicy) {
			t.Fatalf("first install: agent_uid owned by another name accepted (%s/%d)", c.user, c.uid)
		}
	}
	// outage branch: the same first-install parameters pass on the healthy
	// database above, so only the outage refuses here.
	down := px1Accounts()
	down.nameErr = errors.New("nss down")
	if !errors.Is(ValidateG2PayIdentity(first, down), ErrPolicy) || !errors.Is(ValidateG2PayIdentity(px1IdentityParameters(), down), ErrPolicy) {
		t.Fatal("account lookup outage treated as absence")
	}
	down = px1Accounts()
	down.uidErr = errors.New("nss down")
	if !errors.Is(ValidateG2PayIdentity(first, down), ErrPolicy) {
		t.Fatal("first install: uid lookup outage accepted")
	}
	if e := ValidateG2PayIdentity(px1IdentityParameters(), down); e != nil {
		t.Fatal("existing branch needs no uid lookup, refused:", e)
	}
	if !errors.Is(ValidateG2PayIdentity(px1IdentityParameters(), nil), ErrPolicy) {
		t.Fatal("missing account database accepted")
	}
}

// Claim (A3, rev 2): the rendered agent declaration is exactly an explicit
// numeric "u" line plus the agent's only G2 membership; never "m"-only, never
// the operator group. A domain refusal renders nothing.
func TestPX1AgentSysusers(t *testing.T) {
	got, e := G2AgentSysusers(px1IdentityParameters())
	if e != nil || got != "u cedar 1201\nm cedar swarma-wallet-peer\n" {
		t.Fatalf("agent declaration drifted: %q, %v", got, e)
	}
	if !strings.HasPrefix(got, "u cedar 1201\n") {
		t.Fatal("agent declaration lost its numeric u line")
	}
	if strings.Contains(got, G2OperatorGroup) {
		t.Fatal("agent declared into the operator group")
	}
	p := px1IdentityParameters()
	p.AgentUser = "cedar\nu root 0"
	if s, e := G2AgentSysusers(p); !errors.Is(e, ErrPolicy) || s != "" {
		t.Fatalf("injected agent_user rendered: %q", s)
	}
}

// Claim (A3, rev 2): the REQUIRED post-apply check passes only when the target
// host now has agent_user at exactly agent_uid, in agent_socket_gid and not
// in operator_gid. The sysusers collision result (same name, substituted
// UID), absence, outages and wrong groups all refuse.
func TestPX1AgentAccountPostApply(t *testing.T) {
	p := px1IdentityParameters()
	if e := VerifyG2AgentAccount(p, px1Accounts()); e != nil {
		t.Fatal("positive control: applied account refused", e)
	}
	with := func(f func(*px1AccountDB)) px1AccountDB {
		d := px1Accounts()
		d.users = map[string]uint32{"cedar": 1201, "mallory": 1202}
		d.groups = map[string][]uint32{"cedar": {1201, 1301}}
		f(&d)
		return d
	}
	for _, c := range []struct {
		marker string
		db     G2AccountDB
	}{
		{"post-apply: substituted agent uid accepted", with(func(d *px1AccountDB) { d.users["cedar"] = 999 })},
		{"post-apply: absent agent accepted", with(func(d *px1AccountDB) { delete(d.users, "cedar") })},
		{"post-apply: lookup outage accepted", with(func(d *px1AccountDB) { d.nameErr = errors.New("nss down") })},
		{"post-apply: agent without agent_socket_gid accepted", with(func(d *px1AccountDB) { d.groups["cedar"] = []uint32{1201} })},
		{"post-apply: agent in operator_gid accepted", with(func(d *px1AccountDB) { d.groups["cedar"] = []uint32{1201, 1301, 1401} })},
		{"post-apply: group lookup outage accepted", with(func(d *px1AccountDB) { d.groupErr = errors.New("nss down") })},
		{"post-apply: missing database accepted", nil},
	} {
		if !errors.Is(VerifyG2AgentAccount(p, c.db), ErrPolicy) {
			t.Error(c.marker)
		}
	}
}

// Claim (A3, rev 2): os/user errors are classified: only UnknownUserError and
// UnknownUserIdError (also wrapped) are ErrG2AccountAbsent; any other error is
// returned unchanged as an outage.
func TestPX1HostAccountErrors(t *testing.T) {
	for _, e := range []error{user.UnknownUserError("cedar"), user.UnknownUserIdError(1201), fmt.Errorf("lookup: %w", user.UnknownUserError("x"))} {
		if !errors.Is(g2AccountErr(e), ErrG2AccountAbsent) {
			t.Fatalf("absence not classified: %v", e)
		}
	}
	outage := errors.New("nss down")
	if got := g2AccountErr(outage); errors.Is(got, ErrG2AccountAbsent) || got != outage {
		t.Fatal("outage classified as absence")
	}
}

// Claim (A3): the production database reads this host's accounts: the running
// account resolves by name and by UID, its groups include its primary GID,
// and an unknown name and an unknown UID are ErrG2AccountAbsent. Limit: it
// proves the os/user wiring on this host, not any provisioned user; an
// outage cannot be produced here (TestPX1HostAccountErrors covers it).
func TestPX1HostAccounts(t *testing.T) {
	cur, e := user.Current()
	if e != nil {
		t.Skip("no current account entry on this host:", e)
	}
	want, _ := strconv.ParseUint(cur.Uid, 10, 32)
	gid, _ := strconv.ParseUint(cur.Gid, 10, 32)
	db := G2HostAccounts{}
	if uid, e := db.UserUID(cur.Username); e != nil || uint64(uid) != want {
		t.Fatalf("UserUID %q = %d, %v; want %d", cur.Username, uid, e, want)
	}
	if name, e := db.UIDUser(uint32(want)); e != nil || name != cur.Username {
		t.Fatalf("UIDUser %d = %q, %v", want, name, e)
	}
	gids, e := db.UserGroups(cur.Username)
	if e != nil || !slices.Contains(gids, uint32(gid)) {
		t.Fatalf("UserGroups %q = %v, %v; want primary %d", cur.Username, gids, e, gid)
	}
	if _, e := db.UserUID("px1-no-such-user-zz"); !errors.Is(e, ErrG2AccountAbsent) {
		t.Fatal("unknown account not absent:", e)
	}
	if _, e := db.UIDUser(3999999989); !errors.Is(e, ErrG2AccountAbsent) {
		t.Fatal("unknown uid not absent:", e)
	}
}

// px1SharesDir reports whether binding the directory of either socket would
// expose the other: same directory, or one directory nested in the other.
func px1SharesDir(a, b string) bool {
	da, db := path.Dir(a)+"/", path.Dir(b)+"/"
	return strings.HasPrefix(da, db) || strings.HasPrefix(db, da)
}

// Claim (A8): the operator status socket has its own 0750 directory and the
// socket keeps 0660; no frozen agent-facing path shares a directory with it,
// and no non-test deploy source names the old /run/swarma-wallet status path.
// The checker itself flags the old layout and a nested one (controls) and
// does not confuse the -status prefix with the wallet directory.
func TestPX1StatusSocketSplit(t *testing.T) {
	if !px1SharesDir("/run/swarma-wallet/wallet.sock", "/run/swarma-wallet/status.sock") || !px1SharesDir("/run/swarma-wallet/wallet.sock", "/run/swarma-wallet/s/status.sock") || px1SharesDir("/run/swarma-wallet/wallet.sock", "/run/swarma-wallet-status/status.sock") {
		t.Fatal("shared-directory checker is broken")
	}
	if G2StatusSocketPath != "/run/swarma-wallet-status/status.sock" || path.Dir(G2StatusSocketPath) != G2StatusSocketDir || G2StatusSocketDirMode != 0o750 || G2StatusSocketMode != 0o660 {
		t.Errorf("status socket placement drifted: %s %o %o", G2StatusSocketPath, G2StatusSocketDirMode, G2StatusSocketMode)
	}
	if G2WalletSocketPath != "/run/swarma-wallet/wallet.sock" || path.Dir(G2WalletSocketPath) != G2WalletSocketDir {
		t.Errorf("wallet socket placement drifted: %s", G2WalletSocketPath)
	}
	for _, a := range []string{G2WalletSocketPath, G2WalletSocketDir + "/"} {
		if px1SharesDir(a, G2StatusSocketPath) {
			t.Errorf("agent-facing path shares a directory with the status socket: %s", a)
		}
	}
	e := filepath.WalkDir(".", func(p string, d fs.DirEntry, e error) error {
		if e != nil || d.IsDir() && (d.Name() == "testdata" || d.Name() == ".temp") {
			if e == nil {
				return filepath.SkipDir
			}
			return e
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, e := os.ReadFile(p)
		if e == nil && strings.Contains(string(b), "/run/swarma-wallet/status.sock") {
			t.Errorf("old status socket path in %s (A8 migration)", p)
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}

// Claim: each S0 deploy plant in testdata/px1-mutations-s0.json compiles and
// fails its named assertion in an isolated copy (W1_MUTATIONS=1 only); setup
// errors, crashes and unrelated failures are never a kill.
func TestPX1S0GuardPlants(t *testing.T) {
	if os.Getenv("W1_MUTATIONS") != "1" {
		t.Skip("W1_MUTATIONS=1 requires a fresh absolute W1_MUTATION_ROOT")
	}
	root := os.Getenv("W1_MUTATION_ROOT")
	if !filepath.IsAbs(root) || os.Mkdir(root, 0700) != nil {
		t.Fatal("fresh absolute W1_MUTATION_ROOT required")
	}
	var plants []struct{ Name, File, Old, New, Selector, Marker string }
	raw, e := os.ReadFile("testdata/px1-mutations-s0.json")
	if e != nil || json.Unmarshal(raw, &plants) != nil || len(plants) < 1 {
		t.Fatal("S0 plant manifest", e)
	}
	repo, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	copyTree := func(src, dst string) error {
		return filepath.WalkDir(src, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, _ := filepath.Rel(src, p)
			if d.IsDir() {
				if d.Name() == ".temp" {
					return filepath.SkipDir
				}
				return os.MkdirAll(filepath.Join(dst, rel), 0700)
			}
			if !d.Type().IsRegular() {
				return errors.New("non-regular source file " + p)
			}
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			return os.WriteFile(filepath.Join(dst, rel), b, 0600)
		})
	}
	for _, p := range plants {
		t.Run(p.Name, func(t *testing.T) {
			dir := filepath.Join(root, p.Name)
			for _, m := range []string{"deploy", "experiments/single-use", "experiments/sealwatch"} {
				if e := copyTree(filepath.Join(repo, m), filepath.Join(dir, m)); e != nil {
					t.Fatal(e)
				}
			}
			file := filepath.Join(dir, "deploy", p.File)
			original, e := os.ReadFile(file)
			if e != nil || strings.Count(string(original), p.Old) != 1 {
				t.Fatal("plant guard not uniquely applied", e)
			}
			if e = os.WriteFile(file, []byte(strings.Replace(string(original), p.Old, p.New, 1)), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			selector := "^" + strings.ReplaceAll(p.Selector, "/", "$/^") + "$"
			cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", selector, ".")
			cmd.Dir = filepath.Join(dir, "deploy")
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "W1_") && !strings.HasPrefix(v, "GOWORK=") {
					cmd.Env = append(cmd.Env, v)
				}
			}
			cmd.Env = append(cmd.Env, "GOWORK=off")
			out, err := cmd.CombinedOutput()
			_ = os.WriteFile(filepath.Join(dir, "test.log"), out, 0600)
			o := string(out)
			killed := err != nil && ctx.Err() == nil && strings.Contains(o, p.Marker) && strings.Contains(o, "--- FAIL:") && !strings.Contains(o, "[build failed]") && !strings.Contains(o, "[setup failed]") && !strings.Contains(o, "panic:")
			if !killed {
				t.Fatalf("intended control not detected: %s", filepath.Join(dir, "test.log"))
			}
		})
	}
}
