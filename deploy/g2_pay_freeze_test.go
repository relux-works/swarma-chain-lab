package deploy

// PX1 FROZEN contract test (owner S0): the deploy mirror of the G2 operator
// block marshals to the same bytes agent-wallet pins.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
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
// other members are irrelevant to ValidateG2PayIdentity.
func px1IdentityParameters() G2PayParameters {
	return G2PayParameters{Network: "main", AgentUID: 1201, AgentSocketGID: 1301, OperatorGID: 1401, ServiceUID: 1101, AgentUser: "cedar", AgentKeyFile: "/home/cedar/.config/swarma/agent.key", NodeDataDir: "/var/lib/namecoin", FeeRateSatVB: 110, G2: px1OperatorParameters()}
}

// px1Accounts is a fixture account database: cedar has UID 1201, mallory 1202.
func px1Accounts(name string) (uint32, error) {
	switch name {
	case "cedar":
		return 1201, nil
	case "mallory":
		return 1202, nil
	}
	return 0, errors.New("unknown user")
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
	if e := ValidateG2PayIdentity(px1IdentityParameters(), px1Accounts); e != nil {
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
			// The lookup always agrees with agent_uid, so only the domain refuses.
			if e := ValidateG2PayIdentity(p, func(string) (uint32, error) { return p.AgentUID, nil }); !errors.Is(e, ErrPolicy) {
				t.Fatalf("%s=%d accepted (reserved id domain)", name, id)
			}
		}
		for _, id := range []uint32{65533, 65536} {
			p := px1IdentityParameters()
			*field(&p) = id
			if e := ValidateG2PayIdentity(p, func(string) (uint32, error) { return p.AgentUID, nil }); e != nil {
				t.Fatalf("%s=%d refused (valid neighbour): %v", name, id, e)
			}
		}
	}
	same := px1IdentityParameters()
	same.ServiceUID = same.AgentUID
	if !errors.Is(ValidateG2PayIdentity(same, px1Accounts), ErrPolicy) {
		t.Fatal("service_uid == agent_uid accepted (Q9)")
	}
	long := strings.Repeat("a", 31)
	for _, c := range []struct {
		user string
		ok   bool
	}{{"cedar", true}, {"_c3d-ar", true}, {long, true}, {long + "a", false}, {"", false}, {"1cedar", false}, {"-cedar", false}, {"ced ar", false}, {"ced.ar", false}, {"<PLACEHOLDER:AGENT_USER>", false}, {"root", false}, {"nobody", false}, {"swarma-wallet", false}, {"swarma-wallet-peer", false}, {"swarma-wallet-status", false}} {
		p := px1IdentityParameters()
		p.AgentUser = c.user
		e := ValidateG2PayIdentity(p, func(string) (uint32, error) { return p.AgentUID, nil })
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
		if e := ValidateG2PayIdentity(p, px1Accounts); c.ok != (e == nil) {
			t.Fatalf("paths %q %q: got %v, want ok=%v", c.key, c.dir, e, c.ok)
		}
	}
}

// Claim (A3, R1): agent_user is BOUND to agent_uid through the account lookup:
// the name of another account, an unknown name, a failing or missing lookup
// all refuse ErrPolicy; the matching account passes.
func TestPX1PayIdentityBinding(t *testing.T) {
	p := px1IdentityParameters()
	if e := ValidateG2PayIdentity(p, px1Accounts); e != nil {
		t.Fatal("positive control: bound name refused", e)
	}
	p.AgentUser = "mallory"
	if !errors.Is(ValidateG2PayIdentity(p, px1Accounts), ErrPolicy) {
		t.Fatal("agent_user bound to another UID accepted")
	}
	p.AgentUser = "cedr"
	if !errors.Is(ValidateG2PayIdentity(p, px1Accounts), ErrPolicy) {
		t.Fatal("unknown agent_user accepted (a typo would create an account)")
	}
	p.AgentUser = "cedar"
	if !errors.Is(ValidateG2PayIdentity(p, nil), ErrPolicy) {
		t.Fatal("missing account lookup accepted")
	}
	if !errors.Is(ValidateG2PayIdentity(p, func(string) (uint32, error) { return 1201, errors.New("nss down") }), ErrPolicy) {
		t.Fatal("failing account lookup accepted")
	}
}

// Claim (A3): the production lookup reads the host account database: the
// running account resolves to its own UID, and an unknown name is an error.
// Limit: it proves the os/user wiring on this host, not any provisioned user.
func TestPX1HostAccountLookup(t *testing.T) {
	cur, e := user.Current()
	if e != nil {
		t.Skip("no current account entry on this host:", e)
	}
	want, _ := strconv.ParseUint(cur.Uid, 10, 32)
	if uid, e := LookupG2HostAccount(cur.Username); e != nil || uint64(uid) != want {
		t.Fatalf("lookup %q = %d, %v; want %d", cur.Username, uid, e, want)
	}
	if _, e := LookupG2HostAccount("px1-no-such-user-zz"); e == nil {
		t.Fatal("unknown account resolved")
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
