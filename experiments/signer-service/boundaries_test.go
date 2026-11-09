package signerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func dir(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func write(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func testKey(n byte) (*btcec.PrivateKey, string, string) {
	b := make([]byte, 32)
	b[31] = n
	k, _ := btcec.PrivKeyFromBytes(b)
	pub := hex.EncodeToString(schnorr.SerializePubKey(k.PubKey()))
	script, _ := rental.GrantSealScript(pub)
	return k, pub, script
}
func config(t *testing.T) Config {
	root := dir(t)
	grant, pub, seal := testKey(6)
	fund, _, fundScript := testKey(7)
	_, agent, _ := testKey(3)
	_, provider, _ := testKey(4)
	kp, fp := filepath.Join(root, "grant.key"), filepath.Join(root, "funding.key")
	write(t, kp, grant.Serialize())
	write(t, fp, fund.Serialize())
	return Config{Profile: "v1-nmc", Policy: rental.IssuerPolicy{Policy: rental.Policy{Network: "regtest", Genesis: su.RegtestGenesis, IssuerPubkey: pub, AgentPubkey: agent, AgentName: "id/sg1-agent", StationName: "id/sg1-agent", LandlordName: "id/sg1-landlord", SealScript: seal, StationScript: seal, FundingScript: fundScript, StateDir: dir(t)}, ProviderPubkey: provider}, StateDir: dir(t), GrantKeyPath: kp, FundingKeyPath: fp, Caps: RegtestCaps()}
}
func wantError(t *testing.T, e error, want string) {
	t.Helper()
	if e == nil || e.Error() != want {
		t.Fatalf("want %s, got %v", want, e)
	}
}

// Startup refuses every non-regtest network before opening state or key files;
// the otherwise identical regtest configuration is accepted without key reads.
func TestStartupNetwork(t *testing.T) {
	c := config(t)
	if e := c.validate(); e != nil {
		t.Fatal("regtest neighbor", e)
	}
	for _, network := range []string{"main", "mainnet", "testnet"} {
		t.Run(network, func(t *testing.T) {
			bad := c
			bad.Policy.Policy.Network = network
			bad.GrantKeyPath = "/missing"
			bad.StateDir = "/missing"
			_, e := Open(bad, nil, nil, nil, nil)
			wantError(t, e, "REGTEST_ONLY")
		})
	}
	c.Policy.Policy.Genesis = strings.Repeat("0", 64)
	_, e := Open(c, nil, nil, nil, nil)
	wantError(t, e, "REGTEST_ONLY")
}

// Real ECDSA signatures made with an odd-y secret use the even-y normalized
// public point. Unsafe file permissions, links, lengths and pins refuse.
func TestKeyCustody(t *testing.T) {
	c := config(t)
	k, e := loadKey(c.GrantKeyPath, c.Policy.Policy.SealScript)
	if e != nil {
		t.Fatal(e)
	}
	defer k.Zero()
	if k.PubKey().SerializeCompressed()[0] != 2 {
		t.Fatal("key not normalized")
	}
	raw, e := os.ReadFile(c.GrantKeyPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"mode", "zero", "hex", "symlink", "hardlink", "wrong-key"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(dir(t), "key")
			write(t, path, raw)
			switch mode {
			case "mode":
				os.Chmod(path, 0644)
			case "zero":
				write(t, path, make([]byte, 32))
			case "hex":
				write(t, path, []byte(hex.EncodeToString(raw)))
			case "symlink":
				path += "-link"
				if e := os.Symlink(c.GrantKeyPath, path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, path+"-link"); e != nil {
					t.Fatal(e)
				}
			case "wrong-key":
				other, _, _ := testKey(9)
				write(t, path, other.Serialize())
			}
			if got, e := loadKey(path, c.Policy.Policy.SealScript); e == nil {
				got.Zero()
				t.Fatal("unsafe key accepted")
			}
			good, e := loadKey(c.GrantKeyPath, c.Policy.Policy.SealScript)
			if e != nil {
				t.Fatal("valid neighbor", e)
			}
			good.Zero()
		})
	}
}
func appendItem(t *testing.T, root string, index []string, item Item) []string {
	b := encode(item)
	write(t, filepath.Join(root, hash(b)+".json"), b)
	index = append(index, hash(b))
	write(t, filepath.Join(root, "index.json"), encode(index))
	return index
}

// The file cursor binds source and exact consumed prefix. No malformed cursor,
// rewritten prefix or substituted content advances it; appending does work.
func TestFileSource(t *testing.T) {
	root := dir(t)
	index := appendItem(t, root, nil, Item{ID: hash([]byte("one")), Kind: "grant-issue"})
	s, e := OpenFileSource(root)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.Pull(context.Background(), "", 1)
	if e != nil || len(rows) != 1 {
		t.Fatal("first pull", e)
	}
	cursor := rows[0].After
	index = appendItem(t, root, index, Item{ID: hash([]byte("two")), Kind: "revoke"})
	rows, e = s.Pull(context.Background(), cursor, 1)
	if e != nil || len(rows) != 1 {
		t.Fatal("append neighbor", e)
	}
	for _, bad := range []string{"{}", "null", `{"version":1}`, "broken"} {
		_, e = s.Pull(context.Background(), bad, 1)
		wantError(t, e, "OUTBOX_CURSOR")
	}
	other := dir(t)
	write(t, filepath.Join(other, "index.json"), encode(index))
	source, _ := OpenFileSource(other)
	_, e = source.Pull(context.Background(), cursor, 1)
	wantError(t, e, "OUTBOX_CURSOR")
	write(t, filepath.Join(root, "index.json"), encode([]string{index[1], index[0]}))
	_, e = s.Pull(context.Background(), cursor, 1)
	wantError(t, e, "OUTBOX_CURSOR")
	write(t, filepath.Join(root, "index.json"), encode(index))
	write(t, filepath.Join(root, index[1]+".json"), []byte(`{}`))
	_, e = s.Pull(context.Background(), cursor, 1)
	wantError(t, e, "OUTBOX_HASH")
}

type noNode struct{ t *testing.T }

func (n noNode) Call(context.Context, string, ...any) (json.RawMessage, error) {
	n.t.Fatal("unexpected node call")
	return nil, fail("UNREACHABLE")
}

type noBroadcast struct{ t *testing.T }

func (b noBroadcast) Send(context.Context, []byte) (string, error) {
	b.t.Fatal("unexpected broadcast")
	return "", fail("UNREACHABLE")
}

type noStore struct{ t *testing.T }

func (s noStore) Put(context.Context, []byte) (string, error) {
	s.t.Fatal("unexpected upload")
	return "", fail("UNREACHABLE")
}

type preflightIssuer struct {
	t *testing.T
	i Intent
}

func (a preflightIssuer) Inspect([]byte, []byte, int64) (Intent, error) { return a.i, nil }
func (a preflightIssuer) Check(context.Context, []byte, []byte, int64) error {
	a.t.Fatal("unexpected admission read")
	return fail("UNREACHABLE")
}
func (a preflightIssuer) Prepare(context.Context, []byte, []byte, rental.Point, rental.PlanSpec, int64) rental.GrantIssueResult {
	a.t.Fatal("unexpected grant signature")
	return rental.GrantIssueResult{}
}
func opened(t *testing.T, c Config, i Intent) *Engine {
	t.Helper()
	x, e := Open(c, preflightIssuer{t, i}, noNode{t}, noBroadcast{t}, noStore{t})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(x.Close)
	return x
}
func files(t *testing.T, root string) []string {
	t.Helper()
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	result := []string{}
	for _, e := range entries {
		result = append(result, e.Name())
	}
	return result
}

// Preflight cap/template refusals perform no state/blob write or downstream
// call. This test isolates service accounting; genuine-Core tests cover issuer
// authentication and actual signatures instead of this trusted test adapter.
func TestPreflightNoEffects(t *testing.T) {
	c := config(t)
	i := Intent{BookingID: hash([]byte("book")), ContractSHA256: hash([]byte("contract")), BudgetSat: c.Caps.BudgetHour + 1, PaymentCoin: "nmc", PaymentNetwork: "regtest", PaymentGenesis: su.RegtestGenesis, PaymentTxID: hash([]byte("payment"))}
	x := opened(t, c, i)
	before := encode(files(t, c.StateDir))
	req := encode(map[string]string{"booking_id": i.BookingID})
	item := Item{ID: hash([]byte("id")), Kind: "grant-issue", Request: string(req), Publication: `{}`}
	_, e := x.Process(context.Background(), encode(item), BookingSource, 500)
	wantError(t, e, "ISSUANCE_CAP")
	item.Kind = "sweep"
	_, e = x.Process(context.Background(), encode(item), BookingSource, 500)
	wantError(t, e, "TEMPLATE_REFUSED")
	if !bytes.Equal(before, encode(files(t, c.StateDir))) || len(x.state.Operations) != 0 {
		t.Fatal("denial wrote state")
	}
	valid := i
	valid.BudgetSat = c.Caps.BudgetHour
	if e = x.capIssue(valid, 500); e != nil {
		t.Fatal("cap neighbor", e)
	}
	in := su.PlanInput{Point: su.Point{TxID: hash([]byte("fund"))}, Role: "funding", ValueSat: 1000000, Script: c.Policy.Policy.SealScript}
	wantError(t, x.Enroll(context.Background(), []su.PlanInput{in}, 500), "FUNDING_SEAL_SCRIPT")
	if !bytes.Equal(before, encode(files(t, c.StateDir))) {
		t.Fatal("invalid enrollment wrote state")
	}
	in.Script = c.Policy.Policy.FundingScript
	if e = x.validInventory(in); e != nil {
		t.Fatal("funding neighbor", e)
	}
}

// Closed booking-source authority refuses forged operator reasons; the same
// explicit private operator source suppresses a booking before issuance and
// replay does not allocate a transaction or consume any seal.
func TestRevokeSourceAndSuppression(t *testing.T) {
	c := config(t)
	x := opened(t, c, Intent{})
	r := &Revoke{Version: 2, BookingID: hash([]byte("b")), ContractSHA256: hash([]byte("c")), Reason: "operator"}
	item := Item{ID: hash([]byte("id")), Kind: "revoke", Revoke: r}
	_, e := x.Process(context.Background(), encode(item), BookingSource, 500)
	wantError(t, e, "REVOKE_AUTHORITY")
	result, e := x.Process(context.Background(), encode(item), OperatorSource, 500)
	if e != nil || result.Phase != "suppressed" {
		t.Fatal(result, e)
	}
	result, e = x.Process(context.Background(), encode(item), OperatorSource, 500)
	if e != nil || len(x.state.Suppressed) != 1 || len(x.state.Operations) != 0 {
		t.Fatal("suppression replay", result, e)
	}
	r.ContractSHA256 = hash([]byte("different"))
	_, e = x.Process(context.Background(), encode(item), OperatorSource, 500)
	wantError(t, e, "ITEM_CONFLICT")
}

// A real signed refill is a valid neighbor; changed output, sequence, signature
// or script-key binding cannot pass recovery just by updating the txid.
func TestSignedTemplateRecovery(t *testing.T) {
	c := config(t)
	in := su.PlanInput{Point: su.Point{TxID: hash([]byte("prevout"))}, ValueSat: 2000000, Script: c.Policy.Policy.FundingScript, Role: "funding"}
	spec := rental.PlanSpec{Kind: "refill", Inputs: []su.PlanInput{in}, ChangeScript: c.Policy.Policy.FundingScript, Count: 2, ValueSat: 200000}
	plan, e := rental.MakePlan(c.Policy, spec, nil, nil, nil, 500)
	if e != nil {
		t.Fatal(e)
	}
	key, e := loadKey(c.FundingKeyPath, c.Policy.Policy.FundingScript)
	if e != nil {
		t.Fatal(e)
	}
	defer key.Zero()
	raw, _, e := signPlan(plan, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifySignedPlan(plan, raw); e != nil {
		t.Fatal("valid signed neighbor", e)
	}
	for _, mode := range []string{"output", "sequence", "signature", "key"} {
		t.Run(mode, func(t *testing.T) {
			tx, e := su.DecodeTransaction(raw)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "output":
				tx.Outputs[0].Value++
			case "sequence":
				tx.Inputs[0].Sequence--
			case "signature":
				tx.Inputs[0].Script[10] ^= 1
			case "key":
				tx.Inputs[0].Script[len(tx.Inputs[0].Script)-1] ^= 1
			}
			if verifySignedPlan(plan, tx.Bytes()) == nil {
				t.Fatal("changed signed transaction accepted")
			}
		})
	}
}

// Unfinished reservations remain charged after hour/day rollover; a clock
// rollback refuses. Retrying that same reservation does not charge it twice.
func TestCapsAcrossRecovery(t *testing.T) {
	c := config(t)
	c.Caps.CountHour = 1
	c.Caps.CountDay = 1
	x := opened(t, c, Intent{})
	id := hash([]byte("pending"))
	intent := Intent{BudgetSat: 1}
	r := record{ID: id, Phase: "reserved", Spec: rental.PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{}}}
	if e := x.reserve(operation{ID: id, Kind: "grant-issue", Intent: intent, At: 500}, r, nil); e != nil {
		t.Fatal(e)
	}
	wantError(t, x.capIssue(Intent{BudgetSat: 1}, 86401), "ISSUANCE_CAP")
	wantError(t, x.ready(499), "CLOCK_ROLLBACK")
	if e := x.capIssueExcept(intent, 86401, id); e != nil {
		t.Fatal("same reservation retry", e)
	}
}

// Fee refusal precedes identity/RPC/key access and preserves the whole state
// directory. The real lifecycle supplies the funded successful neighbor.
func TestFeeCapNoEffects(t *testing.T) {
	c := config(t)
	c.Caps.FeePerTx = 1
	i := Intent{BookingID: hash([]byte("fee-book")), ContractSHA256: hash([]byte("fee-contract")), BudgetSat: 1, PaymentCoin: "nmc", PaymentNetwork: "regtest", PaymentGenesis: su.RegtestGenesis, PaymentTxID: hash([]byte("fee-pay"))}
	x := opened(t, c, i)
	for _, role := range []string{"seal", "funding"} {
		script := c.Policy.Policy.SealScript
		if role == "funding" {
			script = c.Policy.Policy.FundingScript
		}
		x.state.Inventory = append(x.state.Inventory, Inventory{Input: su.PlanInput{Point: su.Point{TxID: hash([]byte(role))}, ValueSat: 2000000, Script: script, Role: role}})
	}
	before := encode(files(t, c.StateDir))
	item := Item{ID: hash([]byte("fee-id")), Kind: "grant-issue", Request: string(encode(map[string]string{"booking_id": i.BookingID})), Publication: `{}`}
	_, e := x.Process(context.Background(), encode(item), BookingSource, 500)
	wantError(t, e, "FEE_CAP")
	if !bytes.Equal(before, encode(files(t, c.StateDir))) || len(x.state.Operations) != 0 {
		t.Fatal("fee cap wrote state")
	}
}
