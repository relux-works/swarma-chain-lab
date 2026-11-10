package signerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func snapshotTree(t *testing.T, root string) []byte {
	t.Helper()
	entries := map[string][]byte{}
	if e := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		entries[rel] = raw
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return encode(entries)
}

type fundingFixture struct {
	t                       *testing.T
	raw                     map[string][]byte
	height                  map[string]int64
	sends                   int
	name, nameValue, nameID string
}

func (n *fundingFixture) add(raw []byte, h int64) string {
	tx, e := su.DecodePaymentTransaction(raw)
	if e != nil {
		n.t.Fatal(e)
	}
	id := tx.ID()
	n.raw[id] = raw
	n.height[id] = h
	return id
}
func fixtureBlock(h int64) string {
	if h == 0 {
		return su.RegtestGenesis
	}
	return fmt.Sprintf("%064x", h)
}
func (n *fundingFixture) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	var result any
	switch method {
	case "name_show":
		result = map[string]any{"name": n.name, "value": n.nameValue, "txid": n.nameID, "vout": 0, "height": 190, "expires_in": 1000, "expired": false, "name_encoding": "ascii", "value_encoding": "ascii"}
	case "getrawmempool":
		ids := []string{}
		for id, h := range n.height {
			if h == 0 {
				ids = append(ids, id)
			}
		}
		result = ids
	case "getblockchaininfo":
		result = map[string]any{"chain": "regtest", "blocks": 200, "headers": 200, "bestblockhash": fixtureBlock(200), "initialblockdownload": false}
	case "getblockhash":
		var h int64
		switch x := args[0].(type) {
		case int:
			h = int64(x)
		case int64:
			h = x
		default:
			n.t.Fatal("height type")
		}
		result = fixtureBlock(h)
	case "getblockheader":
		id := args[0].(string)
		var h int64
		if id != su.RegtestGenesis {
			fmt.Sscanf(id, "%x", &h)
		}
		result = map[string]any{"hash": id, "height": h, "confirmations": 201 - h}
	case "getblock":
		id := args[0].(string)
		var h int64
		fmt.Sscanf(id, "%x", &h)
		ids := []string{}
		for txid, height := range n.height {
			if height == h {
				ids = append(ids, txid)
			}
		}
		result = map[string]any{"hash": id, "height": h, "tx": ids}
	case "getrawtransaction", "gettxout":
		id := args[0].(string)
		raw := n.raw[id]
		tx, e := su.DecodePaymentTransaction(raw)
		if e != nil {
			return nil, fmt.Errorf("missing fixture tx")
		}
		conf := int64(0)
		if n.height[id] > 0 {
			conf = 201 - n.height[id]
		}
		output := func(i int) map[string]any {
			o := tx.Outputs[i]
			script := map[string]any{"hex": hex.EncodeToString(o.Script)}
			if id == n.nameID {
				script["nameOp"] = map[string]any{"op": "name_update", "name": n.name, "value": n.nameValue, "name_encoding": "ascii", "value_encoding": "ascii"}
			}
			return map[string]any{"n": i, "value": json.Number(fmt.Sprintf("%d.%08d", o.Value/100000000, o.Value%100000000)), "scriptPubKey": script, "confirmations": conf}
		}
		if method == "gettxout" {
			var i int
			switch x := args[1].(type) {
			case uint32:
				i = int(x)
			case int:
				i = x
			default:
				n.t.Fatal("vout type")
			}
			result = output(i)
			break
		}
		vin := []any{}
		for _, in := range tx.Inputs {
			vin = append(vin, map[string]any{"txid": in.TxID, "vout": in.Vout, "scriptSig": map[string]any{"hex": hex.EncodeToString(in.Script)}})
		}
		vout := []any{}
		for i := range tx.Outputs {
			vout = append(vout, output(i))
		}
		view := map[string]any{"txid": id, "hex": hex.EncodeToString(raw), "vin": vin, "vout": vout, "confirmations": conf}
		if conf > 0 {
			view["blockhash"] = fixtureBlock(n.height[id])
		}
		result = view
	default:
		n.t.Fatal("unexpected or effect RPC", method)
	}
	return json.Marshal(result)
}
func (n *fundingFixture) Send(_ context.Context, raw []byte) (string, error) {
	n.sends++
	return n.add(raw, 0), nil
}
func newFundingFixture(t *testing.T, c Config) (*fundingFixture, su.PlanInput) {
	script, _ := hex.DecodeString(c.Policy.Policy.FundingScript)
	n := &fundingFixture{t: t, raw: map[string][]byte{}, height: map[string]int64{}}
	// This ordinary funding body's ancestry/confirmation is simulated by the
	// read-only node. Actual network acceptance is covered by opt-in Core tests.
	tx := &su.Transaction{Version: 2, Inputs: []su.Input{{Point: su.Point{TxID: hash([]byte("fixture ancestor"))}, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 2000000, Script: script}}}
	id := n.add(tx.Bytes(), 0)
	n.name = c.Policy.Policy.LandlordName
	n.nameValue = string(encode(map[string]any{"swarma": map[string]any{"landlord": map[string]any{"grant": c.Policy.Policy.IssuerPubkey}}}))
	nameTx := &su.Transaction{Version: 0x7100, Inputs: []su.Input{{Point: su.Point{TxID: hash([]byte("name ancestor"))}, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 1000000, Script: su.NameUpdateScript(n.name, n.nameValue, script)}}}
	n.nameID = n.add(nameTx.Bytes(), 190)
	return n, su.PlanInput{Point: su.Point{TxID: id}, ValueSat: 2000000, Script: c.Policy.Policy.FundingScript, Role: "funding"}
}

// Enrollment and refill re-observe ordinary funding. Unconfirmed funding must
// leave every durable file and in-memory ledger unchanged, with no broadcast;
// the exact output confirmed by one block is the valid neighbor. This default
// fixture tests service ordering and signatures, not node consensus.
func TestWitnessUnconfirmedFunding(t *testing.T) {
	for _, operation := range []string{"enroll", "refill"} {
		t.Run(operation, func(t *testing.T) {
			c := config(t)
			n, fund := newFundingFixture(t, c)
			x, e := Open(c, preflightIssuer{t, Intent{}}, n, n, noStore{t})
			if e != nil {
				t.Fatal(e)
			}
			defer x.Close()
			if operation == "refill" {
				n.height[fund.Point.TxID] = 200
				if e = x.Enroll(context.Background(), []su.PlanInput{fund}, 500); e != nil {
					t.Fatal(e)
				}
				n.height[fund.Point.TxID] = 0 // Re-observation after the confirmation disappears.
			}
			memory, disk := encode(x.state), snapshotTree(t, c.StateDir)
			call := func() error {
				if operation == "enroll" {
					return x.Enroll(context.Background(), []su.PlanInput{fund}, 500)
				}
				_, e := x.Refill(context.Background(), 500)
				return e
			}
			wantError(t, call(), "W_UNCONFIRMED_NON_LINKAGE_PARENT")
			if n.sends != 0 || !bytes.Equal(memory, encode(x.state)) || !bytes.Equal(disk, snapshotTree(t, c.StateDir)) {
				t.Fatal("funding refusal had effects")
			}
			n.height[fund.Point.TxID] = 200
			if e = call(); e != nil {
				t.Fatal("confirmed funding neighbor", e)
			}
			if operation == "refill" && n.sends != 1 {
				t.Fatal("refill neighbor did not broadcast once", n.sends)
			}
		})
	}
}

// A valid signed T with two distinct native change outputs grants only one
// unconfirmed linkage exception. Refusing the second preserves all state;
// enrolling the same seal with exactly one L succeeds and never broadcasts.
func TestWitnessSecondLinkage(t *testing.T) {
	c := config(t)
	n, fund := newFundingFixture(t, c)
	n.height[fund.Point.TxID] = 199
	key, e := loadKey(c.FundingKeyPath, c.Policy.Policy.FundingScript)
	if e != nil {
		t.Fatal(e)
	}
	defer key.Zero()
	plan := rental.Plan{ConstructionProfile: "W", Kind: "refill", TransactionVersion: 2, Inputs: []su.PlanInput{fund}, Outputs: []su.PlanOutput{{ValueSat: 200000, Script: c.Policy.Policy.SealScript}, {ValueSat: 800000, Script: c.Policy.Policy.FundingScript}, {ValueSat: 800000, Script: c.Policy.Policy.FundingScript}}, MaxSignedVBytes: 1000}
	raw, _, e := signPlan(plan, key)
	if e != nil {
		t.Fatal(e)
	}
	id := n.add(raw, 0)
	seal := su.PlanInput{Point: su.Point{TxID: id, Vout: 0}, ValueSat: 200000, Script: c.Policy.Policy.SealScript, Role: "seal"}
	link := su.PlanInput{Point: su.Point{TxID: id, Vout: 1}, ValueSat: 800000, Script: c.Policy.Policy.FundingScript, Role: "funding"}
	second := link
	second.Point.Vout = 2
	x, e := Open(c, preflightIssuer{t, Intent{}}, n, n, noStore{t})
	if e != nil {
		t.Fatal(e)
	}
	defer x.Close()
	memory, disk := encode(x.state), snapshotTree(t, c.StateDir)
	wantError(t, x.Enroll(context.Background(), []su.PlanInput{seal, link, second}, 500), "W_LINKAGE_REQUIRED")
	if n.sends != 0 || !bytes.Equal(memory, encode(x.state)) || !bytes.Equal(disk, snapshotTree(t, c.StateDir)) {
		t.Fatal("second linkage refusal had effects")
	}
	if e = x.Enroll(context.Background(), []su.PlanInput{seal, link}, 500); e != nil {
		t.Fatal("single linkage neighbor", e)
	}
	if n.sends != 0 {
		t.Fatal("enrollment broadcast")
	}
}
