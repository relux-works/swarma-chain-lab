package singleuse

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type discoveryNode struct {
	raw   json.RawMessage
	calls int
}

func (n *discoveryNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	n.calls++
	if method != "getrawtransaction" || len(args) != 2 || args[1] != true {
		return nil, fail("TEST_CALL")
	}
	return n.raw, nil
}

// Exact projected vin may establish irrelevance without decoding witness/raw
// bytes. Missing, aliased, duplicate, null or wrongly typed selection fields
// are never silently treated as an unrelated transaction.
func TestDiscoveryProjection(t *testing.T) {
	id, prev := strings.Repeat("11", 32), strings.Repeat("22", 32)
	good := `{"txid":"` + id + `","vin":[{"txid":"` + prev + `","vout":0}],"hex":"000000000001","vout":"irrelevant-extension"}`
	cases := []struct{ name, raw, want string }{
		{"unrelated-witness", good, ""},
		{"wrong-txid", strings.Replace(good, id, prev, 1), "DISCOVERY_TXID"},
		{"alias-txid", strings.Replace(good, `"txid"`, `"TXID"`, 1), "NODE_PROJECTION"},
		{"alias-vin", strings.Replace(good, `"vin"`, `"VIN"`, 1), "NODE_PROJECTION"},
		{"alias-vout", strings.Replace(good, `"vout":0`, `"VOUT":0`, 1), "NODE_PROJECTION"},
		{"null-vout", strings.Replace(good, `"vout":0`, `"vout":null`, 1), "NODE_PROJECTION"},
		{"missing-vout", strings.Replace(good, `,"vout":0`, "", 1), "NODE_PROJECTION"},
		{"string-vout", strings.Replace(good, `"vout":0`, `"vout":"0"`, 1), "NODE_PROJECTION"},
		{"overflow-vout", strings.Replace(good, `"vout":0`, `"vout":4294967296`, 1), "NODE_PROJECTION"},
		{"duplicate-vout", strings.Replace(good, `"vout":0`, `"vout":0,"vout":1`, 1), "NODE_PROJECTION"},
		{"conflicting-alias", strings.Replace(good, `"vout":0`, `"vout":0,"VOUT":1`, 1), "NODE_PROJECTION"},
		{"bad-prevout", strings.Replace(good, prev, "bad", 1), "DISCOVERY_INPUTS"},
		{"null-vin", `{"txid":"` + id + `","vin":null}`, "NODE_PROJECTION"},
		{"empty-vin", `{"txid":"` + id + `","vin":[]}`, "DISCOVERY_INPUTS"},
		{"coinbase", `{"txid":"` + id + `","vin":[{"coinbase":"00"}]}`, "NODE_PROJECTION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := &discoveryNode{raw: json.RawMessage(tc.raw)}
			o := observation{ctx: context.Background(), node: node}
			_, tx, e := o.spendCandidate(id, Point{strings.Repeat("33", 32), 0})
			if publicError(e) != tc.want || tx != nil || node.calls != 1 {
				t.Fatalf("%v %+v calls%d", e, tx, node.calls)
			}
		})
	}
}

// Candidate discovery and strict validation share the same RPC bytes. The
// genuine Core candidate passes; forged raw/projected outpoints cannot become
// a candidate without failing the existing raw binding checks. This is an
// offline parser test; end-to-end state invariants are exercised on Core too.
func TestDiscoveryCandidateBinding(t *testing.T) {
	b, e := os.ReadFile("testdata/grantee-spend.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture map[string]json.RawMessage
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	tx, seal, _, _ := coreFixture(t, "grantee")
	for _, mode := range []string{"valid", "forged-projection", "witness-candidate", "bad-raw"} {
		t.Run(mode, func(t *testing.T) {
			raw := append([]byte(nil), fixture["confirmed"]...)
			point := seal
			var view map[string]any
			if e := json.Unmarshal(raw, &view); e != nil {
				t.Fatal(e)
			}
			want := ""
			switch mode {
			case "forged-projection":
				point.Vout++
				view["vin"].([]any)[0].(map[string]any)["vout"] = point.Vout
				want = "RAW_INPUT_BINDING"
			case "witness-candidate":
				view["hex"] = "02000000000100000000"
				want = "LEGACY_INPUT_BOUND"
			case "bad-raw":
				view["hex"] = "zz"
				want = "TX_HEX"
			}
			raw, e = json.Marshal(view)
			if e != nil {
				t.Fatal(e)
			}
			node := &discoveryNode{raw: raw}
			o := observation{ctx: context.Background(), node: node}
			_, got, e := o.spendCandidate(tx.ID(), point)
			if publicError(e) != want || node.calls != 1 {
				t.Fatalf("%v calls%d", e, node.calls)
			}
			if want == "" && (got == nil || got.ID() != tx.ID()) {
				t.Fatal("valid candidate missing")
			}
			if want != "" && got != nil {
				t.Fatal("invalid candidate returned")
			}
		})
	}
}

type discoveryBlockNode struct{ raw json.RawMessage }

func (n discoveryBlockNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	if method != "getblock" || len(args) != 2 || args[1] != 2 {
		return nil, fail("TEST_CALL")
	}
	return n.raw, nil
}

// Verbose block discovery preserves exact context and unique official txids;
// the unparsed coinbase and unrelated witness metadata are harmless.
func TestDiscoveryBlockProjection(t *testing.T) {
	block, id, other := strings.Repeat("11", 32), strings.Repeat("22", 32), strings.Repeat("33", 32)
	good := `{"hash":"` + block + `","height":4,"tx":[{"txid":"` + id + `","vin":[{"coinbase":"00"}]},{"txid":"` + other + `","hex":"0001"}]}`
	for _, tc := range []struct{ name, raw, want string }{
		{"valid", good, ""},
		{"wrong-hash", strings.Replace(good, block, other, 1), "BLOCK_PROJECTION"},
		{"wrong-height", strings.Replace(good, `"height":4`, `"height":5`, 1), "BLOCK_PROJECTION"},
		{"height-alias", strings.Replace(good, `"height"`, `"HEIGHT"`, 1), "NODE_PROJECTION"},
		{"tx-alias", strings.Replace(good, `"tx"`, `"TX"`, 1), "NODE_PROJECTION"},
		{"txid-alias", strings.Replace(good, `"txid"`, `"TXID"`, 1), "NODE_PROJECTION"},
		{"duplicate-id", strings.Replace(good, other, id, 1), "BLOCK_TXIDS"},
		{"invalid-id", strings.Replace(good, other, "bad", 1), "BLOCK_TXIDS"},
		{"empty", `{"hash":"` + block + `","height":4,"tx":[]}`, "BLOCK_PROJECTION"},
		{"null", `{"hash":"` + block + `","height":4,"tx":null}`, "NODE_PROJECTION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := observation{ctx: context.Background(), node: discoveryBlockNode{json.RawMessage(tc.raw)}}
			_, ids, e := o.scanBlock(block, 4)
			if publicError(e) != tc.want || o.calls != 1 {
				t.Fatal(e, o.calls)
			}
			if tc.want == "" && (len(ids) != 2 || ids[1] != other) {
				t.Fatal(ids)
			}
		})
	}
}

// Context may be absent from Core v2 entries or agree exactly; conflicting
// explicit context is not replaced by a favorable enclosing block.
func TestDiscoveryBlockCandidateContext(t *testing.T) {
	b, e := os.ReadFile("testdata/grantee-spend.json")
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]json.RawMessage
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	tx, seal, _, _ := coreFixture(t, "grantee")
	for _, mode := range []string{"matching", "absent", "wrong-block", "wrong-confirmations", "empty-block"} {
		t.Run(mode, func(t *testing.T) {
			var view map[string]any
			if e := json.Unmarshal(f["confirmed"], &view); e != nil {
				t.Fatal(e)
			}
			block := view["blockhash"].(string)
			want := ""
			switch mode {
			case "absent":
				delete(view, "blockhash")
				delete(view, "confirmations")
			case "wrong-block":
				view["blockhash"] = RegtestGenesis
				want = "BLOCK_CANDIDATE_BINDING"
			case "wrong-confirmations":
				view["confirmations"] = 0
				want = "BLOCK_CANDIDATE_BINDING"
			case "empty-block":
				view["blockhash"] = ""
				want = "BLOCK_CANDIDATE_BINDING"
			}
			raw, e := json.Marshal(view)
			if e != nil {
				t.Fatal(e)
			}
			v, got, e := candidateInBlock(raw, tx.ID(), seal, block, 1)
			if publicError(e) != want {
				t.Fatal(e)
			}
			if want == "" && (got == nil || v.Block != block || v.Confirmations != 1) {
				t.Fatal("missing candidate context")
			}
			if want != "" && got != nil {
				t.Fatal("invalid candidate context accepted")
			}
		})
	}
}
