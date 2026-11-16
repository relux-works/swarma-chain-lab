package grantcheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	bitcoinwire "github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/identity"
	v4wire "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire"
)

type v4Vector struct {
	ID, Expect, Signature string
	SignedFormHex         string `json:"signed_form_hex"`
	Payload               string
	Digest                string `json:"typed_digest"`
	GrantID               string `json:"grant_id"`
	Address               string `json:"content_address"`
	SealScript            string `json:"seal_script"`
	Neighbour             string `json:"valid_neighbour"`
	Context               struct {
		Parent    string
		Reference *string
	}
}

func v4Vectors(t *testing.T) (map[string][]v4Vector, map[string]v4Vector) {
	t.Helper()
	raw, err := os.ReadFile("testdata/grant-v4.json")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != "66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106" {
		t.Fatal("pinned grant vectors", err)
	}
	var file map[string]json.RawMessage
	if json.Unmarshal(raw, &file) != nil {
		t.Fatal("fixture JSON")
	}
	groups, byID := map[string][]v4Vector{}, map[string]v4Vector{}
	for _, group := range []string{"valid", "invalid", "compound", "undetermined"} {
		var rows []v4Vector
		if json.Unmarshal(file[group], &rows) != nil {
			t.Fatal("fixture group", group)
		}
		groups[group] = rows
		for _, v := range rows {
			if v.ID == "" || byID[v.ID].ID != "" {
				t.Fatal("fixture id")
			}
			byID[v.ID] = v
		}
	}
	return groups, byID
}
func v4Hex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func v4Checker(t *testing.T, view HolderSealView) *Checker {
	t.Helper()
	c, err := New(Config{ContractProfile: ContractProfileV4, Network: "main", Genesis: MainGenesis, ConstructionProfile: "W", HolderSeals: view})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func v4Read(t *testing.T, c *Checker, v v4Vector, byID map[string]v4Vector) (*V4Document, error) {
	t.Helper()
	input := V4DocumentContext{Reference: v.Context.Reference}
	if v.Context.Parent != "" {
		p, err := v4Read(t, c, byID[v.Context.Parent], byID)
		if err != nil {
			t.Fatal("parent control", err)
		}
		input.Parent = p.Required
	}
	return c.VerifyV4Document(v4Hex(t, v.SignedFormHex), input)
}

// TestV4EmptyParent proves an unverified zero parent context refuses without a panic beside the same valid root and verified parent.
func TestV4EmptyParent(t *testing.T) {
	_, rows := v4Vectors(t)
	c := v4Checker(t, nil)
	raw := v4Hex(t, rows["grant-v-01"].SignedFormHex)
	control, err := c.VerifyV4Document(raw, V4DocumentContext{})
	if err != nil {
		t.Fatal("positive control", err)
	}
	if _, err := c.VerifyV4Document(raw, V4DocumentContext{Parent: control.Required}); err != nil {
		t.Fatal("verified parent control", err)
	}
	if document, err := c.VerifyV4Document(raw, V4DocumentContext{Parent: new(v4wire.SignedGrant)}); document != nil || !errors.Is(err, ErrV4Binding) {
		t.Fatal("zero parent admitted", err)
	}
}

func v4Code(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}
func v4Step(id, code string) int {
	switch code {
	case "WIRE_SIZE", "WIRE_JSON", "WIRE_DUPLICATE", "WIRE_VALUE", "WIRE_NUMBER", "WIRE_STRING", "WIRE_NOT_CANONICAL":
		return 1
	case "WIRE_MEMBER":
		if id == "grant-i-03" {
			return 2
		}
		return 4
	case "WIRE_TYPE":
		return 3
	case "WIRE_INTEGER", "WIRE_KEY":
		return 4
	case "WIRE_SIGNATURE_FORM":
		return 5
	case "CHAIN_DEPTH", "NOT_DELEGABLE":
		return 6
	case "WIRE_ID":
		if id == "grant-i-48" {
			return 8
		}
		return 6
	case "WIRE_SIGNATURE", "CHILD_SIGNER":
		return 7
	case "GRANT_SHAPE", "GRANT_DELEGATE":
		return 9
	}
	return 0
}

// TestV4DocumentVectors proves all 112 pinned vectors through the configured exported verifier, with exact hashes and refusal positions.
func TestV4DocumentVectors(t *testing.T) {
	groups, byID := v4Vectors(t)
	c := v4Checker(t, nil)
	counts := map[string]int{}
	var table bytes.Buffer
	for _, group := range []string{"valid", "invalid", "compound", "undetermined"} {
		for _, v := range groups[group] {
			counts[group]++
			t.Run(v.ID, func(t *testing.T) {
				if group != "valid" {
					control := v.Neighbour
					if control == "" {
						control = "grant-v-01"
					}
					if _, err := v4Read(t, c, byID[control], byID); err != nil {
						t.Fatal("positive control", err)
					}
				}
				d, err := v4Read(t, c, v, byID)
				want := v.Expect
				if group == "undetermined" {
					want = "ok"
				}
				if v4Code(err) != want {
					t.Fatalf("code = %s, want %s", v4Code(err), want)
				}
				proposal := want
				if err != nil {
					var failure *v4wire.GrantFailure
					if d != nil || !errors.As(err, &failure) || failure.Step != v4Step(v.ID, want) {
						t.Fatalf("precedence = %#v, want step %d", failure, v4Step(v.ID, want))
					}
				} else {
					proposal = d.ProposalOutcome
					if group == "valid" {
						g := d.Required
						digest := g.Digest()
						if !bytes.Equal(g.Bytes(), v4Hex(t, v.SignedFormHex)) || v.Payload != "" && string(g.Payload()) != v.Payload || hex.EncodeToString(digest[:]) != v.Digest || g.ID() != v.GrantID || g.ContentAddress() != v.Address || g.Signature() != v.Signature || hex.EncodeToString(g.SealScript()) != v.SealScript {
							t.Fatal("exact bytes or derived values differ")
						}
						if proposal != "ok" {
							t.Fatal("determined vector changed under proposals")
						}
					} else if proposal != "GRANT_DELEGATE" {
						t.Fatal("undetermined alternatives were collapsed")
					}
				}
				fmt.Fprintf(&table, "%s\t%s\t%s\n", v.ID, want, proposal)
			})
		}
	}
	for group, count := range map[string]int{"valid": 11, "invalid": 84, "compound": 13, "undetermined": 4} {
		if counts[group] != count {
			t.Fatalf("%s count %d, want %d", group, counts[group], count)
		}
	}
	if len(byID) != 112 {
		t.Fatalf("inventory %d, want 112", len(byID))
	}
	if path := os.Getenv("GRANT_VERDICT_TABLE"); path != "" {
		if bytes.Count(table.Bytes(), []byte{'\n'}) != 112 {
			t.Fatal("verdict table requires all 112 executed vectors")
		}
		if err := os.WriteFile(path, table.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestV4ClockMember proves a correctly signed grant with a clock member refuses WIRE_MEMBER beside a valid heights-only grant.
func TestV4ClockMember(t *testing.T) {
	_, byID := v4Vectors(t)
	c := v4Checker(t, nil)
	if _, err := v4Read(t, c, byID["grant-v-01"], byID); err != nil {
		t.Fatal("positive control", err)
	}
	var p map[string]any
	d := json.NewDecoder(strings.NewReader(byID["grant-v-01"].Payload))
	d.UseNumber()
	if d.Decode(&p) != nil {
		t.Fatal("fixture")
	}
	p["clock"] = uint64(1)
	payload, err := v4wire.EncodeDocument(p, v4wire.MaxGrantSize)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := v4wire.TypedDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	publicScalar := make([]byte, 32)
	publicScalar[31] = 3 // Published BIP-340 test scalar, never custody material.
	key, _ := btcec.PrivKeyFromBytes(publicScalar)
	sig := signHash(t, key, hex.EncodeToString(digest[:]))
	raw := append([]byte(`{"payload":`), payload...)
	raw = append(raw, []byte(`,"signature":"`+sig+`"}`)...)
	if _, err := c.VerifyV4Document(raw, V4DocumentContext{}); v4Code(err) != "WIRE_MEMBER" {
		t.Fatalf("clock code = %s, want WIRE_MEMBER", v4Code(err))
	}
}

// TestV4HeightWindow proves the inclusive opening/exclusive closing heights and recent-block floor without any clock input.
func TestV4HeightWindow(t *testing.T) {
	for _, tc := range []struct{ recent, tip uint64 }{{100, 199}, {100, 300}, {201, 250}, {100, v4wire.MaxNumber + 1}} {
		if !V4HeightWindowContains(100, 200, 300, 200) || !V4HeightWindowContains(100, 200, 300, 299) {
			t.Fatal("height positive control")
		}
		if V4HeightWindowContains(tc.recent, 200, 300, tc.tip) {
			t.Fatal("height outside the signed window admitted")
		}
	}
}

// TestV4ProfileBoundary proves configured profile/network dispatch is closed and the offline checker never emits Live or Exchange.
func TestV4ProfileBoundary(t *testing.T) {
	_, byID := v4Vectors(t)
	c := v4Checker(t, nil)
	for _, config := range []Config{
		{ContractProfile: "v4", ConstructionProfile: "W"},
		{ContractProfile: "v4", ConstructionProfile: "W", Network: "main", Genesis: genesisOf("regtest")},
	} {
		if _, err := New(Config{ContractProfile: "v4", ConstructionProfile: "W", Network: "main", Genesis: MainGenesis}); err != nil {
			t.Fatal("network positive control", err)
		}
		if _, err := New(config); err != ErrConfig {
			t.Fatal("network default or mismatched genesis admitted", err)
		}
	}
	for _, profile := range []string{ContractProfilePay, ContractProfileTrust} {
		if _, err := v4Read(t, c, byID["grant-v-01"], byID); err != nil {
			t.Fatal("v4 control", err)
		}
		// Real constructors, with each profile's established valid fixture.
		config := unitConfig(t)
		var checker *Checker
		var proof Presentation
		if profile == ContractProfilePay {
			checker, _, proof = unitChecker(t)
		} else {
			terms := trustV1(t, "regtest", nil)
			config = trustConfig(t, "regtest", genesisOf("regtest"), terms)
			checker, _ = trustChecker(t, config)
			proof = trustGrant(t, trustGrantSpec{Network: "regtest", Genesis: genesisOf("regtest"), Contract: terms})
		}
		if v := checker.Inbound(context.Background(), xonly(2), &proof); v.Decision != Live {
			t.Fatalf("%s positive control: %s", profile, v.Code)
		}
		if _, err := checker.VerifyV4Document(v4Hex(t, byID["grant-v-01"].SignedFormHex), V4DocumentContext{}); v4Code(err) != "WIRE_TYPE" {
			t.Fatal("v4 read under another configured profile", err)
		}
		if _, err := c.VerifyV4Document(proof.Bytes, V4DocumentContext{}); v4Code(err) != "WIRE_NOT_CANONICAL" {
			t.Fatal("v3 read as v4", err)
		}
		if v := checker.Inbound(context.Background(), xonly(2), &Presentation{Bytes: v4Hex(t, byID["grant-v-01"].SignedFormHex)}); v.Decision != Refused || v.Code != CodeInvalidPresentation {
			t.Fatal("v4 admission under other profile", v.Code)
		}
	}
	for _, v := range []Verdict{
		c.Inbound(context.Background(), xonly(2), nil),
		c.InboundFrom(context.Background(), SenderProof{Transport: NostrNIP17Seal, Key: xonly(2)}, nil),
		c.InboundFrom(context.Background(), SenderProof{Transport: SwarmEnvelopeV2, Key: xonly(2)}, nil),
		c.Provision(context.Background(), Presentation{}),
		c.Outbound(context.Background(), xonly(2)),
		c.OutboundFrom(context.Background(), RecipientProof{Transport: NostrNIP17Seal, Keys: []string{xonly(2)}}),
	} {
		if v.Decision != Refused || v.Code != CodeVerifierUnavailable || v.Closed {
			t.Fatal("offline profile became admission", v)
		}
	}
}

type holderFixtureView struct{ observation HolderSealObservation }

func (f holderFixtureView) ReadHolderSeal(context.Context, HolderSealRequest) (HolderSealObservation, error) {
	return f.observation, nil
}

// TestV4HolderView proves missing/non-enforcement-grade views refuse unavailable, while the isolated fixture distinguishes live and spent funding.
func TestV4HolderView(t *testing.T) {
	key := "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"
	tx := bitcoinwire.NewMsgTx(2)
	tx.AddTxOut(bitcoinwire.NewTxOut(1000, append([]byte{0, 20}, bytes.Repeat([]byte{1}, 20)...)))
	// A funding transaction needs an input to avoid witness-marker ambiguity.
	tx.AddTxIn(bitcoinwire.NewTxIn(&bitcoinwire.OutPoint{Index: 1}, nil, nil))
	var funding bytes.Buffer
	if tx.Serialize(&funding) != nil {
		t.Fatal("funding fixture")
	}
	seal := identity.HolderOutpoint{TxID: tx.TxHash().String()}
	list := []byte(`{"schema":"swarma-holders-list/1","network":"main","owner":"id/example","seq":1,"holders":[{"name":"id/example-agent","key":"` + key + `","seal":{"txid":"` + seal.TxID + `","vout":0}}]}`)
	hash := sha256.Sum256(list)
	value := []byte(fmt.Sprintf(`{"swarma-holders":{"seq":1,"sha256":"%x"}}`, hash))
	tip, anchor, block := HolderTip{strings.Repeat("a", 64), 200}, HolderTip{strings.Repeat("b", 64), 150}, HolderTip{strings.Repeat("c", 64), 100}
	request := HolderSealRequest{Seal: seal, Tip: tip, PinAnchor: anchor}
	live := HolderSealObservation{enforcementGrade: true, tip: tip, funding: funding.Bytes(), fundingBlock: block, unspent: true}
	check := func(t *testing.T, view HolderSealView, want string) {
		t.Helper()
		c := v4Checker(t, view)
		err := c.VerifyV4HolderDocument(context.Background(), value, list, "id/example", "id/example-agent", key, request)
		if v4Code(err) != want {
			t.Fatalf("holder code = %s, want %s", v4Code(err), want)
		}
	}
	for _, tc := range []struct {
		name string
		view HolderSealView
		want string
	}{
		{"missing", nil, "CLASS_HISTORY_UNAVAILABLE"},
		{"zero", holderFixtureView{}, "CLASS_HISTORY_UNAVAILABLE"},
		{"non-enforcement-grade", holderFixtureView{HolderSealObservation{tip: tip, funding: funding.Bytes(), fundingBlock: block, unspent: true}}, "CLASS_HISTORY_UNAVAILABLE"},
		{"spent", holderFixtureView{HolderSealObservation{enforcementGrade: true, tip: tip, funding: funding.Bytes(), fundingBlock: block}}, "HOLDER_SEAL_NOT_LIVE"},
		{"funded after anchor", holderFixtureView{HolderSealObservation{enforcementGrade: true, tip: tip, funding: funding.Bytes(), fundingBlock: HolderTip{block.Hash, 151}, unspent: true}}, "HOLDER_SEAL_NOT_LIVE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check(t, holderFixtureView{live}, "ok")
			check(t, tc.view, tc.want)
		})
	}
}

// TestV4GenesisBinding proves a valid main document refuses under the configured
// regtest binding; document bytes never select or change the configured network.
func TestV4GenesisBinding(t *testing.T) {
	_, rows := v4Vectors(t)
	raw := v4Hex(t, rows["grant-v-01"].SignedFormHex)
	if _, err := v4Checker(t, nil).VerifyV4Document(raw, V4DocumentContext{}); err != nil {
		t.Fatal("positive control", err)
	}
	c, err := New(Config{ContractProfile: ContractProfileV4, Network: "regtest", Genesis: genesisOf("regtest"), ConstructionProfile: "W"})
	if err != nil {
		t.Fatal(err)
	}
	if document, err := c.VerifyV4Document(raw, V4DocumentContext{}); document != nil || !errors.Is(err, ErrV4Binding) {
		t.Fatal("genesis binding accepted another network", err)
	}
}
