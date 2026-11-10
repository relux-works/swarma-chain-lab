package rehearsal

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental/oplocator"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Build a native W seal transaction and a deliberately non-W legacy anchor on the owned chain,
// with valid fixture issuer/consent signatures and the exact issuance commitment.
// This is hostile test construction, never native signer issuance or a fallback.
// The independent real node must refuse specifically W_WITNESS_REQUIRED without
// admission records, then admit the original native W grant as a valid neighbour.
func (l *lab) rejectNonW(original []byte, p rental.Policy, node su.Node) {
	t := l.t
	presentation, e := rental.ParseGrantPresentation(original)
	checked(t, e, "non-W neighbour presentation")
	addr := str(t, l.rpc("rehearsal", "getnewaddress", "", "legacy"))
	var info struct {
		Script string `json:"scriptPubKey"`
	}
	checked(t, json.Unmarshal(l.rpc("rehearsal", "getaddressinfo", addr), &info), "legacy control address")
	legacy, e := hex.DecodeString(info.Script)
	checked(t, e, "legacy control script")
	funding := str(t, l.rpc("rehearsal", "sendtoaddress", addr, su.Coins(2000000)))
	l.mine(1)
	var fund su.TransactionView
	checked(t, json.Unmarshal(l.rpc("", "getrawtransaction", funding, true), &fund), "legacy control funding")
	var point su.Point
	found := false
	for _, out := range fund.Vout {
		if out.Script.Hex == info.Script && int64(out.Value) == 2000000 {
			point = su.Point{TxID: funding, Vout: out.N}
			found = true
		}
	}
	if !found {
		t.Fatal("legacy control funding missing")
	}
	seal, e := hex.DecodeString(p.SealScript)
	checked(t, e, "control seal script")
	broadcast := func(tx su.Transaction) string {
		var result struct {
			Hex      string `json:"hex"`
			Complete bool   `json:"complete"`
		}
		checked(t, json.Unmarshal(l.rpc("rehearsal", "signrawtransactionwithwallet", hex.EncodeToString(tx.Bytes())), &result), "legacy control wallet signing")
		if !result.Complete {
			t.Fatal("legacy control signature incomplete")
		}
		return str(t, l.rpc("", "sendrawtransaction", result.Hex))
	}
	nativeAddr := str(t, l.rpc("rehearsal", "getnewaddress", "", "bech32"))
	var nativeInfo struct {
		Script string `json:"scriptPubKey"`
	}
	checked(t, json.Unmarshal(l.rpc("rehearsal", "getaddressinfo", nativeAddr), &nativeInfo), "native control funding script")
	nativeScript, e := hex.DecodeString(nativeInfo.Script)
	checked(t, e, "native control script bytes")
	if !su.NativeP2WPKH(nativeScript) {
		t.Fatal("non-W control T seed is not native")
	}
	nativeID := str(t, l.rpc("rehearsal", "sendtoaddress", nativeAddr, su.Coins(2000000)))
	l.mine(1)
	var nativeView su.TransactionView
	checked(t, json.Unmarshal(l.rpc("", "getrawtransaction", nativeID, true), &nativeView), "native control seed")
	var nativePoint su.Point
	found = false
	for _, out := range nativeView.Vout {
		if out.Script.Hex == nativeInfo.Script && int64(out.Value) == 2000000 {
			nativePoint = su.Point{TxID: nativeID, Vout: out.N}
			found = true
		}
	}
	if !found {
		t.Fatal("native control seed absent")
	}
	txT := broadcast(su.Transaction{Version: 2, Inputs: []su.Input{{Point: nativePoint, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 1000000, Script: seal}, {Value: 900000, Script: nativeScript}}})
	l.mine(1)
	forged := presentation.SignedGrant
	forged.Grant.Seal = rental.Point{TxID: txT, Vout: 0}
	digest, e := forged.Grant.SigningHash()
	checked(t, e, "control grant digest")
	message, e := hex.DecodeString(digest)
	checked(t, e, "control signature message")
	rawKey, e := os.ReadFile(filepath.Join(l.private, "grant.key"))
	checked(t, e, "fixture-only grant key")
	if len(rawKey) != 32 {
		t.Fatal("fixture issuer key length")
	}
	key, _ := btcec.PrivKeyFromBytes(rawKey)
	clear(rawKey)
	defer key.Zero()
	signature, e := schnorr.Sign(key, message)
	checked(t, e, "hostile control grant signature")
	forged.Signature = hex.EncodeToString(signature.Serialize())
	commitment, e := rental.IssuanceCommitment(forged)
	checked(t, e, "control issuance commitment")
	hash, e := hex.DecodeString(commitment)
	checked(t, e, "control commitment bytes")
	var c [32]byte
	copy(c[:], hash)
	pointer, e := hex.DecodeString(forged.ID())
	checked(t, e, "control grant pointer")
	op, e := oplocator.Build(oplocator.ActionGrantIssuance, c, oplocator.Locator{Type: oplocator.LocationBlob, Pointer: pointer})
	checked(t, e, "control OP_RETURN")
	txA := broadcast(su.Transaction{Version: 2, Inputs: []su.Input{{Point: point, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 0, Script: op}, {Value: 1900000, Script: legacy}}})
	l.mine(1)
	malicious := encoded(rental.GrantPresentation{SignedGrant: forged, Issuance: rental.IssuanceProof{TxID: txA}})
	_, e = rental.ParseGrantPresentation(malicious)
	checked(t, e, "control presentation signature validation")
	ctxT, cancelT := context.WithTimeout(context.Background(), 10*time.Second)
	observation := su.NewReadObservation(ctxT, node)
	checked(t, observation.Start(p.Network, p.Genesis), "control T observation")
	_, e = observation.WitnessCreation("W", su.Point{TxID: txT, Vout: 0})
	observation.Close()
	cancelT()
	checked(t, e, "control seal transaction must independently satisfy W")
	p.StateDir = l.dir("nonw-verifier")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	refusal := rental.Check(ctx, node, p, malicious, agentName, forged.Grant.GranteeKey, time.Now().Unix())
	cancel()
	if refusal.Verdict != "refused" || refusal.Reason != "W_WITNESS_REQUIRED" {
		t.Fatalf("non-W control not detected at W boundary: %s/%s", refusal.Verdict, refusal.Reason)
	}
	entries, e := os.ReadDir(p.StateDir)
	checked(t, e, "non-W state inventory")
	for _, v := range entries {
		if v.Name() != "rental.lock" {
			t.Fatal("non-W refusal wrote admission state")
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	positive := rental.Check(ctx, node, p, original, agentName, presentation.SignedGrant.Grant.GranteeKey, time.Now().Unix())
	cancel()
	if positive.Verdict != "live" || positive.Reason != "LIVE" {
		t.Fatal("native W neighbour refused after non-W control")
	}
	// The original signed grant remains byte-identical; the hostile sample has a
	// distinct seal/id and is never copied into gateway's presentation directory.
	if bytes.Equal(malicious, original) || forged.ID() == presentation.SignedGrant.ID() {
		t.Fatal("non-W plant not distinct")
	}
	l.evidence["non_w_anchor"] = map[string]any{"reason": refusal.Reason, "no_admission_state": true, "native_w_neighbour": "LIVE", "consensus_accepted_t": txT, "consensus_accepted_a": txA, "commitment": commitment, "hostile_grant_id": forged.ID(), "seal_transaction_w": true}
}
