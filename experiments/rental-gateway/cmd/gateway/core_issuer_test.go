package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"time"
)

// issueBooking uses the actual booking package and watcher request unchanged.
// Only this regtest harness owns the separate issuer and isolated-wallet keys.
func (l *coreLab) issueBooking(b booking.Booking, provider string) []byte {
	l.t.Helper()
	ctx := context.Background()
	seal := l.seal()
	funding := l.output(l.address, l.script)
	dir := filepath.Join(l.private, "exchange-issuer")
	if err := os.Mkdir(dir, 0700); err != nil {
		l.t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "grant-key")
	if err := os.WriteFile(keyPath, l.issuer.Serialize(), 0600); err != nil {
		l.t.Fatal(err)
	}
	sealScript, _ := rental.GrantSealScript(l.issuerPub)
	policy := rental.Policy{Network: "regtest", Genesis: su.RegtestGenesis, AgentName: e2eAgentName, LandlordName: e2eLandlordName, SealScript: sealScript, FundingScript: l.script, StateDir: dir}
	spec := rental.PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: funding.TxID, Vout: funding.Vout}, ValueSat: 1000000, Script: l.script, Role: "funding"}}, ChangeScript: l.script}
	result := rental.IssueGrant(ctx, l.observer, rental.IssuerPolicy{Policy: policy, ProviderPubkey: provider}, jsonCanonical(b.Issuance), jsonCanonical(b.PackageEvent), seal, spec, keyPath, time.Now().Unix())
	if result.Verdict != "prepared" || result.Plan == nil {
		l.t.Fatalf("actual booking issuance: %s/%s", result.Verdict, result.Reason)
	}
	tx := su.Transaction{Version: result.Plan.TransactionVersion}
	for _, in := range result.Plan.Inputs {
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Sequence: 0xfffffffe})
	}
	for _, out := range result.Plan.Outputs {
		script, err := hex.DecodeString(out.Script)
		if err != nil {
			l.t.Fatal(err)
		}
		tx.Outputs = append(tx.Outputs, su.Output{Value: out.ValueSat, Script: script})
	}
	id := l.send(hex.EncodeToString(tx.Bytes()), true)
	proof, err := rental.PresentIssuedGrant(result.SignedGrant, id)
	if err != nil {
		l.t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"exchange-issuance.json": jsonCanonical(result), "exchange-presentation.json": proof, "exchange-booking.json": jsonCanonical(b)} {
		if err = os.WriteFile(filepath.Join(l.root, name), raw, 0600); err != nil {
			l.t.Fatal(err)
		}
	}
	return proof
}
