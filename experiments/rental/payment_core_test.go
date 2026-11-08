package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type paymentReplyMutation struct {
	base    su.Node
	id      string
	edit    func([]byte) []byte
	applied int
}

func (n *paymentReplyMutation) Call(ctx context.Context, m string, args ...any) (json.RawMessage, error) {
	b, e := n.base.Call(ctx, m, args...)
	if e != nil || m != "getrawtransaction" || len(args) < 1 || args[0] != n.id {
		return b, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return nil, bad("TEST_MUTATION")
	}
	var encoded string
	if json.Unmarshal(fields["hex"], &encoded) != nil {
		return nil, bad("TEST_MUTATION")
	}
	raw, e := hex.DecodeString(encoded)
	if e != nil {
		return nil, e
	}
	fields["hex"], _ = json.Marshal(hex.EncodeToString(n.edit(raw)))
	n.applied++
	return json.Marshal(fields)
}

// A real Core P2WPKH wallet funds a booking payment. Both policies refuse it
// in mempool, admit after active confirmation and refuse after rollback.
// Malformed-witness cases explicitly mutate a real Core reply (not consensus
// transactions) and must refuse before any reservation; each has an unmodified
// confirmed witness neighbor. Legacy payment controls remain in the other suite.
func TestCoreWitnessPayment(t *testing.T) {
	l := newCore(t)
	p := l.policy("witness-payment")
	_, provider := testKey(4)
	ip := IssuerPolicy{p, provider}
	l.rpc("", "createwallet", "payer")
	address := text(t, l.rpc("payer", "getnewaddress", "", "bech32"))
	payScript := text(t, object(t, l.rpc("payer", "getaddressinfo", address))["scriptPubKey"])
	fund, _ := l.payment(5000000, payScript, true)
	stationScript, _ := hex.DecodeString(l.script)
	changeScript, _ := hex.DecodeString(payScript)
	tx := su.Transaction{Version: 2, Inputs: []su.Input{{Point: su.Point{TxID: fund, Vout: 0}, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 1000000, Script: stationScript}, {Value: 3900000, Script: changeScript}}}
	signed := object(t, l.rpc("payer", "signrawtransactionwithwallet", hex.EncodeToString(tx.Bytes())))
	if string(signed["complete"]) != "true" {
		t.Fatal("incomplete wallet signature")
	}
	wireHex := text(t, signed["hex"])
	wire, e := hex.DecodeString(wireHex)
	if e != nil || len(wire) < 6 || !bytes.Equal(wire[4:6], []byte{0, 1}) {
		t.Fatal("not witness serialization")
	}
	id := text(t, l.rpc("", "sendrawtransaction", wireHex))
	var view su.TransactionView
	if e = json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &view); e != nil {
		t.Fatal(e)
	}
	full := object(t, l.rpc("", "getrawtransaction", id, true))
	wtxid := text(t, full["hash"])
	stripped, e := su.DecodePaymentTransaction(wire)
	if e != nil || stripped.ID() != id || wtxid == id {
		t.Fatal("Core stripped txid binding", e)
	}
	l.save("witness-payment.json", full)
	passed := []string{}
	check := func(label string, node su.Node, req, event []byte, verdict, reason string) {
		l.t.Helper()
		a := AdmitIssuance(context.Background(), node, ip, req, event, 500)
		l.save(label+".json", a)
		if a.Verdict != verdict || a.Reason != reason {
			l.t.Fatalf("%s: %+v", label, a)
		}
		files, e := os.ReadDir(p.StateDir)
		if e != nil || len(files) != 0 {
			l.t.Fatal("read-only admission wrote state", e)
		}
		passed = append(passed, label)
	}
	_, startReq, startEvent := l.requestFor(testCertificate(), id, "start_now")
	_, advanceReq, advanceEvent := l.requestFor(testCertificate(), id, "advance")
	check("witness-mempool-start-now", l.observer, startReq, startEvent, "refused", "payment_unconfirmed")
	check("witness-mempool-advance", l.observer, advanceReq, advanceEvent, "refused", "payment_unconfirmed")
	l.mine(1)
	// Same historical request (height zero) is accepted only after a fresh node
	// observation proves confirmation; request fields cannot supply that proof.
	check("witness-confirmed-start-now", l.observer, startReq, startEvent, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	check("witness-confirmed-advance", l.observer, advanceReq, advanceEvent, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	witnessAt := len(stripped.Bytes()) - 4 + 2
	for _, mode := range []string{"zero-flag", "unknown-flag", "nonminimal-stack", "oversize-item", "truncated", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			parent := l.t
			l.t = t
			defer func() { l.t = parent }()
			want := "WITNESS_FLAG"
			n := &paymentReplyMutation{base: l.observer, id: id, edit: func(b []byte) []byte {
				switch mode {
				case "zero-flag":
					b[5] = 0
				case "unknown-flag":
					b[5] = 3
				case "nonminimal-stack":
					want = "WITNESS_STACK_BOUND"
					n := b[witnessAt]
					if n == 0 || n >= 253 {
						t.Fatal("unexpected stack")
					}
					b = append(append(bytes.Clone(b[:witnessAt]), 253, n, 0), b[witnessAt+1:]...)
				case "oversize-item":
					want = "WITNESS_ITEM_BOUND"
					b = append(append(bytes.Clone(b[:witnessAt+1]), 253, 17, 39), b[witnessAt+2:]...)
				case "truncated":
					want = "TX_TRAILING"
					b = b[:len(b)-1]
				case "trailing":
					want = "TX_TRAILING"
					b = append(b, 0)
				}
				return b
			}}
			// Resolve the expected reason before the admission call evaluates it.
			_ = n.edit(bytes.Clone(wire))
			check(mode, n, startReq, startEvent, "refused", want)
			if n.applied != 1 {
				t.Fatal("mutation not applied exactly once", n.applied)
			}
			check(mode+"-valid-neighbor", l.observer, startReq, startEvent, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
		})
	}
	if e = json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &view); e != nil {
		t.Fatal(e)
	}
	l.rpc("", "invalidateblock", view.Block)
	check("witness-rollback", l.observer, startReq, startEvent, "refused", "payment_unconfirmed")
	l.rpc("", "reconsiderblock", view.Block)
	check("witness-restored", l.observer, startReq, startEvent, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	l.save("witness-payment-result.json", map[string]any{"status": "PASS", "txid": id, "wtxid": wtxid, "cases": passed, "malformed_cases_are_reply_mutations": true, "no_admission_state_writes": true})
}
