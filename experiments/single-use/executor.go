package singleuse

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"relux.works/swarma-chain-lab/experiments/sealwatch"
)

type Receipt struct {
	Status                     string `json:"status"`
	Reason                     string `json:"reason"`
	RequestHash                string `json:"request_sha256"`
	SpendTxID                  string `json:"spend_txid,omitempty"`
	JournalPhase               string `json:"journal_phase,omitempty"`
	Calls                      int    `json:"read_calls"`
	LabOnly                    bool   `json:"lab_only"`
	ProductionEffectAuthorized bool   `json:"production_effect_authorized"`
}

// Execute appends only the fixed local laboratory effect. Hook is a test-driver
// fault-injection seam; the shipped executor CLI always supplies nil. A durable
// reservation is terminal for retries, even when the effect outcome is unknown.
func Execute(parent context.Context, node Node, p Policy, cert, req []byte, at time.Time, hook func(string)) Receipt {
	receipt := Receipt{Status: "refused", RequestHash: Hash(req), LabOnly: true}
	refuse := func(e error) Receipt { receipt.Reason = publicError(e); return receipt }
	if node == nil || parent == nil || at.IsZero() {
		return refuse(fail("INPUT"))
	}
	if e := p.validate(cert, req); e != nil {
		return refuse(e)
	}
	j, e := openJournal(p)
	if e != nil {
		return refuse(e)
	}
	defer j.close()
	bindingRaw, _ := json.Marshal(p)
	binding := Hash(bindingRaw)
	prior, e := j.read()
	if e != nil {
		return refuse(e)
	}
	if prior != nil {
		if prior.Binding != binding {
			return refuse(fail("JOURNAL_BINDING"))
		}
		if prior.Request != receipt.RequestHash {
			return refuse(fail("DIFFERENT_REQUEST_AFTER_USE"))
		}
		receipt.Status = "already-executed"
		receipt.SpendTxID = prior.Spend
		receipt.JournalPhase = prior.Phase
		receipt.Reason = "DURABLE_RESERVATION_NO_RETRY"
		return receipt
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	started := time.Now()
	at = at.UTC().Truncate(time.Second)
	if e = verifyRequest(ctx, p, cert, req, at); e != nil {
		return refuse(e)
	}
	o := &observation{ctx: ctx, node: node}
	spend, pending, e := o.proof(p, cert, req)
	receipt.Calls = o.calls
	receipt.SpendTxID = spend
	if e != nil {
		return refuse(e)
	}
	if pending {
		receipt.Status = "pending"
		receipt.Reason = "NO_CONFIRMED_USE"
		return receipt
	}
	if e = o.stable(); e != nil {
		receipt.Calls = o.calls
		return refuse(e)
	}
	if e = o.currentAnchor(p); e != nil {
		receipt.Calls = o.calls
		return refuse(e)
	}
	if e = verifyRequest(ctx, p, cert, req, at.Add(time.Since(started)).Truncate(time.Second)); e != nil {
		return refuse(e)
	}
	if e = o.stable(); e != nil {
		receipt.Calls = o.calls
		return refuse(e)
	}
	receipt.Calls = o.calls
	if hook != nil {
		hook("before-journal")
	}
	record := journalRecord{1, binding, receipt.RequestHash, spend, "reserved"}
	if e = j.write(record); e != nil {
		return refuse(e)
	}
	receipt.JournalPhase = "reserved"
	if hook != nil {
		hook("after-journal")
	}
	if e = j.effect(record); e != nil {
		return refuse(e)
	}
	if hook != nil {
		hook("after-effect")
	}
	record.Phase = "complete"
	if e = j.write(record); e != nil {
		return refuse(e)
	}
	receipt.Status = "executed"
	receipt.Reason = "CONFIRMED_GRANTEE_USE"
	receipt.JournalPhase = "complete"
	return receipt
}

func (o *observation) currentName(p Policy) (nameShow, error) {
	var n nameShow
	e := o.call("name_show", &n, p.OwnerName, map[string]string{"nameEncoding": "ascii", "valueEncoding": "ascii"})
	if e != nil {
		return n, e
	}
	if n.Name != p.OwnerName || n.TxID != p.Anchor.TxID || n.Vout != p.Anchor.Vout || n.Height != p.Anchor.Height || n.Expired || n.ExpiresIn <= 0 || n.NameEncoding != "ascii" || n.ValueEncoding != "ascii" || len(n.NameError) > 0 || len(n.ValueError) > 0 || len(n.Value) > 520 {
		return n, fail("CURRENT_ANCHOR")
	}
	for _, c := range []byte(n.Value) {
		if c > 127 {
			return n, fail("NAME_VALUE_ENCODING")
		}
	}
	var swarma json.RawMessage
	if e = sealwatch.ProjectJSON([]byte(n.Value), map[string]any{"swarma": &swarma}, nil); e != nil {
		return n, fail("NAME_VALUE_PROJECTION")
	}
	var owner, requester, certificate string
	var seal Point
	if e = sealwatch.ProjectJSON(swarma, map[string]any{"keyvault_owner_spki": &owner, "keyvault_certificate_sha256": &certificate, "keyvault_seal": &seal}, map[string]any{"keyvault_requester_spki": &requester}); e != nil {
		return n, fail("NAME_VALUE_PROJECTION")
	}
	if owner != p.OwnerSPKI || certificate != p.CertificateHash || seal != p.Seal {
		return n, fail("ANCHORED_GRANT_BINDING")
	}
	return n, nil
}
func (o *observation) currentAnchor(p Policy) error { _, e := o.currentName(p); return e }

func (o *observation) proof(p Policy, cert, req []byte) (string, bool, error) {
	if e := o.start(); e != nil {
		return "", false, e
	}
	name, e := o.currentName(p)
	if e != nil {
		return "", false, e
	}
	anchorView, anchorTx, e := o.transaction(p.Anchor.TxID)
	if e != nil {
		return "", false, e
	}
	anchorHeader, e := o.confirmed(anchorView)
	if e != nil || anchorView.Block != p.Anchor.Block || anchorHeader.Height != p.Anchor.Height {
		return "", false, fail("ANCHOR_CONFIRMATION")
	}
	if int(p.Anchor.Vout) >= len(anchorTx.Outputs) {
		return "", false, fail("ANCHOR_OUTPUT")
	}
	payment, _ := hex.DecodeString(p.OwnerPaymentScript)
	expected := NameUpdateScript(p.OwnerName, name.Value, payment)
	op := anchorView.Vout[p.Anchor.Vout].Script.Name
	if !bytes.Equal(anchorTx.Outputs[p.Anchor.Vout].Script, expected) || op == nil || op.Op != "name_update" || op.Name != name.Name || op.Value != name.Value || op.NameEncoding != "ascii" || op.ValueEncoding != "ascii" || len(op.NameError) > 0 || len(op.ValueError) > 0 {
		return "", false, fail("RAW_NAME_ANCHOR")
	}
	if e = RequestCommitment(anchorTx, cert); e != nil {
		return "", false, fail("ANCHOR_CERTIFICATE_COMMITMENT")
	}
	sealView, sealTx, e := o.transaction(p.Seal.TxID)
	if e != nil {
		return "", false, e
	}
	sealHeader, e := o.confirmed(sealView)
	if e != nil {
		return "", false, e
	}
	if sealHeader.Height >= p.Anchor.Height {
		return "", false, fail("SEAL_ANCHOR_ORDER")
	}
	if int(p.Seal.Vout) >= len(sealTx.Outputs) || sealTx.Outputs[p.Seal.Vout].Value <= 0 || hex.EncodeToString(sealTx.Outputs[p.Seal.Vout].Script) != p.SealScript {
		return "", false, fail("RAW_SEAL_BINDING")
	}
	if o.tip.Blocks-sealHeader.Height > 64 {
		return "", false, fail("SPEND_SCAN_BOUND")
	}
	type candidate struct {
		view rpcTx
		tx   *Transaction
	}
	var found []candidate
	seen := map[string]bool{}
	inspect := func(id string) error {
		if seen[id] {
			return nil
		}
		seen[id] = true
		view, tx, e := o.transaction(id)
		if e != nil {
			return e
		}
		for _, in := range tx.Inputs {
			if in.Point == p.Seal {
				found = append(found, candidate{view, tx})
				break
			}
		}
		return nil
	}
	for height := sealHeader.Height; height <= o.tip.Blocks; height++ {
		var blockHash string
		if e = o.call("getblockhash", &blockHash, height); e != nil {
			return "", false, e
		}
		b, e := o.block(blockHash, height)
		if e != nil {
			return "", false, e
		}
		// Core block order identifies the first transaction as coinbase. Its witness
		// serialization is irrelevant to a spend of a pre-existing seal.
		for _, id := range b.Tx[1:] {
			if e = inspect(id); e != nil {
				return "", false, e
			}
		}
	}
	var mempool []string
	if e = o.call("getrawmempool", &mempool); e != nil {
		return "", false, e
	}
	if mempool == nil || len(mempool) > 256 {
		return "", false, fail("MEMPOOL_BOUND")
	}
	for _, id := range mempool {
		if !digestHex(id) {
			return "", false, fail("MEMPOOL_TXID")
		}
		if e = inspect(id); e != nil {
			return "", false, e
		}
	}
	if len(found) > 1 {
		return "", false, fail("MULTIPLE_SEAL_SPENDS")
	}
	if len(found) == 0 {
		return "", true, o.stable()
	}
	spend := found[0]
	role, e := Attribute(spend.tx, p.Seal, p.IssuerKey, p.GranteeKey)
	if e != nil {
		return spend.view.TxID, false, e
	}
	if role != "grantee" {
		return spend.view.TxID, false, fail("ISSUER_REVOCATION")
	}
	if e = RequestCommitment(spend.tx, req); e != nil {
		return spend.view.TxID, false, e
	}
	if spend.view.Block == "" && spend.view.Confirmations == 0 {
		return spend.view.TxID, true, o.stable()
	}
	h, e := o.confirmed(spend.view)
	if e != nil {
		return spend.view.TxID, false, e
	}
	if h.Height <= p.Anchor.Height {
		return spend.view.TxID, false, fail("ANCHOR_USE_ORDER")
	}
	return spend.view.TxID, false, nil
}
