package singleuse

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func (l *coreLab) signedRequest(label string, change func(map[string]any)) []byte {
	l.t.Helper()
	key := os.Getenv("SUG_CORE_REQUESTER_KEY")
	if !filepath.IsAbs(key) {
		l.t.Fatal("absolute SUG_CORE_REQUESTER_KEY required")
	}
	var envelope map[string]string
	if e := json.Unmarshal(l.request, &envelope); e != nil {
		l.t.Fatal(e)
	}
	payload, e := base64.RawURLEncoding.DecodeString(envelope["payload"])
	if e != nil {
		l.t.Fatal(e)
	}
	var operation map[string]any
	if e = json.Unmarshal(payload, &operation); e != nil {
		l.t.Fatal(e)
	}
	change(operation)
	payload, e = json.Marshal(operation)
	if e != nil {
		l.t.Fatal(e)
	}
	path := filepath.Join(l.public, label+"-operation.json")
	if e = os.WriteFile(path, payload, 0600); e != nil {
		l.t.Fatal(e)
	}
	pub, e := base64.RawURLEncoding.DecodeString(l.template.RequesterSPKI)
	if e != nil {
		l.t.Fatal(e)
	}
	pubPath := filepath.Join(l.public, "requester.der")
	if e = os.WriteFile(pubPath, pub, 0600); e != nil {
		l.t.Fatal(e)
	}
	binary, e := os.ReadFile(l.signer)
	if e != nil || Hash(binary) != "7f9e8b1dd60244537ceb54b5096ad70b8cef4274c07a0af4cc7d81b1f04694ac" {
		l.t.Fatal("lab signer pin")
	}
	prepare := []string{"prepare-request", "--payload", path, "--requester-spki", pubPath}
	digest, e := exec.Command(l.signer, prepare...).Output()
	if e != nil {
		l.t.Fatal("prepare request", e)
	}
	args := []string{"request", "--payload", path, "--requester-spki", pubPath, "--key", key, "--digest", string(digest)}
	signed, e := exec.Command(l.signer, args...).Output()
	if e != nil {
		l.t.Fatal("authorized throwaway request signer", e)
	}
	l.rows = append(l.rows, map[string]any{"kind": "lab-signer", "argv": append([]string{l.signer}, args...), "exit_code": 0, "request_sha256": Hash(signed), "private_key_exported": false})
	return signed
}
func (l *coreLab) validNeighbor(label string) {
	l.t.Helper()
	p := l.state(l.newPolicy(), label+"-valid")
	l.use(p, "grantee", "ALL", nil, true)
	r, exit := l.invoke(p, l.request, label+"-valid")
	if exit != 0 || r.Status != "executed" || r.JournalPhase != "complete" || effectCount(l.t, p) != 1 || journalCount(l.t, p) != 1 {
		l.t.Fatalf("valid neighbor %+v exit%d", r, exit)
	}
}
func (l *coreLab) refused(p Policy, request []byte, label, reason string) {
	l.t.Helper()
	r, exit := l.invoke(p, request, label)
	if exit != 1 || r.Status != "refused" || r.Reason != reason || effectCount(l.t, p) != 0 || journalCount(l.t, p) != 0 {
		l.t.Fatalf("required refusal %s, got %+v exit%d effect%d journal%d", reason, r, exit, effectCount(l.t, p), journalCount(l.t, p))
	}
}
func changeCommitment(request []byte) func(*Transaction) {
	return func(tx *Transaction) {
		h, _ := hex.DecodeString(Hash(request))
		tx.Outputs[1].Script = append([]byte{0x6a, 32}, h...)
	}
}

// Every row has an actual Core-created/confirmed spend and a fresh valid
// neighbor. Refusal reasons and absence of journal/effect are explicit; these
// are genuine-node controls, not synthetic RPC replacements.
func TestGenuineCoreMatrix(t *testing.T) {
	l := newCoreLab(t)
	var passed []string
	run := func(name string, fn func()) {
		t.Run(name, func(st *testing.T) {
			old := l.t
			l.t = st
			defer func() { l.t = old }()
			fn()
			passed = append(passed, name)
		})
	}
	expired := l.signedRequest("expired", func(v map[string]any) { v["expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) })
	otherGrant := l.signedRequest("other-grant", func(v map[string]any) { v["certificate_id"] = "w3-other-grant" })
	otherRequest := l.signedRequest("other-request", func(v map[string]any) { v["request_id"] = "w3-other-request" })
	var badEnvelope map[string]string
	_ = json.Unmarshal(l.request, &badEnvelope)
	sig, _ := base64.RawURLEncoding.DecodeString(badEnvelope["signature"])
	sig[len(sig)-1] ^= 1
	badEnvelope["signature"] = base64.RawURLEncoding.EncodeToString(sig)
	badRequest, _ := json.Marshal(badEnvelope)
	newAddress := textValue(t, l.rpc("grantee", "getnewaddress", "", "legacy"))
	newKey := textValue(t, object(t, l.rpc("grantee", "getaddressinfo", newAddress))["pubkey"])
	cases := []struct {
		name, reason, role, sighash string
		request                     []byte
		tx                          func(*Transaction)
		policy                      func(*Policy)
	}{
		{name: "wrong-request-hash", reason: "REQUEST_COMMITMENT", tx: func(tx *Transaction) { tx.Outputs[1].Script[2] ^= 1 }},
		{name: "missing-opreturn", reason: "OP_RETURN_COUNT", tx: func(tx *Transaction) { tx.Outputs = tx.Outputs[:1] }},
		{name: "two-opreturns", reason: "OP_RETURN_COUNT", tx: func(tx *Transaction) { tx.Outputs = append(tx.Outputs, tx.Outputs[1]) }},
		{name: "short-hash-push", reason: "REQUEST_COMMITMENT", tx: func(tx *Transaction) { tx.Outputs[1].Script = tx.Outputs[1].Script[:33]; tx.Outputs[1].Script[1] = 31 }},
		{name: "long-hash-push", reason: "REQUEST_COMMITMENT", tx: func(tx *Transaction) {
			tx.Outputs[1].Script = append(tx.Outputs[1].Script, 0)
			tx.Outputs[1].Script[1] = 33
		}},
		{name: "nonminimal-hash-push", reason: "REQUEST_COMMITMENT", tx: func(tx *Transaction) {
			tx.Outputs[1].Script = append([]byte{0x6a, 0x4c, 32}, tx.Outputs[1].Script[2:]...)
		}},
		{name: "trailing-opreturn-byte", reason: "REQUEST_COMMITMENT", tx: func(tx *Transaction) { tx.Outputs[1].Script = append(tx.Outputs[1].Script, 0) }},
		{name: "nonzero-opreturn-value", reason: "REQUEST_COMMITMENT", tx: func(tx *Transaction) { tx.Outputs[1].Value = 1; tx.Outputs[0].Value-- }},
		{name: "issuer-with-request-hash", role: "issuer", reason: "ISSUER_REVOCATION"},
		{name: "issuer-without-request-hash", role: "issuer", reason: "ISSUER_REVOCATION", tx: func(tx *Transaction) { tx.Outputs = tx.Outputs[:1] }},
		{name: "sighash-none", sighash: "NONE", reason: "SIGHASH_ALL_REQUIRED"},
		{name: "sighash-anyonecanpay", sighash: "ALL|ANYONECANPAY", reason: "SIGHASH_ALL_REQUIRED"},
		{name: "invalid-request-signature", request: badRequest, tx: changeCommitment(badRequest), reason: "REQUEST_VERIFICATION"},
		{name: "expired-signed-request", request: expired, tx: changeCommitment(expired), reason: "REQUEST_VERIFICATION"},
		{name: "request-for-another-grant", request: otherGrant, tx: changeCommitment(otherGrant), reason: "REQUEST_VERIFICATION"},
		{name: "different-valid-request-after-spend", request: otherRequest, reason: "REQUEST_COMMITMENT"},
		{name: "wrong-grantee-pin", reason: "SEAL_SCRIPT_PIN", policy: func(p *Policy) { p.GranteeKey = newKey }},
		{name: "wrong-issuer-pin", reason: "SEAL_SCRIPT_PIN", policy: func(p *Policy) { p.IssuerKey = newKey }},
		{name: "equal-chain-key-pins", reason: "EQUAL_CHAIN_KEYS", policy: func(p *Policy) { p.IssuerKey = p.GranteeKey }},
		{name: "wrong-seal-script-pin", reason: "SEAL_SCRIPT_PIN", policy: func(p *Policy) { p.SealScript += "00" }},
		{name: "wrong-owner-payment-script", reason: "RAW_NAME_ANCHOR", policy: func(p *Policy) { p.OwnerPaymentScript = "51" }},
		{name: "wrong-certificate-hash", reason: "POLICY_BINDING", policy: func(p *Policy) { p.CertificateHash = Hash([]byte("other-certificate")) }},
		{name: "wrong-anchor-block", reason: "ANCHOR_CONFIRMATION", policy: func(p *Policy) { p.Anchor.Block = RegtestGenesis }},
		{name: "wrong-anchor-height", reason: "CURRENT_ANCHOR", policy: func(p *Policy) { p.Anchor.Height-- }},
	}
	for _, tc := range cases {
		run(tc.name, func() {
			p := l.state(l.newPolicy(), tc.name)
			role, mode := tc.role, tc.sighash
			if role == "" {
				role = "grantee"
			}
			if mode == "" {
				mode = "ALL"
			}
			l.use(p, role, mode, tc.tx, true)
			if tc.policy != nil {
				tc.policy(&p)
			}
			request := tc.request
			if request == nil {
				request = l.request
			}
			l.refused(p, request, tc.name, tc.reason)
			l.validNeighbor(tc.name)
		})
	}
	run("mempool-pending-then-confirm", func() {
		p := l.state(l.newPolicy(), "pending")
		l.use(p, "grantee", "ALL", nil, false)
		r, exit := l.invoke(p, l.request, "mempool-pending")
		if exit != 0 || r.Status != "pending" || journalCount(l.t, p) != 0 || effectCount(l.t, p) != 0 {
			l.t.Fatal(r, exit)
		}
		l.mine(1)
		r, exit = l.invoke(p, l.request, "pending-valid")
		if exit != 0 || r.Status != "executed" || effectCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
	})
	run("replay-and-other-request", func() {
		p := l.state(l.newPolicy(), "replay")
		l.use(p, "grantee", "ALL", nil, true)
		r, exit := l.invoke(p, l.request, "replay-valid")
		if exit != 0 || r.Status != "executed" {
			l.t.Fatal(r, exit)
		}
		r, exit = l.invoke(p, l.request, "replay-restart")
		if exit != 0 || r.Status != "already-executed" || effectCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
		r, exit = l.invoke(p, otherRequest, "replay-other-request")
		if exit != 1 || r.Reason != "DIFFERENT_REQUEST_AFTER_USE" || effectCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
	})
	run("confirmed-anchor-replacement", func() {
		p := l.state(l.newPolicy(), "replacement")
		l.use(p, "grantee", "ALL", nil, true)
		replacement := p
		l.anchor(&replacement, true)
		l.refused(p, l.request, "replaced-anchor", "CURRENT_ANCHOR")
		l.validNeighbor("replacement")
	})
	run("use-before-anchor", func() {
		p := l.state(l.newPolicy(), "before-anchor")
		l.use(p, "grantee", "ALL", nil, true)
		l.anchor(&p, true)
		l.refused(p, l.request, "use-before-anchor", "ANCHOR_USE_ORDER")
		l.validNeighbor("before-anchor")
	})
	run("same-block-anchor-and-use", func() {
		p := l.state(l.newPolicy(), "same-block")
		l.anchor(&p, false)
		l.use(p, "grantee", "ALL", nil, false)
		l.mine(1)
		l.refreshAnchor(&p)
		l.refused(p, l.request, "same-block", "ANCHOR_USE_ORDER")
		l.validNeighbor("same-block")
	})
	run("unconfirmed-anchor", func() {
		p := l.state(l.newPolicy(), "unconfirmed")
		oldBlock := p.Anchor.Block
		l.anchor(&p, false)
		p.Anchor.Block = oldBlock
		p.Anchor.Height++
		l.refused(p, l.request, "unconfirmed-anchor", "CURRENT_ANCHOR")
		l.mine(1)
		l.validNeighbor("unconfirmed")
	})
	run("hash-in-different-transaction", func() {
		p := l.state(l.newPolicy(), "different-tx")
		raw := textValue(l.t, l.rpc("", "createrawtransaction", []Point{}, []map[string]any{{"data": Hash(l.request)}}))
		funded := object(l.t, l.rpc("issuer", "fundrawtransaction", raw))
		l.send("issuer", textValue(l.t, funded["hex"]), "ALL", true)
		l.use(p, "grantee", "ALL", func(tx *Transaction) { tx.Outputs = tx.Outputs[:1] }, true)
		l.refused(p, l.request, "hash-other-tx", "OP_RETURN_COUNT")
		l.validNeighbor("different-tx")
	})
	l.lifecycleControls(run)
	status := "PASS"
	if t.Failed() {
		status = "FAIL"
	}
	l.save("result.json", map[string]any{"status": status, "negative_controls": len(passed), "passed_controls": passed, "genuine_core": true, "nonstandard_regtest_admission": true, "production_effect_authorized": false})
}

func (l *coreLab) refreshAnchor(p *Policy) {
	var v rpcTx
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", p.Anchor.TxID, true), &v); e != nil {
		l.t.Fatal(e)
	}
	p.Anchor.Block = v.Block
	var h header
	if e := json.Unmarshal(l.rpc("", "getblockheader", v.Block), &h); e != nil {
		l.t.Fatal(e)
	}
	p.Anchor.Height = h.Height
}
