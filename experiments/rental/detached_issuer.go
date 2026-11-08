package rental

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

type IssueResult struct {
	Verdict   string          `json:"verdict"`
	Reason    string          `json:"reason"`
	ID        string          `json:"id,omitempty"`
	Envelope  json.RawMessage `json:"envelope,omitempty"`
	Admission Admission       `json:"admission"`
	Replay    bool            `json:"replay"`
}
type issuedDetached struct {
	Version       int             `json:"version"`
	Binding       string          `json:"binding"`
	RequestSHA256 string          `json:"request_sha256"`
	PackageSHA256 string          `json:"package_sha256"`
	BookingID     string          `json:"booking_id"`
	Seal          Point           `json:"seal"`
	Phase         string          `json:"phase"`
	ID            string          `json:"id"`
	Envelope      json.RawMessage `json:"envelope,omitempty"`
	Admission     Admission       `json:"admission"`
}

// IssueDetached signs no transaction and performs no broadcast. It authenticates
// the package, freshly admits payment and own-node name/seal state, fsyncs
// permanent booking+pool burns, then signs and persists one exact envelope.
// An uncertain reservation is never re-signed; a completed retry returns bytes.
func IssueDetached(ctx context.Context, node su.Node, p IssuerPolicy, request, publication []byte, pool Point, keyPath string, now int64) IssueResult {
	return issueDetached(ctx, node, p, request, publication, pool, keyPath, now, nil)
}
func issueDetached(ctx context.Context, node su.Node, p IssuerPolicy, request, publication []byte, pool Point, keyPath string, now int64, hook func(string)) (result IssueResult) {
	started := time.Now()
	result.Verdict = "refused"
	refuse := func(e error) IssueResult { result.Reason = e.Error(); return result }
	if e := p.Policy.validateDetached(); e != nil {
		return refuse(e)
	}
	var claimed IssuanceRequest
	if canonical(request, &claimed) != nil || !digest(claimed.BookingID) || !digest(pool.TxID) {
		return refuse(bad("ISSUANCE_REQUEST"))
	}
	bindingBytes, _ := json.Marshal(struct{ Network, Genesis, Agent, Script, Provider string }{p.Policy.Network, p.Policy.Genesis, p.Policy.AgentName, p.Policy.SealScript, p.ProviderPubkey})
	record := issuedDetached{Version: 2, Binding: Hash(bindingBytes), RequestSHA256: Hash(request), PackageSHA256: Hash(publication), BookingID: claimed.BookingID, Seal: pool, Phase: "reserved"}
	bookingKey, _ := json.Marshal(struct{ Network, Genesis, BookingID string }{p.Policy.Network, p.Policy.Genesis, claimed.BookingID})
	recordName := "issued-detached-" + Hash(bookingKey) + ".json"
	store, e := durable.Open(p.Policy.StateDir, "rental.lock")
	if e != nil {
		return refuse(e)
	}
	defer store.Close()
	prior, e := store.Read(recordName, 16384)
	if e != nil {
		return refuse(e)
	}
	if prior != nil {
		var old issuedDetached
		if canonical(prior, &old) != nil || old.Version != 2 || old.Binding != record.Binding || old.RequestSHA256 != record.RequestSHA256 || old.PackageSHA256 != record.PackageSHA256 || old.BookingID != record.BookingID || old.Seal != record.Seal {
			return refuse(bad("ISSUANCE_CONFLICT"))
		}
		if old.Phase == "reserved" && old.ID == "" && len(old.Envelope) == 0 {
			return refuse(bad("ISSUANCE_UNCERTAIN"))
		}
		env, e := ParseDetachedEnvelope(old.Envelope)
		if e != nil || old.Phase != "complete" || old.ID != Hash(old.Envelope) || env.Certificate.Seal != pool || env.Certificate.ContractSHA256 != claimed.ContractSHA256 || env.Certificate.AgentName != p.Policy.AgentName {
			return refuse(bad("ISSUANCE_JOURNAL_CORRUPT"))
		}
		result.Verdict = "issued"
		result.Reason = "EXACT_ENVELOPE_REPLAY"
		result.ID = old.ID
		result.Envelope = old.Envelope
		result.Admission = old.Admission
		result.Replay = true
		return result
	}
	if node == nil {
		return refuse(bad("NODE_UNAVAILABLE"))
	}
	o := su.NewReadObservation(ctx, node)
	defer o.Close()
	if e = o.Start(p.Policy.Network, p.Policy.Genesis); e != nil {
		return refuse(e)
	}
	name, keys, _, e := readAgentName(o, p.Policy.AgentName)
	if e != nil {
		return refuse(e)
	}
	script, e := GrantSealScript(keys.Grant)
	if e != nil || script != p.Policy.SealScript {
		return refuse(bad("SEAL_KEY_BINDING"))
	}
	key, e := readGrantKey(keyPath, keys.Grant)
	if e != nil {
		return refuse(e)
	}
	defer key.Zero()
	// Explicit compatibility mapping; the authenticated M3 package bytes are
	// never rewritten or re-signed. Existing online admission remains unchanged.
	admissionPolicy := p
	admissionPolicy.Policy.StationName = p.Policy.AgentName
	admissionPolicy.Policy.StationScript = script
	admissionPolicy.Policy.IssuerPubkey = keys.Grant
	admissionPolicy.Policy.AgentPubkey = keys.Nostr
	r, pack, e := VerifyIssuancePackage(admissionPolicy, request, publication, now)
	if e != nil {
		return refuse(e)
	}
	pending, memBefore, e := pendingAgentRotation(o, name, keys.Grant)
	if e != nil {
		return refuse(e)
	}
	if pending {
		return refuse(bad("PENDING_GRANT_ROTATION"))
	}
	v, tx, e := o.PaymentTransaction(pool.TxID)
	if e != nil {
		return refuse(e)
	}
	if v.Block == "" || v.Confirmations <= 0 {
		return refuse(bad("POOL_UNCONFIRMED"))
	}
	header, e := o.Confirmed(v)
	if e != nil {
		return refuse(e)
	}
	if uint64(pool.Vout) >= uint64(len(tx.Outputs)) {
		return refuse(bad("POOL_OUTPUT"))
	}
	output := tx.Outputs[pool.Vout]
	if output.Value < 100000 || hex.EncodeToString(output.Script) != script {
		return refuse(bad("POOL_KEY_BINDING"))
	}
	spent, e := sealSpent(o, pool, output, header)
	if e != nil {
		return refuse(e)
	}
	if spent {
		return refuse(bad("POOL_SPENT"))
	}
	result.Admission = AdmitIssuance(ctx, node, admissionPolicy, request, publication, now+int64(time.Since(started)/time.Second))
	if result.Admission.Verdict != "admit" {
		return refuse(bad(result.Admission.Reason))
	}
	again, e := currentName(o, p.Policy.AgentName)
	if e != nil {
		return refuse(e)
	}
	if !sameName(name, again) {
		return refuse(bad("NAME_CHANGED"))
	}
	pending, memAfter, e := pendingAgentRotation(o, name, keys.Grant)
	if e != nil {
		return refuse(e)
	}
	if pending {
		return refuse(bad("PENDING_GRANT_ROTATION"))
	}
	if !sameJSON(memBefore, memAfter) {
		return refuse(bad("MEMPOOL_CHANGED"))
	}
	spent, e = sealSpent(o, pool, output, header)
	if e != nil {
		return refuse(e)
	}
	if spent {
		return refuse(bad("POOL_SPENT"))
	}
	if e = o.Stable(); e != nil {
		return refuse(e)
	}
	current := now + int64(time.Since(started)/time.Second)
	if current >= pack.HoldExpiresAt {
		return refuse(bad("hold_expired_at_admission"))
	}
	if current >= r.NotAfter {
		return refuse(bad("ISSUANCE_BINDING"))
	}
	c := DetachedCertificate{Version: 2, Network: p.Policy.Network, Genesis: p.Policy.Genesis, AgentName: p.Policy.AgentName, IssuerKey: keys.Grant, GranteeKey: r.RenterPubkey, GranteeName: pack.Contract.RenterName, ContractSHA256: r.ContractSHA256, Scope: r.Scope, NotBefore: r.NotBefore, NotAfter: r.NotAfter, Seal: pool}
	if r.BudgetSat != 0 {
		budget := r.BudgetSat
		c.Budget = &budget
	}
	unsigned, e := c.Canonical()
	if e != nil {
		return refuse(e)
	}
	// Match the legacy planner's exact key encoding: a new profile must not
	// reset existing permanent pool or booking burns in the same state root.
	poolKey, _ := json.Marshal(struct {
		Network, Genesis string
		Point            Point
	}{p.Policy.Network, p.Policy.Genesis, pool})
	poolName := "pool-" + Hash(poolKey) + ".json"
	bookingName := "booking-" + Hash(bookingKey) + ".json"
	for _, item := range []struct{ name, reason string }{{poolName, "POOL_ALREADY_RESERVED"}, {bookingName, "BOOKING_ALREADY_RESERVED"}} {
		b, e := store.Read(item.name, 16384)
		if e != nil {
			return refuse(e)
		}
		if b != nil {
			return refuse(bad(item.reason))
		}
	}
	record.Admission = result.Admission
	reservation, _ := json.Marshal(struct {
		Version        int    `json:"version"`
		Network        string `json:"network"`
		Genesis        string `json:"genesis"`
		Point          Point  `json:"point"`
		BookingID      string `json:"booking_id"`
		UnsignedSHA256 string `json:"unsigned_sha256"`
	}{2, p.Policy.Network, p.Policy.Genesis, pool, r.BookingID, Hash(unsigned)})
	if e = store.Write(bookingName, reservation); e != nil {
		return refuse(e)
	}
	if e = store.Write(poolName, reservation); e != nil {
		return refuse(e)
	}
	b, _ := json.Marshal(record)
	if e = store.Write(recordName, b); e != nil {
		return refuse(e)
	}
	if hook != nil {
		hook("reserved")
	}
	if now+int64(time.Since(started)/time.Second) >= pack.HoldExpiresAt {
		return refuse(bad("hold_expired_at_admission"))
	}
	if now+int64(time.Since(started)/time.Second) >= r.NotAfter {
		return refuse(bad("ISSUANCE_BINDING"))
	}
	sig, e := schnorr.Sign(key, mustDecodeKey(Hash(unsigned)))
	if e != nil {
		return refuse(bad("GRANT_SIGNING"))
	}
	raw, e := json.Marshal(DetachedEnvelope{c, hex.EncodeToString(sig.Serialize())})
	if e != nil {
		return refuse(bad("GRANT_ENCODING"))
	}
	if hook != nil {
		hook("signed")
	}
	record.Envelope = raw
	record.ID = Hash(raw)
	record.Phase = "complete"
	b, _ = json.Marshal(record)
	if e = store.Write(recordName, b); e != nil {
		return refuse(e)
	}
	if hook != nil {
		hook("complete")
	}
	result.Verdict = "issued"
	result.Reason = "DETACHED_CERTIFICATE_ISSUED"
	result.ID = record.ID
	result.Envelope = raw
	return result
}
