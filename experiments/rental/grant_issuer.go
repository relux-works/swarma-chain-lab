package rental

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
	"time"
)

type GrantIssueResult struct {
	Verdict          string          `json:"verdict"`
	Reason           string          `json:"reason"`
	GrantID          string          `json:"grant_id,omitempty"`
	SignedGrant      json.RawMessage `json:"signed_grant,omitempty"`
	Plan             *Plan           `json:"plan,omitempty"`
	Admission        Admission       `json:"admission"`
	Replay           bool            `json:"replay"`
	PaymentAdmission *AdmissionV2    `json:"payment_admission,omitempty"`
}
type issuedGrant struct {
	Version          int             `json:"version"`
	Binding          string          `json:"binding"`
	RequestSHA256    string          `json:"request_sha256"`
	PackageSHA256    string          `json:"package_sha256"`
	SpecSHA256       string          `json:"spec_sha256"`
	BookingID        string          `json:"booking_id"`
	Seal             Point           `json:"seal"`
	Phase            string          `json:"phase"`
	GrantID          string          `json:"grant_id"`
	SignedGrant      json.RawMessage `json:"signed_grant,omitempty"`
	Plan             *Plan           `json:"plan,omitempty"`
	Admission        Admission       `json:"admission"`
	PaymentAdmission *AdmissionV2    `json:"payment_admission,omitempty"`
}

// IssueGrant prepares a signed v3 grant and unsigned issuance plan. Both
// landlord signatures follow durable booking/pool burns; ambiguous recovery
// never signs again. An operator must separately broadcast the commitment and
// provide its confirmed txid to Check before the grant can become live.
func IssueGrant(ctx context.Context, node su.Node, p IssuerPolicy, request, publication []byte, pool Point, spec PlanSpec, keyPath string, now int64) GrantIssueResult {
	return issueGrant(ctx, node, p, request, publication, pool, spec, keyPath, now, nil)
}
func issueGrant(ctx context.Context, node su.Node, p IssuerPolicy, request, publication []byte, pool Point, spec PlanSpec, keyPath string, now int64, hook func(string)) GrantIssueResult {
	return issueGrantRouted(ctx, node, p, request, publication, pool, spec, keyPath, now, hook, nil, readGrantKey)
}
func issueGrantRouted(ctx context.Context, node su.Node, p IssuerPolicy, request, publication []byte, pool Point, spec PlanSpec, keyPath string, now int64, hook func(string), payment *grantPaymentRoute, readKey func(string, string) (*secp.PrivateKey, error)) (result GrantIssueResult) {
	started := time.Now()
	result.Verdict = "refused"
	refuse := func(e error) GrantIssueResult { result.Reason = e.Error(); return result }
	if e := p.Policy.validateGrantFunding(); e != nil {
		return refuse(e)
	}
	claimed, claimErr := decodeGrantIntent(request, payment != nil)
	if claimErr != nil || !digest(claimed.BookingID) || !digest(pool.TxID) {
		return refuse(bad("ISSUANCE_REQUEST"))
	}
	// Check shared funding facts before touching the journal. Fee/framing is
	// selected only after distinguishing a completed replay from fresh issuance.
	if _, _, e := grantFundingInputs(p.Policy, spec, pool); e != nil {
		return refuse(e)
	}
	binding, _ := json.Marshal(struct{ Network, Genesis, Agent, Landlord, Script, Funding, Provider, Construction string }{p.Policy.Network, p.Policy.Genesis, p.Policy.AgentName, p.Policy.LandlordName, p.Policy.SealScript, p.Policy.FundingScript, p.ProviderPubkey, p.Policy.ConstructionProfile})
	if payment != nil {
		binding, _ = json.Marshal(struct {
			Identity       json.RawMessage
			PaymentVersion int
			Policies       map[string]PaymentAdmissionPolicy
		}{binding, 2, payment.policies})
	}
	sb, _ := json.Marshal(spec)
	record := issuedGrant{Version: 3, Binding: Hash(binding), RequestSHA256: Hash(request), PackageSHA256: Hash(publication), SpecSHA256: Hash(sb), BookingID: claimed.BookingID, Seal: pool, Phase: "reserved"}
	bookingKey, _ := json.Marshal(struct{ Network, Genesis, BookingID string }{p.Policy.Network, p.Policy.Genesis, claimed.BookingID})
	recordName := "issued-grant-" + Hash(bookingKey) + ".json"
	store, e := durable.Open(p.Policy.StateDir, "rental.lock")
	if e != nil {
		return refuse(e)
	}
	defer store.Close()
	poolReservation := func(point Point) string {
		b, _ := json.Marshal(struct {
			Network, Genesis string
			Point            Point
		}{p.Policy.Network, p.Policy.Genesis, point})
		return "pool-" + Hash(b) + ".json"
	}
	checkFundingReservation := func(point Point) error {
		b, e := store.Read(poolReservation(point), 16384)
		if e != nil {
			return e
		}
		// Existence is enough: complete, reserved and corrupt records all burn
		// this point. Never reinterpret an uncertain pool seal as ordinary funds.
		if b != nil {
			return bad("FUNDING_RESERVED_POOL")
		}
		return nil
	}
	// Replay is not allowed to return an old plan whose funds became a pool
	// seal since preparation. Current known inventory was checked above too.
	for _, in := range spec.Inputs {
		if e = checkFundingReservation(Point{in.Point.TxID, in.Point.Vout}); e != nil {
			return refuse(e)
		}
	}
	prior, e := store.Read(recordName, 16384)
	if e != nil {
		return refuse(e)
	}
	if prior != nil {
		var old issuedGrant
		if canonical(prior, &old) != nil || old.Version != 3 || old.Binding != record.Binding || old.RequestSHA256 != record.RequestSHA256 || old.PackageSHA256 != record.PackageSHA256 || old.SpecSHA256 != record.SpecSHA256 || old.BookingID != record.BookingID || old.Seal != pool {
			return refuse(bad("ISSUANCE_CONFLICT"))
		}
		if old.Phase == "reserved" && old.GrantID == "" && len(old.SignedGrant) == 0 && old.Plan == nil {
			return refuse(bad("ISSUANCE_UNCERTAIN"))
		}
		signed, e := ParseSignedGrant(old.SignedGrant)
		if e != nil || old.Phase != "complete" || old.GrantID != signed.ID() || signed.Grant.Seal != pool || signed.Grant.ContractSHA256 != claimed.ContractSHA256 {
			return refuse(bad("ISSUANCE_JOURNAL_CORRUPT"))
		}
		if !matchesIssuedGrantPlan(p.Policy, spec, old.SignedGrant, old.Plan) {
			return refuse(bad("ISSUANCE_JOURNAL_CORRUPT"))
		}
		result.Verdict = "prepared"
		result.Reason = "EXACT_GRANT_REPLAY"
		result.GrantID = old.GrantID
		result.SignedGrant = old.SignedGrant
		result.Plan = old.Plan
		if payment != nil {
			if !validStoredPaymentAdmission(old.PaymentAdmission, request) {
				return refuse(bad("ISSUANCE_JOURNAL_CORRUPT"))
			}
		} else if old.PaymentAdmission != nil {
			return refuse(bad("ISSUANCE_JOURNAL_CORRUPT"))
		}
		result.PaymentAdmission = old.PaymentAdmission
		result.Admission = old.Admission
		result.Replay = true
		return result
	}
	// Fresh issuance must fund the larger framed output before any reservation
	// or signature. Completed bare records above retain their original fee floor.
	if _, _, e := grantFunding(p.Policy, spec, pool); e != nil {
		return refuse(e)
	}
	if node == nil {
		return refuse(bad("NODE_UNAVAILABLE"))
	}
	o := su.NewReadObservation(ctx, node)
	defer o.Close()
	if e = o.Start(p.Policy.Network, p.Policy.Genesis); e != nil {
		return refuse(e)
	}
	agent, _, e := readNameGeneration(o, p.Policy.AgentName)
	if e != nil {
		return refuse(e)
	}
	ab, e := ParseAgentBinding(agent.Value)
	if e != nil {
		return refuse(e)
	}
	if ab.Landlord != p.Policy.LandlordName {
		return refuse(bad("AGENT_LANDLORD_MISMATCH"))
	}
	landlord, _, e := readNameGeneration(o, p.Policy.LandlordName)
	if e != nil {
		return refuse(e)
	}
	lb, e := ParseLandlordValue(landlord.Value)
	if e != nil {
		return refuse(e)
	}
	script, e := GrantSealScript(lb.Grant)
	if e != nil || script != p.Policy.SealScript {
		return refuse(bad("SEAL_KEY_BINDING"))
	}
	key, e := readKey(keyPath, lb.Grant)
	if e != nil {
		return refuse(e)
	}
	defer key.Zero()
	admissionPolicy := p
	admissionPolicy.Policy.StationName = p.Policy.AgentName
	admissionPolicy.Policy.StationScript = script
	admissionPolicy.Policy.IssuerPubkey = lb.Grant
	admissionPolicy.Policy.AgentPubkey = ab.Nostr
	req, pack, e := verifyGrantIntent(admissionPolicy, payment, request, publication, now)
	if e != nil {
		return refuse(e)
	}
	memBefore, e := pendingGrantBinding(o, agent, landlord, p.Policy.LandlordName, lb.Grant)
	if e != nil {
		return refuse(e)
	}
	creation, e := o.WitnessCreation(p.Policy.ConstructionProfile, su.Point{TxID: pool.TxID, Vout: pool.Vout})
	if e != nil {
		return refuse(e)
	}
	// The signed seal outpoint authenticates this exact non-witness T body.
	if creation.Body.ID() != pool.TxID {
		return refuse(bad("W_BODY_BINDING"))
	}
	checkOutput := func(point Point, value int64, role string) error {
		if role == "FUNDING" {
			if e := checkFundingReservation(point); e != nil {
				return e
			}
		}
		v, tx, e := o.FundingTransaction(point.TxID)
		if e != nil {
			return e
		}
		linked := point.TxID == pool.TxID && point.Vout != pool.Vout
		unconfirmed := v.Block == "" && v.Confirmations == 0
		if unconfirmed && role == "POOL" {
			found := false
			for _, in := range spec.Inputs {
				if in.Point.TxID == pool.TxID && in.Point.Vout != pool.Vout {
					found = true
				}
			}
			if !found {
				return bad("W_LINKAGE_REQUIRED")
			}
		}
		if unconfirmed && role == "FUNDING" && !linked {
			return bad("W_UNCONFIRMED_NON_LINKAGE_PARENT")
		}
		var h su.Header
		if !unconfirmed {
			h, e = o.Confirmed(v)
			if e != nil {
				return e
			}
		} else if role != "POOL" && !linked {
			return bad("W_UNCONFIRMED_NON_LINKAGE_PARENT")
		}

		if uint64(point.Vout) >= uint64(len(tx.Outputs)) {
			return bad(role + "_OUTPUT")
		}
		out := tx.Outputs[point.Vout]
		wantScript := script
		if role == "FUNDING" {
			if hex.EncodeToString(out.Script) == p.Policy.SealScript {
				return bad("FUNDING_SEAL_SCRIPT")
			}
			wantScript = p.Policy.FundingScript
		}
		if hex.EncodeToString(out.Script) != wantScript || out.Value < 1 || (value > 0 && out.Value != value) || (role == "POOL" && out.Value < 100000) {
			return bad(role + "_BINDING")
		}
		if unconfirmed {
			// A mempool output must still exist on the same pinned node.
			var u json.RawMessage
			if e := o.Call("gettxout", &u, point.TxID, point.Vout, true); e != nil {
				return e
			}
			if string(u) == "null" || len(u) == 0 {
				return bad(role + "_SPENT")
			}
			var unspent struct {
				Confirmations int64       `json:"confirmations"`
				Value         json.Number `json:"value"`
				Script        struct {
					Hex string `json:"hex"`
				} `json:"scriptPubKey"`
			}
			if json.Unmarshal(u, &unspent) != nil {
				return bad(role + "_BINDING")
			}
			amount, err := su.ParseCoins(string(unspent.Value))
			if err != nil || unspent.Confirmations != 0 || amount != out.Value || unspent.Script.Hex != wantScript {
				return bad(role + "_BINDING")
			}
			return nil
		}
		spent, e := sealSpent(o, point, out, h)
		if e != nil {
			return e
		}
		if spent {
			return bad(role + "_SPENT")
		}
		return nil
	}
	if e = checkOutput(pool, 0, "POOL"); e != nil {
		return refuse(e)
	}
	for _, in := range spec.Inputs {
		if e = checkOutput(Point{in.Point.TxID, in.Point.Vout}, in.ValueSat, "FUNDING"); e != nil {
			return refuse(e)
		}
	}
	admit := func() error {
		at := now + int64(time.Since(started)/time.Second)
		if payment == nil {
			result.Admission = AdmitIssuance(ctx, node, admissionPolicy, request, publication, at)
			if result.Admission.Verdict != "admit" {
				return bad(result.Admission.Reason)
			}
		} else {
			a := AdmitIssuanceV2(ctx, payment.nodes, IssuerPolicyV2{IssuerPolicy: admissionPolicy, PaymentPolicies: payment.policies}, request, publication, at)
			result.PaymentAdmission = &a
			if a.Verdict != "admit" {
				return bad(a.Reason)
			}
		}
		return nil
	}
	if e = admit(); e != nil {
		return refuse(e)
	}
	for _, n := range []su.NameView{agent, landlord} {
		again, e := currentName(o, n.Name)
		if e != nil {
			return refuse(e)
		}
		if !sameName(n, again) {
			return refuse(bad("NAME_CHANGED"))
		}
	}
	memAfter, e := pendingGrantBinding(o, agent, landlord, p.Policy.LandlordName, lb.Grant)
	if e != nil {
		return refuse(e)
	}
	if !sameJSON(memBefore, memAfter) {
		return refuse(bad("MEMPOOL_CHANGED"))
	}
	if e = checkOutput(pool, 0, "POOL"); e != nil {
		return refuse(e)
	}
	for _, in := range spec.Inputs {
		if e = checkOutput(Point{in.Point.TxID, in.Point.Vout}, in.ValueSat, "FUNDING"); e != nil {
			return refuse(e)
		}
	}
	if e = o.Stable(); e != nil {
		return refuse(e)
	}
	// The payment chain may differ from the Namecoin identity/funding chain.
	// Refresh its independent observation after the final identity/funding pass.
	if payment != nil {
		if e = admit(); e != nil {
			return refuse(e)
		}
	}
	window := func() error {
		current := now + int64(time.Since(started)/time.Second)
		if current >= pack.HoldExpiresAt {
			return bad("hold_expired_at_admission")
		}
		if current >= req.NotAfter {
			return bad("ISSUANCE_BINDING")
		}
		return nil
	}
	if e = window(); e != nil {
		return refuse(e)
	}
	poolName := poolReservation(pool)
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
	record.PaymentAdmission = result.PaymentAdmission
	reserved, _ := json.Marshal(record)
	for _, name := range []string{bookingName, poolName, recordName} {
		if e = store.Write(name, reserved); e != nil {
			return refuse(e)
		}
	}
	if hook != nil {
		hook("reserved")
	}
	if e = window(); e != nil {
		return refuse(e)
	}
	consentSig, e := schnorr.Sign(key, mustDecodeKey(req.ContractSHA256))
	if e != nil {
		return refuse(bad("GRANT_SIGNING"))
	}
	if hook != nil {
		hook("countersigned")
	}
	if e = window(); e != nil {
		return refuse(e)
	}
	g := Grant{Version: 3, Network: p.Policy.Network, Genesis: p.Policy.Genesis, AgentName: p.Policy.AgentName, LandlordName: p.Policy.LandlordName, IssuerKey: lb.Grant, GranteeKey: req.RenterPubkey, GranteeName: pack.RenterName, ContractSHA256: req.ContractSHA256, Scope: req.Scope, NotBefore: req.NotBefore, NotAfter: req.NotAfter, Seal: pool, Consent: GrantConsent{req.ContractSHA256, pack.Consent, hex.EncodeToString(consentSig.Serialize())}}
	if req.BudgetSat != 0 {
		budget := req.BudgetSat
		g.Budget = &budget
	}
	unsigned, e := g.Canonical()
	if e != nil {
		return refuse(e)
	}
	sig, e := schnorr.Sign(key, mustDecodeKey(grantSigningDigest(unsigned)))
	if e != nil {
		return refuse(bad("GRANT_SIGNING"))
	}
	raw, e := json.Marshal(SignedGrant{g, hex.EncodeToString(sig.Serialize())})
	if e != nil {
		return refuse(bad("GRANT_ENCODING"))
	}
	plan, e := MakeGrantIssuancePlan(p.Policy, spec, raw)
	if e != nil {
		return refuse(e)
	}
	if hook != nil {
		hook("signed")
	}
	record.Phase = "complete"
	record.GrantID = Hash(raw)
	record.SignedGrant = raw
	record.Plan = &plan
	encoded, _ := json.Marshal(record)
	if e = store.Write(recordName, encoded); e != nil {
		return refuse(e)
	}
	if hook != nil {
		hook("complete")
	}
	result.Verdict = "prepared"
	result.Reason = "GRANT_PREPARED"
	result.GrantID = record.GrantID
	result.SignedGrant = raw
	result.Plan = &plan
	return result
}
