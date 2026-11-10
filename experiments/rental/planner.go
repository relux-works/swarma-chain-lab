package rental

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// PoolOutput is an operator-supplied observation, not cryptographic evidence of
// ownership or confirmations. The online signer must independently recheck it.
type PoolOutput struct {
	Point    Point  `json:"point"`
	ValueSat int64  `json:"value_sat"`
	Script   string `json:"script"`
	Height   int64  `json:"height"`
	Block    string `json:"block"`
}
type PlanSpec struct {
	Kind         string         `json:"kind"`
	Inputs       []su.PlanInput `json:"inputs"`
	ChangeScript string         `json:"change_script"`
	Count        int            `json:"count"`
	ValueSat     int64          `json:"value_sat"`
	Pool         PoolOutput     `json:"pool"`
}
type Plan struct {
	ConstructionProfile string          `json:"construction_profile,omitempty"`
	Version             int             `json:"version"`
	Network             string          `json:"network"`
	Genesis             string          `json:"genesis"`
	Kind                string          `json:"kind"`
	Offline             bool            `json:"offline"`
	TransactionVersion  uint32          `json:"transaction_version"`
	Inputs              []su.PlanInput  `json:"inputs"`
	Outputs             []su.PlanOutput `json:"outputs"`
	FeeRate             int64           `json:"fee_rate_sat_vbyte"`
	FeeSat              int64           `json:"reserved_fee_sat"`
	MaxSignedVBytes     int             `json:"maximum_signed_vbytes"`
	CertificateSHA256   string          `json:"certificate_sha256,omitempty"`
	GrantID             string          `json:"grant_id,omitempty"`
	BookingID           string          `json:"booking_id,omitempty"`
	NameValue           string          `json:"name_value,omitempty"`
	Reservation         string          `json:"reservation,omitempty"`
	RequiredReview      string          `json:"required_review"`
}
type poolReservation struct {
	Version           int    `json:"version"`
	Network           string `json:"network"`
	Genesis           string `json:"genesis"`
	Point             Point  `json:"point"`
	CertificateSHA256 string `json:"certificate_sha256"`
	BookingID         string `json:"booking_id"`
}

// MakePlan returns unsigned refill/revoke plans without RPC or reservations.
// Legacy station-anchor issuance is disabled; use IssueDetached for issuance.
func MakePlan(p IssuerPolicy, s PlanSpec, certificate, request, publication []byte, now int64) (Plan, error) {
	if s.Kind == "issue" {
		return Plan{}, bad("LEGACY_ISSUANCE_DISABLED")
	}
	if p.Policy.LandlordName != "" {
		return makeGrantPoolPlan(p.Policy, s)
	}
	if p.Policy.AgentName != "" {
		return makeDetachedPoolPlan(p.Policy, s)
	}
	return MakeLegacyPlan(p, s, certificate, request, publication, now)
}

// MakeLegacyPlan retains station-anchor issuance solely for explicit legacy
// regression callers. New issuance signs a detached certificate instead.
func MakeLegacyPlan(p IssuerPolicy, s PlanSpec, certificate, request, publication []byte, now int64) (plan Plan, err error) {
	plan = Plan{Version: 1, Network: p.Policy.Network, Genesis: p.Policy.Genesis, Kind: s.Kind, Offline: true, TransactionVersion: 2, Inputs: s.Inputs, FeeRate: 200, RequiredReview: "Offline unsigned plan only; independently verify prevouts, current payment/package, signer policy and exact transaction immediately before signing. No broadcast authority."}
	if e := p.Policy.validate(); e != nil {
		return plan, e
	}
	if s.ChangeScript != p.Policy.StationScript || !p2pkh(s.ChangeScript) {
		return plan, bad("CHANGE_PIN")
	}
	if len(s.Inputs) == 0 || len(s.Inputs) > 16 {
		return plan, bad("PLAN_BOUNDS")
	}
	tx := su.Transaction{Version: 2}
	var total int64
	seen := map[su.Point]bool{}
	names, seals := 0, 0
	payment, _ := hex.DecodeString(p.Policy.StationScript)
	for _, in := range s.Inputs {
		if !digest(in.Point.TxID) || seen[in.Point] || in.ValueSat <= 0 || in.ValueSat > MaxMoney-total {
			return plan, bad("FUNDING_INPUT")
		}
		seen[in.Point] = true
		total += in.ValueSat
		script, e := hex.DecodeString(in.Script)
		if e != nil || hex.EncodeToString(script) != in.Script {
			return plan, bad("PREVOUT_SCRIPT")
		}
		switch in.Role {
		case "funding":
			if !p2pkh(in.Script) {
				return plan, bad("LEGACY_FUNDING_ONLY")
			}
		case "name":
			names++
			if s.Kind != "issue" || in.ValueSat != 1000000 || len(script) <= len(payment) || !bytes.Equal(script[len(script)-len(payment):], payment) || (script[0] != 0x52 && script[0] != 0x53) {
				return plan, bad("NAME_PREVOUT")
			}
		case "seal":
			seals++
			if s.Kind != "revoke" || in.Point != (su.Point{TxID: s.Pool.Point.TxID, Vout: s.Pool.Point.Vout}) || in.ValueSat != s.Pool.ValueSat || in.Script != p.Policy.StationScript {
				return plan, bad("REVOKE_SEAL_BINDING")
			}
		default:
			return plan, bad("INPUT_ROLE")
		}
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Script: make([]byte, 140), Sequence: 0xfffffffe})
	}
	add := func(value int64, script []byte, role string) {
		tx.Outputs = append(tx.Outputs, su.Output{Value: value, Script: script})
		plan.Outputs = append(plan.Outputs, su.PlanOutput{ValueSat: value, Script: hex.EncodeToString(script), Role: role})
	}
	var reserve *poolReservation
	switch s.Kind {
	case "refill":
		if names != 0 || seals != 0 || s.Count < 1 || s.Count > 16 || s.ValueSat < 100000 || s.ValueSat > MaxMoney/int64(s.Count) {
			return plan, bad("REFILL_TEMPLATE")
		}
		for i := 0; i < s.Count; i++ {
			add(s.ValueSat, payment, "pool-seal")
		}
	case "issue":
		if names != 1 || seals != 0 {
			return plan, bad("ISSUE_TEMPLATE")
		}
		env, e := ParseEnvelope(certificate)
		if e != nil {
			return plan, e
		}
		c := env.Certificate
		r, _, e := VerifyIssuancePackage(p, request, publication, now)
		if e != nil {
			return plan, e
		}
		if r.PaymentHeight == 0 {
			return plan, bad("payment_unconfirmed")
		}
		if c.Network != p.Policy.Network || c.Genesis != p.Policy.Genesis || c.IssuerPubkey != p.Policy.IssuerPubkey || c.AgentPubkey != r.AgentPubkey || c.StationName != r.StationName || c.GranteePubkey != r.RenterPubkey || c.ContractSHA256 != r.ContractSHA256 || c.NotBefore != r.NotBefore || c.NotAfter != r.NotAfter || c.BudgetSat != r.BudgetSat || !slices.Equal(c.Scope, r.Scope) {
			return plan, bad("CERTIFICATE_REQUEST_BINDING")
		}
		pool := s.Pool
		if pool.Point != c.Seal || !digest(pool.Block) || pool.Height < 1 || pool.Height > 2147483647 {
			return plan, bad("POOL_UNCONFIRMED")
		}
		if pool.Script != p.Policy.StationScript || pool.ValueSat < 100000 || pool.ValueSat > MaxMoney {
			return plan, bad("POOL_STATION_BINDING")
		}
		if seen[su.Point{TxID: pool.Point.TxID, Vout: pool.Point.Vout}] {
			return plan, bad("ISSUE_SPENDS_SEAL")
		}
		plan.CertificateSHA256 = Hash(certificate)
		plan.BookingID = r.BookingID
		plan.NameValue, e = NameValue(c, plan.CertificateSHA256)
		if e != nil {
			return plan, e
		}
		tx.Version = 0x7100
		plan.TransactionVersion = tx.Version
		add(1000000, su.NameUpdateScript(c.StationName, plan.NameValue, payment), "name-anchor")
		hash, _ := hex.DecodeString(plan.CertificateSHA256)
		add(0, append([]byte{0x6a, 32}, hash...), "certificate-commitment")
		reserve = &poolReservation{1, p.Policy.Network, p.Policy.Genesis, pool.Point, plan.CertificateSHA256, r.BookingID}
	case "revoke":
		if names != 0 || seals != 1 || len(s.Inputs) != 1 || !digest(s.Pool.Point.TxID) || s.Pool.Script != p.Policy.StationScript {
			return plan, bad("REVOKE_TEMPLATE")
		}
	default:
		return plan, bad("PLAN_KIND")
	}
	add(0, payment, "change")
	var change int64
	plan.MaxSignedVBytes, plan.FeeSat, change, err = su.ReserveLegacyFee(tx, total)
	if err != nil {
		return plan, err
	}
	plan.Outputs[len(plan.Outputs)-1].ValueSat = change
	if reserve != nil {
		store, e := durable.Open(p.Policy.StateDir, "rental.lock")
		if e != nil {
			return plan, e
		}
		defer store.Close()
		key, _ := json.Marshal(struct {
			Network, Genesis string
			Point            Point
		}{p.Policy.Network, p.Policy.Genesis, reserve.Point})
		name := "pool-" + Hash(key) + ".json"
		old, e := store.Read(name, 4096)
		if e != nil {
			return plan, e
		}
		if old != nil {
			return plan, bad("POOL_ALREADY_RESERVED")
		}
		bookingKey, _ := json.Marshal(struct{ Network, Genesis, BookingID string }{p.Policy.Network, p.Policy.Genesis, reserve.BookingID})
		bookingName := "booking-" + Hash(bookingKey) + ".json"
		prior, e := store.Read(bookingName, 4096)
		if e != nil {
			return plan, e
		}
		if prior != nil {
			return plan, bad("BOOKING_ALREADY_RESERVED")
		}
		b, _ := json.Marshal(reserve)
		// Burn the booking first. If the second write fails or the process dies,
		// uncertainty prevents retry with another seal; neither record is undone.
		if e = store.Write(bookingName, b); e != nil {
			return plan, e
		}
		if e = store.Write(name, b); e != nil {
			return plan, e
		}
		plan.Reservation = name
	}
	return plan, nil
}
