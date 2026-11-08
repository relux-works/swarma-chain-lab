package singleuse

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
)

type PlanInput struct {
	Point    Point  `json:"point"`
	ValueSat int64  `json:"value_sat"`
	Script   string `json:"script"`
	Role     string `json:"role"`
}
type PlanOutput struct {
	ValueSat int64  `json:"value_sat"`
	Script   string `json:"script"`
	Role     string `json:"role"`
}
type PlanSpec struct {
	Kind               string       `json:"kind"`
	IssuerKey          string       `json:"issuer_key"`
	GranteeKey         string       `json:"grantee_key"`
	Inputs             []PlanInput  `json:"inputs"`
	ChangeScript       string       `json:"change_script"`
	Seal               Point        `json:"seal"`
	SealValueSat       int64        `json:"seal_value_sat"`
	OwnerName          string       `json:"owner_name"`
	OwnerSPKI          string       `json:"owner_spki"`
	OwnerPaymentScript string       `json:"owner_payment_script"`
	CertificateHash    string       `json:"certificate_sha256"`
	Payments           []PlanOutput `json:"payments,omitempty"`
}
type Plan struct {
	Network         string       `json:"network"`
	Offline         bool         `json:"offline"`
	Kind            string       `json:"kind"`
	Inputs          []PlanInput  `json:"inputs"`
	Outputs         []PlanOutput `json:"outputs"`
	Version         uint32       `json:"transaction_version"`
	FeeRate         int64        `json:"fee_rate_sat_vbyte"`
	FeeSat          int64        `json:"reserved_fee_sat"`
	MaxSignedVBytes int          `json:"maximum_signed_vbytes"`
	RedeemScript    string       `json:"redeem_script"`
	NameValue       string       `json:"name_value,omitempty"`
	RequestHash     string       `json:"request_sha256,omitempty"`
	RequiredReview  string       `json:"required_review"`
}

func p2pkh(b []byte) bool {
	return len(b) == 25 && bytes.Equal(b[:3], []byte{0x76, 0xa9, 20}) && bytes.Equal(b[23:], []byte{0x88, 0xac})
}
func paymentScript(s string) ([]byte, error) {
	b, e := hex.DecodeString(s)
	if e != nil || hex.EncodeToString(b) != s || !(p2pkh(b) || (len(b) == 23 && bytes.Equal(b[:2], []byte{0xa9, 20}) && b[22] == 0x87)) {
		return nil, fail("PAYMENT_SCRIPT")
	}
	return b, nil
}

// MakePlan performs no RPC, wallet access, signing, subprocess or broadcast.
// It emits an inert mainnet plan, not serialized transaction hex. Funding
// existence/ownership and the final exact signed transaction need later review.
func MakePlan(s PlanSpec, request []byte) (Plan, error) {
	p := Plan{Network: "main", Offline: true, Kind: s.Kind, Inputs: s.Inputs, Version: 2, FeeRate: 200, RequiredReview: "Independent source/prevout/fee review, followed by owner GO for the exact signed hex of each transaction; this plan is not authorization."}
	redeem, sealScript, e := SealScript(s.IssuerKey, s.GranteeKey)
	if e != nil {
		return p, e
	}
	p.RedeemScript = hex.EncodeToString(redeem)
	change, e := paymentScript(s.ChangeScript)
	if e != nil {
		return p, e
	}
	if len(s.Inputs) == 0 || len(s.Inputs) > 16 || len(s.Payments) > 16 {
		return p, fail("PLAN_BOUNDS")
	}
	tx := Transaction{Version: 2}
	var total int64
	seen := map[Point]bool{}
	special := 0
	for _, input := range s.Inputs {
		if !digestHex(input.Point.TxID) || seen[input.Point] || input.ValueSat <= 0 || input.ValueSat > 21000000*100000000-total {
			return p, fail("FUNDING_INPUT")
		}
		seen[input.Point] = true
		total += input.ValueSat
		script, e := hex.DecodeString(input.Script)
		if e != nil || hex.EncodeToString(script) != input.Script {
			return p, fail("PREVOUT_SCRIPT")
		}
		// A funding/name P2PKH input may reveal a 65-byte public key. Reserve
		// the full legacy bound rather than assuming a compressed wallet key.
		length := 140
		switch input.Role {
		case "funding":
			if !p2pkh(script) {
				return p, fail("LEGACY_FUNDING_ONLY")
			}
		case "seal":
			special++
			if s.Kind != "use" || input.Point != s.Seal || input.ValueSat != s.SealValueSat || !bytes.Equal(script, sealScript) {
				return p, fail("PLAN_SEAL_BINDING")
			}
			length = 1 + 1 + 73 + 1 + len(redeem)
		case "name":
			special++
			payment, e := paymentScript(s.OwnerPaymentScript)
			if e != nil || !p2pkh(payment) || s.Kind != "anchor" || len(script) <= len(payment) || !bytes.Equal(script[len(script)-len(payment):], payment) || (script[0] != 0x52 && script[0] != 0x53) {
				return p, fail("PLAN_NAME_PREVOUT")
			}
		default:
			return p, fail("INPUT_ROLE")
		}
		tx.Inputs = append(tx.Inputs, Input{input.Point, make([]byte, length), 0xfffffffe})
	}
	add := func(value int64, script []byte, role string) {
		tx.Outputs = append(tx.Outputs, Output{value, script})
		p.Outputs = append(p.Outputs, PlanOutput{value, hex.EncodeToString(script), role})
	}
	switch s.Kind {
	case "seal":
		if special != 0 || s.SealValueSat < 1000 || s.SealValueSat > 21000000*100000000 {
			return p, fail("SEAL_PLAN")
		}
		add(s.SealValueSat, sealScript, "seal")
	case "anchor":
		if special != 1 || !digestHex(s.Seal.TxID) || !digestHex(s.CertificateHash) || len(s.OwnerName) == 0 || len(s.OwnerName) > 255 || len(s.OwnerSPKI) == 0 {
			return p, fail("ANCHOR_PLAN")
		}
		payment, e := paymentScript(s.OwnerPaymentScript)
		if e != nil {
			return p, e
		}
		value, _ := json.Marshal(map[string]any{"swarma": map[string]any{"keyvault_owner_spki": s.OwnerSPKI, "keyvault_certificate_sha256": s.CertificateHash, "keyvault_seal": s.Seal}})
		if len(value) > 520 {
			return p, fail("NAME_VALUE_BOUND")
		}
		p.NameValue = string(value)
		tx.Version = 0x7100
		p.Version = tx.Version
		add(1000000, NameUpdateScript(s.OwnerName, p.NameValue, payment), "name-anchor")
		commitment, _ := hex.DecodeString(s.CertificateHash)
		add(0, append([]byte{0x6a, 32}, commitment...), "certificate-commitment")
	case "use":
		if special != 1 || len(request) == 0 || len(request) > 12288 {
			return p, fail("USE_PLAN")
		}
		p.RequestHash = Hash(request)
		commitment, _ := hex.DecodeString(p.RequestHash)
		add(0, append([]byte{0x6a, 32}, commitment...), "request-commitment")
	default:
		return p, fail("PLAN_KIND")
	}
	for _, payment := range s.Payments {
		if s.Kind != "use" || payment.ValueSat < 1000 {
			return p, fail("EXTRA_PAYMENT")
		}
		script, e := paymentScript(payment.Script)
		if e != nil {
			return p, e
		}
		add(payment.ValueSat, script, "payment")
	}
	add(0, change, "change")
	p.MaxSignedVBytes = len(tx.Bytes())
	if p.MaxSignedVBytes > 4096 {
		return p, fail("PLAN_SIZE_BOUND")
	}
	p.FeeSat = int64(p.MaxSignedVBytes) * p.FeeRate
	var outputs int64
	for _, output := range tx.Outputs {
		if output.Value < 0 || output.Value > 21000000*100000000-outputs {
			return p, fail("OUTPUT_VALUE")
		}
		outputs += output.Value
	}
	if total-outputs-p.FeeSat < 1000 {
		return p, fail("FUNDING_OR_DUST_RESERVE")
	}
	p.Outputs[len(p.Outputs)-1].ValueSat = total - outputs - p.FeeSat
	return p, nil
}
