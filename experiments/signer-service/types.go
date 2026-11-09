// Package signerservice implements the regtest landlord custody loop. It has
// exactly three transaction templates and no arbitrary signing endpoint.
package signerservice

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"

	rental "relux.works/swarma-chain-lab/experiments/rental"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

const MaxRecords = 64

func fail(code string) error { return errors.New(code) }
func hash(b []byte) string   { return su.Hash(b) }
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func encode(v any) []byte { b, _ := json.Marshal(v); return b }
func strict(b []byte, v any) error {
	if len(b) == 0 || len(b) > 65536 {
		return fail("ENCODING_BOUND")
	}
	return su.StrictInput(b, v)
}

// Caps are deliberately conservative regtest placeholders. Issuance value is
// authority granted (budget_sat), not an estimate of coins spent by the tx.
type Caps struct {
	FeePerTx    int64 `json:"fee_per_tx"`
	CountHour   int   `json:"count_hour"`
	CountDay    int   `json:"count_day"`
	BudgetHour  int64 `json:"budget_hour"`
	BudgetDay   int64 `json:"budget_day"`
	RefillCount int   `json:"refill_count"`
	SealValue   int64 `json:"seal_value"`
	RefillValue int64 `json:"refill_value"`
	LowWater    int   `json:"low_water"`
}

func RegtestCaps() Caps { return Caps{100000, 4, 16, 100000000, 400000000, 4, 200000, 800000, 2} }
func (c Caps) validate() error {
	if c.FeePerTx < 1 || c.FeePerTx > rental.MaxMoney || c.CountHour < 1 || c.CountDay < c.CountHour || c.CountDay > MaxRecords || c.BudgetHour < 1 || c.BudgetDay < c.BudgetHour || c.BudgetDay > rental.MaxMoney || c.RefillCount < 1 || c.RefillCount > 16 || c.SealValue < 100000 || c.SealValue > rental.MaxMoney/int64(c.RefillCount) || c.RefillValue < c.SealValue*int64(c.RefillCount) || c.RefillValue > rental.MaxMoney || c.LowWater < 1 || c.LowWater > c.RefillCount {
		return fail("CAP_CONFIG")
	}
	return nil
}

type Config struct {
	PresentationDir       string                                   `json:"presentation_dir,omitempty"`
	Profile               string                                   `json:"profile"`
	PaymentPolicies       map[string]rental.PaymentAdmissionPolicy `json:"payment_policies,omitempty"`
	Policy                rental.IssuerPolicy                      `json:"policy"`
	StateDir              string                                   `json:"state_dir"`
	GrantKeyPath          string                                   `json:"grant_key_path"`
	FundingKeyPath        string                                   `json:"funding_key_path"`
	HistoricalSealScripts []string                                 `json:"historical_seal_scripts,omitempty"`
	Caps                  Caps                                     `json:"caps"`
}

func (c Config) validate() error {
	p := c.Policy.Policy
	// This unit never enables mainnet, even with non-placeholder cap values.
	if p.Network != "regtest" || p.Genesis != su.RegtestGenesis {
		return fail("REGTEST_ONLY")
	}
	if c.PresentationDir != "" {
		if e := presentationRoot(c.PresentationDir); e != nil {
			return e
		}
	}
	if c.Profile != "v1-nmc" && c.Profile != "v2" {
		return fail("ISSUER_PROFILE_UNAVAILABLE")
	}
	if c.Profile == "v1-nmc" && len(c.PaymentPolicies) != 0 {
		return fail("PAYMENT_POLICY")
	}
	if c.Profile == "v2" {
		if len(c.PaymentPolicies) < 1 || len(c.PaymentPolicies) > 3 {
			return fail("PAYMENT_POLICY")
		}
		for coin, p := range c.PaymentPolicies {
			if (coin != "btc" && coin != "ltc" && coin != "nmc") || p.MinConfirmations < 1 || p.MaxRateAgeSeconds < 1 {
				return fail("PAYMENT_POLICY")
			}
		}
	}
	if e := c.Caps.validate(); e != nil {
		return e
	}
	for _, s := range []string{c.StateDir, p.StateDir, c.GrantKeyPath, c.FundingKeyPath} {
		if !filepath.IsAbs(s) || filepath.Clean(s) != s {
			return fail("CONFIG_PATH")
		}
	}
	if c.StateDir == p.StateDir || c.GrantKeyPath == c.FundingKeyPath {
		return fail("CUSTODY_SEPARATION")
	}
	script, e := rental.GrantSealScript(p.IssuerPubkey)
	if e != nil || script != p.SealScript || p.FundingScript == p.SealScript || !p2pkh(p.FundingScript) {
		return fail("KEY_SCRIPT_PIN")
	}
	for _, s := range c.HistoricalSealScripts {
		if !p2pkh(s) || s == p.FundingScript {
			return fail("HISTORICAL_SEAL_FUNDING")
		}
	}
	if len(c.HistoricalSealScripts) > 64 {
		return fail("HISTORY_BOUND")
	}
	return nil
}
func p2pkh(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s && len(b) == 25 && b[0] == 0x76 && b[1] == 0xa9 && b[2] == 20 && b[23] == 0x88 && b[24] == 0xac
}

type Intent struct {
	BookingID      string `json:"booking_id"`
	ContractSHA256 string `json:"contract_sha256"`
	BudgetSat      int64  `json:"budget_sat"`
	PaymentCoin    string `json:"payment_coin"`
	PaymentNetwork string `json:"payment_network"`
	PaymentGenesis string `json:"payment_genesis"`
	PaymentTxID    string `json:"payment_txid"`
	PaymentVout    uint32 `json:"payment_vout"`
}

// Issuer is a trusted, locally constructed adapter, never selected by an outbox
// record. Inspect authenticates original bytes; Check reads own payment nodes;
// Prepare delegates reservation, signing and exact recovery to the K1 engine.
type Issuer interface {
	Inspect(request, publication []byte, now int64) (Intent, error)
	Check(context.Context, []byte, []byte, int64) error
	Prepare(context.Context, []byte, []byte, rental.Point, rental.PlanSpec, int64) rental.GrantIssueResult
}
type Broadcast interface {
	Send(context.Context, []byte) (string, error)
}
type GrantStore interface {
	Put(context.Context, []byte) (string, error)
}

// Item contains original signed kind8182 bytes, not a reconstructed Package.
// Source authority is assigned by a configured adapter; there is no operator
// boolean inside received JSON. Refill is exclusively an internal template.
type Item struct {
	ID          string  `json:"id"`
	Kind        string  `json:"kind"`
	Request     string  `json:"request,omitempty"`
	Publication string  `json:"publication,omitempty"`
	Revoke      *Revoke `json:"revoke,omitempty"`
}
type Revoke struct {
	Version         int    `json:"version"`
	BookingID       string `json:"booking_id"`
	ContractSHA256  string `json:"contract_sha256"`
	PaymentCoin     string `json:"payment_coin"`
	PaymentNetwork  string `json:"payment_network"`
	PaymentGenesis  string `json:"payment_genesis"`
	PaymentTxID     string `json:"payment_txid"`
	PaymentVout     uint32 `json:"payment_vout"`
	Reason          string `json:"reason"`
	ObservedTipHash string `json:"observed_tip_hash"`
}
type SourceClass string

const BookingSource SourceClass = "booking"
const OperatorSource SourceClass = "operator"

type Pulled struct {
	Raw   []byte
	After string
}
type Source interface {
	Pull(context.Context, string, int) ([]Pulled, error)
}
type Result struct{ ID, Phase, Reason, TxID, GrantID string }
