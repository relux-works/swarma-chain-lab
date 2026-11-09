package booking

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	singleuse "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

var actions = []string{"deliver", "pay", "publish", "repository.push", "secret.release"}

const PrivacyNotice = "Your Nostr public key is in the rental certificate. Its hash is anchored on Namecoin and the certificate is published in the slot report. Your key is therefore publicly and permanently linked to our station name and the slot time."

func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		panic("non-JSON protocol type")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func Strict(raw []byte, v any) error {
	if e := singleuse.StrictInput(raw, v); e != nil {
		return refuse("INPUT_SCHEMA")
	}
	return nil
}
func hexSize(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func pubkey(s string) bool {
	if !hexSize(s, 32) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}
func identifier(s string) bool {
	if len(s) < 1 || len(s) > 160 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._/", r)) {
			return false
		}
	}
	return true
}

func stationName(s string) bool {
	if !strings.HasPrefix(s, "id/") || len(s) > 160 || len(s) <= 3 {
		return false
	}
	for _, r := range s[3:] {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._", r)) {
			return false
		}
	}
	return true
}
func actionPartition(allow, deny []string) bool {
	if allow == nil || deny == nil || !sort.StringsAreSorted(allow) || !sort.StringsAreSorted(deny) {
		return false
	}
	seen := map[string]bool{}
	for _, list := range [][]string{allow, deny} {
		for _, a := range list {
			if seen[a] {
				return false
			}
			seen[a] = true
		}
	}
	if len(seen) != len(actions) {
		return false
	}
	for _, a := range actions {
		if !seen[a] {
			return false
		}
	}
	return true
}

type Template struct {
	Version        int      `json:"version"`
	ID             string   `json:"id"`
	ProfileID      string   `json:"profile_id"`
	ProfileVersion string   `json:"profile_version"`
	ProfileSHA256  string   `json:"profile_sha256"`
	Allowed        []string `json:"allowed"`
	Forbidden      []string `json:"forbidden"`
	BudgetSat      int64    `json:"budget_sat"`
}

func (t Template) Validate(profile []byte, pin string) error {
	if t.Version != 1 || !identifier(t.ID) || !identifier(t.ProfileID) || !identifier(t.ProfileVersion) || !hexSize(t.ProfileSHA256, 32) || Hash(profile) != t.ProfileSHA256 || Hash(canonical(t)) != pin {
		return refuse("TEMPLATE_PROFILE_PIN")
	}
	if !actionPartition(t.Allowed, t.Forbidden) || t.BudgetSat < 0 || t.BudgetSat > 21000000*100000000 {
		return refuse("TEMPLATE_SCOPE")
	}
	return nil
}

type Contract struct {
	Version         int      `json:"version"`
	BookingID       string   `json:"booking_id"`
	RenterPubkey    string   `json:"renter_pubkey"`
	RenterName      string   `json:"renter_name"`
	AgentPubkey     string   `json:"agent_pubkey"`
	StationName     string   `json:"station_name"`
	NotBefore       int64    `json:"not_before"`
	NotAfter        int64    `json:"not_after"`
	Allowed         []string `json:"allowed"`
	Forbidden       []string `json:"forbidden"`
	BudgetSat       int64    `json:"budget_sat"`
	TemplateID      string   `json:"template_id"`
	TemplateSHA256  string   `json:"template_sha256"`
	ProfileID       string   `json:"profile_id"`
	ProfileVersion  string   `json:"profile_version"`
	ProfileSHA256   string   `json:"profile_sha256"`
	PriceUSDCents   int64    `json:"price_usd_cents"`
	USDMicrosPerNMC int64    `json:"usd_micros_per_nmc"`
	RateAsOf        int64    `json:"rate_as_of"`
	PriceNMCSat     int64    `json:"price_nmc_sat"`
	PaymentPolicy   string   `json:"payment_policy"`
	PaymentAddress  string   `json:"payment_address"`
	PrivacySHA256   string   `json:"privacy_sha256"`
}

func (c Contract) Bytes() []byte { return canonical(c) }
func (c Contract) Hash() string  { return Hash(c.Bytes()) }
func (c Contract) Validate() error {
	if c.Version != 1 || !hexSize(c.BookingID, 32) || !pubkey(c.RenterPubkey) || !pubkey(c.AgentPubkey) || !stationName(c.StationName) || c.RenterName != "" && !identifier(c.RenterName) {
		return refuse("CONTRACT_IDENTITY")
	}
	if c.NotBefore <= 0 || c.NotAfter <= c.NotBefore || c.NotAfter-c.NotBefore > 3600 {
		return refuse("CONTRACT_SLOT")
	}
	if !actionPartition(c.Allowed, c.Forbidden) || c.BudgetSat < 0 || c.BudgetSat > 21000000*100000000 {
		return refuse("CONTRACT_SCOPE")
	}
	if !identifier(c.TemplateID) || !identifier(c.ProfileID) || !identifier(c.ProfileVersion) || !hexSize(c.TemplateSHA256, 32) || !hexSize(c.ProfileSHA256, 32) || c.PrivacySHA256 != Hash([]byte(PrivacyNotice)) {
		return refuse("CONTRACT_PINS")
	}
	q, e := NewQuote(c.PriceUSDCents, c.USDMicrosPerNMC, c.RateAsOf, 1, c.RateAsOf)
	if e != nil || q.PriceNMCSat != c.PriceNMCSat {
		return refuse("CONTRACT_QUOTE")
	}
	if c.PaymentPolicy != "advance" && c.PaymentPolicy != "start_now" {
		return refuse("PAYMENT_POLICY")
	}
	if len(c.PaymentAddress) < 26 || len(c.PaymentAddress) > 40 {
		return refuse("CONTRACT_ADDRESS")
	}
	return nil
}
