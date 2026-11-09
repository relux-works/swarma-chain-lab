package deploy

import "encoding/json"

// ComparePaymentCoins checks explicit public deployment inputs only. It does
// not probe availability or add a coin; ServiceV2 remains authoritative at Book.
func ComparePaymentCoins(gateway, booking []byte) error {
	for _, raw := range [][]byte{gateway, booking} {
		if e := ValidatePublicJSON(raw); e != nil {
			return e
		}
	}
	var g struct {
		Kernel   struct{ Network, Genesis string } `json:"kernel"`
		Exchange struct {
			Version int      `json:"booking_version"`
			Coins   []string `json:"payment_coins"`
		} `json:"exchange"`
	}
	var b struct {
		Version int `json:"service_version"`
		Config  struct {
			Network string                     `json:"network"`
			Genesis string                     `json:"genesis"`
			Coins   map[string]json.RawMessage `json:"coins"`
		} `json:"config"`
	}
	if json.Unmarshal(gateway, &g) != nil || json.Unmarshal(booking, &b) != nil || g.Exchange.Version != 2 || b.Version != 2 || len(g.Exchange.Coins) < 1 || len(g.Exchange.Coins) > 3 || len(g.Exchange.Coins) != len(b.Config.Coins) {
		return ErrPolicy
	}
	if g.Kernel.Network == "main" || b.Config.Network == "main" {
		if g.Kernel.Network != "main" || b.Config.Network != "main" || g.Kernel.Genesis != mainGenesis || b.Config.Genesis != mainGenesis || len(g.Exchange.Coins) != 1 || g.Exchange.Coins[0] != "nmc" {
			return ErrNetwork
		}
	}
	seen := map[string]bool{}
	for _, coin := range g.Exchange.Coins {
		if coin != "btc" && coin != "ltc" && coin != "nmc" || seen[coin] {
			return ErrPolicy
		}
		seen[coin] = true
		raw, ok := b.Config.Coins[coin]
		if !ok {
			return ErrPolicy
		}
		var config map[string]json.RawMessage
		if json.Unmarshal(raw, &config) != nil || len(config) == 0 {
			return ErrPolicy
		}
	}
	return nil
}
