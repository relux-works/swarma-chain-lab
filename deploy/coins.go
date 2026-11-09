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
		Exchange struct {
			Version int      `json:"booking_version"`
			Coins   []string `json:"payment_coins"`
		} `json:"exchange"`
	}
	var b struct {
		Version int `json:"service_version"`
		Config  struct {
			Coins map[string]json.RawMessage `json:"coins"`
		} `json:"config"`
	}
	if json.Unmarshal(gateway, &g) != nil || json.Unmarshal(booking, &b) != nil || g.Exchange.Version != 2 || b.Version != 2 || len(g.Exchange.Coins) < 1 || len(g.Exchange.Coins) > 3 || len(g.Exchange.Coins) != len(b.Config.Coins) {
		return ErrPolicy
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
