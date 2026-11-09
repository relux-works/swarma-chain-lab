package paymentchain

import "testing"

// The adapter accepts exactly three lowercase coin strings, with no aliases,
// whitespace normalization, default currency or numeric/network shortcuts.
func TestCoinBoundary(t *testing.T) {
	for _, raw := range []string{"", "BTC", "Nmc", "ltc ", " nmc", "bitcoin", "eth", "regtest", "0"} {
		if c, err := ParseCoin(raw); err == nil || err.Error() != "COIN_PROFILE" || c != "" {
			t.Fatalf("invalid coin accepted: %q", raw)
		}
		if _, err := Coin(raw).Profile(); err == nil || err.Error() != "COIN_PROFILE" {
			t.Fatalf("cast bypass: %q", raw)
		}
	}
	for _, want := range []Coin{CoinNMC, CoinBTC, CoinLTC} {
		got, err := ParseCoin(string(want))
		if err != nil || got != want {
			t.Fatal("valid coin", want, err)
		}
		p, err := got.Profile()
		if err != nil || p.Coin != string(want) || p.Network != "regtest" {
			t.Fatal("profile binding", err)
		}
	}
}
