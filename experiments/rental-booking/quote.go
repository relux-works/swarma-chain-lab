package booking

import "math/big"

// Quote freezes integer monetary units at hold creation. No live rate source or
// floating-point conversion participates in a payment verdict.
type Quote struct {
	PriceUSDCents   int64 `json:"price_usd_cents"`
	USDMicrosPerNMC int64 `json:"usd_micros_per_nmc"`
	RateAsOf        int64 `json:"rate_as_of"`
	PriceNMCSat     int64 `json:"price_nmc_sat"`
}

func NewQuote(cents, micros, asOf, maxAge, now int64) (Quote, error) {
	if cents <= 0 || micros <= 0 || asOf <= 0 || now < asOf || maxAge <= 0 || now-asOf > maxAge {
		return Quote{}, refuse("QUOTE_RATE")
	}
	n := new(big.Int).Mul(big.NewInt(cents), big.NewInt(1000000000000))
	n.Add(n, big.NewInt(micros-1)).Quo(n, big.NewInt(micros))
	if !n.IsInt64() || n.Sign() <= 0 || n.Int64() > 21000000*100000000 {
		return Quote{}, refuse("QUOTE_AMOUNT")
	}
	return Quote{cents, micros, asOf, n.Int64()}, nil
}
