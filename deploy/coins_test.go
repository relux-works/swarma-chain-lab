package deploy

import "testing"

// Exact set equality is independent of order; duplicate, omitted, extra,
// unknown, null or legacy-version coins refuse without probing any host.
func TestPaymentCoinProvisioning(t *testing.T) {
	booking := []byte(`{"service_version":2,"config":{"coins":{"nmc":{"public_branch":"fixture"},"btc":{"public_branch":"fixture"}}}}`)
	for _, coins := range []string{`["nmc","btc"]`, `["btc","nmc"]`} {
		if e := ComparePaymentCoins([]byte(`{"exchange":{"booking_version":2,"payment_coins":`+coins+`}}`), booking); e != nil {
			t.Fatal("equal explicit coin sets refused", e)
		}
	}
	for _, g := range []string{
		`{"exchange":{"booking_version":1,"payment_coins":["nmc","btc"]}}`,
		`{"exchange":{"booking_version":2,"payment_coins":["nmc"]}}`,
		`{"exchange":{"booking_version":2,"payment_coins":["nmc","nmc"]}}`,
		`{"exchange":{"booking_version":2,"payment_coins":["nmc","eth"]}}`,
		`{"exchange":{"booking_version":2,"payment_coins":["nmc","btc","ltc"]}}`,
		`{"exchange":{"booking_version":2,"payment_coins":null}}`,
	} {
		if e := ComparePaymentCoins([]byte(g), booking); e != ErrPolicy {
			t.Fatal("coin mismatch accepted", e)
		}
	}
	g := []byte(`{"exchange":{"booking_version":2,"payment_coins":["nmc","btc"]}}`)
	for _, b := range []string{`{"service_version":1,"config":{"coins":{"nmc":{},"btc":{}}}}`, `{"service_version":2,"config":{"coins":{"nmc":null,"btc":{"x":1}}}}`, `{"service_version":2,"config":{"coins":{"nmc":{"x":1},"nmc":{"x":2}}}}`} {
		if e := ComparePaymentCoins(g, []byte(b)); e != ErrPolicy {
			t.Fatal("ambiguous booking coin set accepted", e)
		}
	}
}
