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
	// Public validation allows test-mode V1 with NMC, but deployment pairing
	// requires V2. Check that both inputs reach the comparison before asserting
	// its rejection; the otherwise identical V2 neighbor must pass.
	singleCoinBooking := []byte(`{"service_version":2,"config":{"coins":{"nmc":{"public_branch":"fixture"}}}}`)
	for _, tc := range []struct {
		version string
		want    error
	}{{"1", ErrPolicy}, {"2", nil}} {
		t.Run("public-valid-version-"+tc.version, func(t *testing.T) {
			g := []byte(`{"mode":"test","exchange":{"booking_version":` + tc.version + `,"payment_coins":["nmc"]}}`)
			for _, raw := range [][]byte{g, singleCoinBooking} {
				if e := ValidatePublicJSON(raw); e != nil {
					t.Fatal("version fixture rejected before coin comparison", e)
				}
			}
			if e := ComparePaymentCoins(g, singleCoinBooking); e != tc.want {
				t.Fatalf("coin mismatch accepted: version=%s got=%v want=%v", tc.version, e, tc.want)
			}
		})
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
