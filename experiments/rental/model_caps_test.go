package rental

import (
	"reflect"
	"testing"
)

// Independent consumer authenticates the added signed caps, rejects invalid
// fully re-signed values, and preserves the existing non-model wire vectors.
// These offline witnesses do not claim payment observation or live issuance.
func TestV2ModelCapsAuthentication(t *testing.T) {
	p, r, pack, pub := paymentV2Fixture(t, "nmc")
	pack.Contract.ModelCaps = &ModelCaps{InputTokens: 1000, OutputTokens: 100, Requests: 10, MaxTokens: 10, CostNanoUSD: 10000, DefaultMaxOutputTokens: 5}
	resignPaymentV2(t, &r, &pack, &pub, true)
	_, decoded, e := VerifyIssuancePackageV2(p, eventBytes(r), eventBytes(pub), pack.HoldCreatedAt+10)
	if e != nil || decoded.Contract.ModelCaps == nil || *decoded.Contract.ModelCaps != *pack.Contract.ModelCaps {
		t.Fatal("valid signed caps refused", e)
	}
	for i := 0; i < reflect.TypeOf(ModelCaps{}).NumField(); i++ {
		t.Run(reflect.TypeOf(ModelCaps{}).Field(i).Name, func(t *testing.T) {
			rr, pp, ee := r, pack, pub
			caps := *pack.Contract.ModelCaps
			pp.Contract.ModelCaps = &caps
			reflect.ValueOf(&caps).Elem().Field(i).SetUint(0)
			resignPaymentV2(t, &rr, &pp, &ee, true)
			if _, _, e := VerifyIssuancePackageV2(p, eventBytes(rr), eventBytes(ee), pack.HoldCreatedAt+10); e == nil || e.Error() != "CONTRACT_MODEL_CAPS" {
				t.Fatal("invalid signed cap accepted", e)
			}
		})
	}
	rr, pp, ee := r, pack, pub
	caps := *pack.Contract.ModelCaps
	pp.Contract.ModelCaps = &caps
	caps.Requests++
	resignPaymentV2(t, &rr, &pp, &ee, false)
	if _, _, e := VerifyIssuancePackageV2(p, eventBytes(rr), eventBytes(ee), pack.HoldCreatedAt+10); e == nil || e.Error() != "RENTER_CONSENT" {
		t.Fatal("old consent accepted changed caps", e)
	}
}
