package main

import (
	"context"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind/bookingbind"
	"testing"
	"time"
)

// The production V2 adapter/client consumes genuine BTC/LTC regtest payments.
// Mempool and one confirmation cannot authorize issuance; two can. Reorg then
// produces the service's sticky revoke. NMC issuance/ready is TestCoreServe.
func TestCoreV2BookingPayments(t *testing.T) {
	for _, coin := range []string{"btc", "ltc"} {
		t.Run(coin, func(t *testing.T) {
			lab := newPaymentCoreLab(t, coin)
			c, s, key, pub, agent := bookingV2Fixture(t, coin, lab.read)
			a := &bookingbind.AdapterV2{ServiceV2: c, AgentName: "id/test-agent", LandlordName: "id/test-landlord", AgentPubkey: agent, Now: time.Now, PaymentCoins: []exchange.Coin{exchange.Coin(coin)}}
			ctx := context.Background()
			h, e := a.Book(ctx, pub, exchange.Selection{Template: "demo", Slot: "one", Coin: exchange.Coin(coin)})
			if e != nil {
				t.Fatal(e)
			}
			var contract booking.ContractV2
			if booking.Strict(h.Contract, &contract) != nil {
				t.Fatal("opaque contract")
			}
			consent := booking.ConsentV2(contract, time.Now().Unix())
			if e = consent.Sign(key); e != nil {
				t.Fatal(e)
			}
			h, e = a.Consent(ctx, h.BookingID, jsonCanonical(consent))
			if e != nil || h.MinConfirmations != 2 {
				t.Fatal("payment terms", e)
			}
			lab.pay(h.Address, h.AmountAtomic)
			refresh := func() exchange.Hold {
				t.Helper()
				if e := s.Refresh(ctx); e != nil {
					t.Fatal(e)
				}
				v, e := a.Status(ctx, h.BookingID)
				if e != nil {
					t.Fatal(e)
				}
				if v.ContractSHA256 != h.ContractSHA256 || v.Coin != h.Coin || v.AmountAtomic != h.AmountAtomic || v.MinConfirmations != 2 {
					t.Fatal("frozen payment changed")
				}
				return v
			}
			if refresh().Issuable {
				t.Fatal("mempool issued")
			}
			block := lab.mine(1)
			if refresh().Issuable {
				t.Fatal("underconfirmed issued")
			}
			lab.mine(1)
			if !refresh().Issuable {
				t.Fatal("confirmed payment refused")
			}
			lab.rpc("", "invalidateblock", block)
			if !refresh().Revoked {
				t.Fatal("reorg not revoked")
			}
			lab.rpc("", "reconsiderblock", block)
			if !refresh().Revoked {
				t.Fatal("reorg revoke cleared")
			}
		})
	}
}
