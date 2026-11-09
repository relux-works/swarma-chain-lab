package signerservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	pc "relux.works/swarma-chain-lab/experiments/payment-chain"
	rental "relux.works/swarma-chain-lab/experiments/rental"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type paymentRelay struct{}

func (paymentRelay) Publish(_ context.Context, e booking.Event) error { return e.Verify() }
func serviceBooking(t *testing.T, l *coreLab, lab *paymentCoreLab, coin string) *booking.ServiceV2 {
	t.Helper()
	profile := []byte("public signer service integration profile")
	provider, providerPub, _ := testKey(4)
	p := l.cfg.Policy.Policy
	template := booking.Template{Version: 1, ID: "demo", ProfileID: "test", ProfileVersion: "1", ProfileSHA256: hash(profile), Allowed: []string{"pay"}, Forbidden: []string{"deliver", "publish", "repository.push", "secret.release"}, BudgetSat: 10000}
	seed := sha256.Sum256([]byte("public signer service xpub/" + coin))
	master, e := hdkeychain.NewMaster(seed[:], &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	branch, e := master.Neuter()
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(l.private, "booking-"+coin)
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := booking.ConfigV2{StateDir: root, AgentPubkey: p.AgentPubkey, ProviderPubkey: providerPub, HoldSeconds: 1200, PriceUSDCents: 1, Template: template, TemplateSHA256: hash(eventBytes(template)), Slots: []booking.Slot{{ID: "slot", StationName: p.AgentName, NotBefore: 501, NotAfter: 4101, PaymentPolicy: "advance"}}, Coins: map[string]booking.CoinConfig{coin: {PublicBranch: branch.String(), PublicBranchSHA256: hash([]byte(branch.String())), USDMicrosPerCoin: 1000000, RateAsOf: 500, MaxRateAgeSeconds: 60, MinConfirmations: 2}}, Limits: booking.Limits{MaxBlocks: 2016, MaxMempool: 100000, MaxCalls: 200000, MaxBytes: 512 << 20}}
	s, e := booking.NewServiceV2(cfg, profile, provider, map[string]booking.Node{coin: lab.read}, l.observer, paymentRelay{}, func() time.Time { return time.Unix(500, 0) })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}

// Actual ServiceV2 outbox bytes flow into the real P1 issuer and service on
// BTC/LTC/NMC, with separate watcher/issuer credentials and a separate NMC
// identity node. Reorg before issuance leaves reservations unchanged; sticky
// reorg after issuance spends exactly that grant's seal even after restoration.
func TestCoreV2Payments(t *testing.T) {
	l := newCore(t)
	ctx := context.Background()
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			lab := newPaymentCoreLab(t, coin)
			l.renew()
			l.cfg.StateDir = dir(t)
			l.cfg.Policy.Policy.StateDir = dir(t)
			seal, fund := l.fund("seal", 200000), l.fund("funding", 2000000)
			service := serviceBooking(t, l, lab, coin)
			renter, renterPub, _ := testKey(2)
			b, e := service.Book(ctx, booking.BookInputV2{SlotID: "slot", Coin: pc.Coin(coin), RenterPubkey: renterPub, PrivacyAcknowledged: true})
			if e != nil {
				t.Fatal(e)
			}
			consent := booking.ConsentV2(b.Contract, 500)
			if e = consent.Sign(renter); e != nil {
				t.Fatal(e)
			}
			if _, e = service.AcceptConsent(ctx, b.Contract.BookingID, consent); e != nil {
				t.Fatal(e)
			}
			lab.pay(b.Contract.Payment.Address, b.Contract.Payment.AmountAtoms)
			refresh := func() booking.BookingV2 {
				t.Helper()
				if e := service.Refresh(ctx); e != nil {
					t.Fatal(e)
				}
				v, e := service.Get(b.Contract.BookingID)
				if e != nil {
					t.Fatal(e)
				}
				return v
			}
			if refresh().Issuance != nil {
				t.Fatal("mempool request issued")
			}
			block := lab.mine(1)
			if refresh().Issuance != nil {
				t.Fatal("underconfirmed request issued")
			}
			lab.mine(1)
			ready := refresh()
			if ready.Issuance == nil {
				t.Fatal("confirmed request absent")
			}
			// Consume the actual exporter; no handwritten Item or index bridges this seam.
			source, e := OpenFileSource(filepath.Join(l.private, "booking-"+coin))
			if e != nil {
				t.Fatal(e)
			}
			batch, e := source.Pull(ctx, "", MaxRecords)
			var item Item
			if e != nil || len(batch) != 1 || strict(batch[0].Raw, &item) != nil || item.Request != string(eventBytes(ready.Issuance)) || item.Publication != string(eventBytes(ready.PackageEvent)) {
				t.Fatal("booking exporter intake", e)
			}
			checkBookingFileSource(t, source, batch)
			ip := rental.IssuerPolicyV2{IssuerPolicy: l.cfg.Policy, PaymentPolicies: map[string]rental.PaymentAdmissionPolicy{coin: {MaxRateAgeSeconds: 60, MinConfirmations: 2, Limits: pc.Limits{MaxBlocks: 2016, MaxMempool: 100000, MaxCalls: 200000, MaxBytes: 512 << 20}}}}
			l.cfg.Profile = "v2"
			l.cfg.PaymentPolicies = ip.PaymentPolicies
			adapter := V2Issuer{ip, l.observer, map[string]su.Node{coin: lab.issuer}, l.cfg.GrantKeyPath}
			broadcaster, e := NewRPCBroadcast(l.send, l.read)
			if e != nil {
				t.Fatal(e)
			}
			x, e := Open(l.cfg, adapter, l.observer, broadcaster, l.sink)
			if e != nil {
				t.Fatal(e)
			}
			defer x.Close()
			if e = x.Enroll(ctx, []su.PlanInput{seal, fund}, 500); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadFile(filepath.Join(l.cfg.StateDir, "ledger.json"))
			lab.rpc("", "invalidateblock", block)
			denied, e := x.Process(ctx, encode(item), BookingSource, 500)
			if e == nil || e.Error() != "PAYMENT_CONFIRMATIONS" {
				t.Fatal("own-node reorg denial", denied, e)
			}
			after, _ := os.ReadFile(filepath.Join(l.cfg.StateDir, "ledger.json"))
			if !bytes.Equal(before, after) || len(x.state.Operations) != 0 {
				t.Fatal("reorg allocated authority")
			}
			lab.rpc("", "reconsiderblock", block)
			if e = x.Pull(ctx, source, BookingSource, 500); e != nil {
				t.Fatal(e)
			}
			intakeBefore := encode(x.state)
			if e = x.Pull(ctx, source, BookingSource, 500); e != nil || !bytes.Equal(intakeBefore, encode(x.state)) {
				t.Fatal("duplicate export intake", e)
			}
			result := x.Step(ctx, 500)
			if len(result) != 1 || result[0].Reason != "" || result[0].Phase != "stored" {
				t.Fatal("v2 issue", result)
			}
			record, e := x.readRecord(x.state.Operations[0])
			if e != nil {
				t.Fatal(e)
			}
			l.mine(1)
			p := l.cfg.Policy.Policy
			p.StateDir = dir(t)
			live := rental.Check(ctx, l.observer, p, record.Presentation, p.AgentName, renterPub, 502)
			if live.Verdict != "live" {
				t.Fatal("v2 grant not live", live)
			}
			lab.rpc("", "invalidateblock", block)
			revoked := refresh()
			if revoked.Revoke == nil || revoked.Revoke.Reason != "payment_reorged" {
				t.Fatal("sticky revoke absent")
			}
			lab.rpc("", "reconsiderblock", block)
			restored := refresh()
			if restored.Revoke == nil || !bytes.Equal(eventBytes(restored.Revoke), eventBytes(revoked.Revoke)) {
				t.Fatal("restoration erased revoke")
			}
			var revoke Revoke
			if e = json.Unmarshal(eventBytes(restored.Revoke), &revoke); e != nil {
				t.Fatal(e)
			}
			revokeBatch, e := source.Pull(ctx, batch[0].After, MaxRecords)
			var revokeItem Item
			if e != nil || len(revokeBatch) != 1 || strict(revokeBatch[0].Raw, &revokeItem) != nil || !bytes.Equal(encode(revokeItem.Revoke), encode(revoke)) {
				t.Fatal("booking revoke intake", e)
			}
			if e = x.Pull(ctx, source, BookingSource, 502); e != nil {
				t.Fatal(e)
			}
			rr, e := x.Process(ctx, encode(revokeItem), BookingSource, 502)
			if e != nil || rr.Phase != "broadcast" {
				t.Fatal("sticky service revoke", rr, e)
			}
			rr2, e := x.Process(ctx, encode(revokeItem), BookingSource, 502)
			if e != nil || rr2.TxID != rr.TxID {
				t.Fatal("sticky replay", rr2, e)
			}
			closed := rental.Check(ctx, l.observer, p, record.Presentation, p.AgentName, renterPub, 502)
			if closed.Reason != "SEAL_SPENT" || !closed.Closed {
				t.Fatal("wrong seal revoke", closed)
			}
			l.save("v2-"+coin+".json", map[string]any{"coin": coin, "issue": result[0], "live": live, "revoke": rr, "closed": closed, "preissue_reorg_no_effect": true, "restored_payment_sticky": true})
		})
	}
}
