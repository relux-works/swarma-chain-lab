package rental

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type paymentRelay struct{ events []booking.Event }

func (r *paymentRelay) Publish(_ context.Context, e booking.Event) error {
	if err := e.Verify(); err != nil {
		return err
	}
	r.events = append(r.events, e)
	return nil
}

type paymentBooking struct {
	s       *booking.ServiceV2
	cfg     booking.ConfigV2
	profile []byte
	nodes   map[string]booking.Node
	relay   *paymentRelay
	now     int64
}

func newPaymentBooking(t *testing.T, l *coreLab, labs map[string]*paymentCoreLab, label string) *paymentBooking {
	t.Helper()
	f := &paymentBooking{profile: []byte("public integration profile"), now: 500, nodes: map[string]booking.Node{}, relay: &paymentRelay{}}
	provider, providerPub := testKey(4)
	_, agent := testKey(3)
	template := booking.Template{Version: 1, ID: "demo", ProfileID: "test", ProfileVersion: "1.0.0", ProfileSHA256: Hash(f.profile), Allowed: []string{"deliver", "pay"}, Forbidden: []string{"publish", "repository.push", "secret.release"}, BudgetSat: 10000}
	seed := sha256.Sum256([]byte("public integration xpub/" + label))
	master, e := hdkeychain.NewMaster(seed[:], &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	branch, e := master.Neuter()
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(l.private, "booking-"+label)
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	f.cfg = booking.ConfigV2{StateDir: root, AgentPubkey: agent, ProviderPubkey: providerPub, HoldSeconds: 1200, PriceUSDCents: 1, Template: template, TemplateSHA256: Hash(eventBytes(template)), Slots: []booking.Slot{{ID: "slot", StationName: l.station, NotBefore: 501, NotAfter: 4101, PaymentPolicy: "advance"}}, Coins: map[string]booking.CoinConfig{}, Limits: booking.Limits{MaxBlocks: 2016, MaxMempool: 100000, MaxCalls: 200000, MaxBytes: 512 << 20}}
	for coin, lab := range labs {
		f.nodes[coin] = lab.read
		f.cfg.Coins[coin] = booking.CoinConfig{PublicBranch: branch.String(), PublicBranchSHA256: Hash([]byte(branch.String())), USDMicrosPerCoin: 1000000, RateAsOf: 500, MaxRateAgeSeconds: 60, MinConfirmations: 2}
	}
	f.s, e = booking.NewServiceV2(f.cfg, f.profile, provider, f.nodes, l.observer, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.s.Close() })
	return f
}
func (f *paymentBooking) refresh(t *testing.T) {
	t.Helper()
	if e := f.s.Refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func (f *paymentBooking) get(t *testing.T, id string) booking.BookingV2 {
	t.Helper()
	b, e := f.s.Get(id)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (f *paymentBooking) restart(t *testing.T, l *coreLab) {
	t.Helper()
	f.s.Close()
	provider, _ := testKey(4)
	var e error
	f.s, e = booking.NewServiceV2(f.cfg, f.profile, provider, f.nodes, l.observer, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if e != nil {
		t.Fatal(e)
	}
}

// Genuine BTC/LTC/NMC nodes use txindex=0 and independent read-only watcher/
// issuer principals. The separate Namecoin node owns identity and seal/funding
// observations. These controls exercise real booking -> issuer -> live grant,
// partial/late/reorg refusals and durable exact replay; no mainnet is contacted.
func TestCorePaymentLifecycle(t *testing.T) {
	if os.Getenv("P1_REGTEST") != "1" {
		t.Skip("requires explicit P1_REGTEST=1")
	}
	l := newCore(t)
	l.grantIdentity()
	labs := map[string]*paymentCoreLab{}
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		labs[coin] = newPaymentCoreLab(t, coin)
	}
	ctx := context.Background()
	nodes := map[string]su.Node{}
	for coin, lab := range labs {
		nodes[coin] = lab.issuer
	}
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			l.agentPointer(labLandlord, 3, true)
			l.landlordKey(1, true)
			pay := labs[coin]
			parentPayT, parentIdentityT := pay.t, l.t
			pay.t, l.t = t, t
			defer func() { pay.t, l.t = parentPayT, parentIdentityT }()
			seal := l.witnessPool(1, true)
			fund := l.witnessPool(7, true)
			p, _, _ := l.grantFixture("p1-"+coin, seal, 2)
			spec := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: fund.TxID, Vout: fund.Vout}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript}
			key, _ := testKey(1)
			keyPath := filepath.Join(l.private, "p1-grant-key")
			if e := os.WriteFile(keyPath, key.Serialize(), 0600); e != nil {
				t.Fatal(e)
			}
			f := newPaymentBooking(t, l, labs, coin)
			_, renterPub := testKey(2)
			b, e := f.s.Book(ctx, booking.BookInputV2{SlotID: "slot", Coin: pc.Coin(coin), RenterPubkey: renterPub, PrivacyAcknowledged: true})
			if e != nil {
				t.Fatal(e)
			}
			id := b.Contract.BookingID
			statePath := filepath.Join(f.cfg.StateDir, "state.json")
			before, _ := os.ReadFile(statePath)
			other := "btc"
			if coin == other {
				other = "ltc"
			}
			if _, e = f.s.Book(ctx, booking.BookInputV2{SlotID: "slot", Coin: pc.Coin(other), RenterPubkey: renterPub, PrivacyAcknowledged: true}); e == nil || e.Error() != "CAPACITY_FULL" {
				t.Fatal("cross-coin capacity", e)
			}
			after, _ := os.ReadFile(statePath)
			if !bytes.Equal(before, after) {
				t.Fatal("capacity refusal wrote state")
			}
			amount := b.Contract.Payment.AmountAtoms
			pay.pay(b.Contract.Payment.Address, amount/2)
			pay.mine(2)
			f.refresh(t)
			if f.get(t, id).Payment != nil {
				t.Fatal("underpayment selected")
			}
			pay.pay(b.Contract.Payment.Address, amount/2)
			pay.mine(2)
			f.refresh(t)
			if f.get(t, id).Payment != nil {
				t.Fatal("underpayments aggregated")
			}
			full := pay.pay(b.Contract.Payment.Address, amount+1000)
			f.refresh(t)
			if f.get(t, id).Payment != nil {
				t.Fatal("mempool admitted")
			}
			block := pay.mine(1)
			f.refresh(t)
			if f.get(t, id).Payment != nil {
				t.Fatal("one confirmation admitted")
			}
			pay.mine(1)
			f.refresh(t)
			paid := f.get(t, id)
			if paid.Payment == nil || paid.Payment.TxID != full || paid.Issuance != nil {
				t.Fatal("threshold/consent boundary")
			}
			pay.rpc("", "invalidateblock", block)
			f.refresh(t)
			if f.get(t, id).Payment != nil || f.get(t, id).Revoke != nil {
				t.Fatal("preissue reorg must return pending")
			}
			pay.rpc("", "reconsiderblock", block)
			f.refresh(t)
			renter, _ := testKey(2)
			consent := booking.ConsentV2(b.Contract, f.now)
			if e = consent.Sign(renter); e != nil {
				t.Fatal(e)
			}
			if _, e = f.s.AcceptConsent(ctx, id, consent); e != nil {
				t.Fatal(e)
			}
			f.refresh(t)
			ready := f.get(t, id)
			if ready.Issuance == nil || !ready.Published {
				t.Fatal("issuance absent")
			}
			request, publication := eventBytes(ready.Issuance), eventBytes(ready.PackageEvent)
			_, provider := testKey(4)
			ip := IssuerPolicyV2{IssuerPolicy: IssuerPolicy{Policy: p, ProviderPubkey: provider}, PaymentPolicies: map[string]PaymentAdmissionPolicy{coin: {MaxRateAgeSeconds: 60, MinConfirmations: 2, Limits: pc.Limits{MaxBlocks: 2016, MaxMempool: 100000, MaxCalls: 200000, MaxBytes: 512 << 20}}}}
			var parsed IssuanceRequestV2
			if e = json.Unmarshal(request, &parsed); e != nil {
				t.Fatal(e)
			}
			deny := func(label, want string, rq, evt []byte, policy IssuerPolicyV2, routes map[string]su.Node, at int64) {
				t.Helper()
				got := IssueGrantWithNodes(ctx, l.observer, routes, policy, rq, evt, seal, spec, keyPath, at)
				if got.Verdict != "refused" || got.Reason != want || len(got.SignedGrant) != 0 || got.Plan != nil {
					t.Fatalf("%s: %+v", label, got)
				}
				assertNoIssuerBurn(t, p.StateDir)
				l.rows = append(l.rows, map[string]any{"p1_coin": coin, "control": label, "reason": got.Reason, "no_burn": true})
			}
			badRequest := parsed
			badRequest.PaymentCoin = other
			deny("request-coin", "PACKAGE_REQUEST_BINDING", eventBytes(badRequest), publication, ip, nodes, 500)
			badRequest = parsed
			badRequest.PaymentGenesis = Hash([]byte("wrong"))
			deny("request-genesis", "PACKAGE_REQUEST_BINDING", eventBytes(badRequest), publication, ip, nodes, 500)
			badRequest = parsed
			badRequest.PaymentVout = 999999
			deny("output-index", "PAYMENT_OUTPUT", eventBytes(badRequest), publication, ip, nodes, 500)
			badRequest = parsed
			badRequest.PaymentBlockHash = Hash([]byte("wrong"))
			deny("active-block", "PAYMENT_ACTIVE_BLOCK", eventBytes(badRequest), publication, ip, nodes, 500)
			badRequest = parsed
			badRequest.PaymentTxID = Hash([]byte("wrong"))
			deny("membership", "PAYMENT_MEMBERSHIP", eventBytes(badRequest), publication, ip, nodes, 500)
			under := ready.Receipts[0].Payment
			badRequest = parsed
			badRequest.PaymentTxID = under.TxID
			badRequest.PaymentVout = under.Vout
			badRequest.PaymentHeight = under.Height
			badRequest.PaymentBlockHash = under.BlockHash
			deny("issuer-underpayment", "PAYMENT_BINDING", eventBytes(badRequest), publication, ip, nodes, 500)
			wrongID := pay.pay(pay.miner, amount)
			wrongBlock := pay.mine(1)
			pay.mine(1)
			var wrongTx struct {
				Vout []struct {
					N      uint32 `json:"n"`
					Script struct {
						Hex string `json:"hex"`
					} `json:"scriptPubKey"`
				} `json:"vout"`
			}
			if e = json.Unmarshal(pay.rpc("", "getrawtransaction", wrongID, true, wrongBlock), &wrongTx); e != nil {
				t.Fatal(e)
			}
			var wrongHeader struct {
				Height int64 `json:"height"`
			}
			if e = json.Unmarshal(pay.rpc("", "getblockheader", wrongBlock), &wrongHeader); e != nil {
				t.Fatal(e)
			}
			badRequest = parsed
			badRequest.PaymentTxID = wrongID
			badRequest.PaymentVout = wrongTx.Vout[0].N
			badRequest.PaymentHeight = wrongHeader.Height
			badRequest.PaymentBlockHash = wrongBlock
			if wrongTx.Vout[0].Script.Hex == b.Script {
				t.Fatal("wrong-script fixture matched")
			}
			deny("issuer-wrong-address", "PAYMENT_BINDING", eventBytes(badRequest), publication, ip, nodes, 500)
			for _, mode := range []string{"stale-rate", "wrong-network-address"} {
				var pp PackageV2
				_ = json.Unmarshal(eventBytes(ready.Package), &pp)
				if mode == "stale-rate" {
					pp.Contract.Payment.RateAsOf = 439
				} else {
					params := chaincfg.MainNetParams
					if coin == "nmc" {
						params.PubKeyHashAddrID = 52
						a, err := btcutil.NewAddressPubKeyHash(make([]byte, 20), &params)
						if err != nil {
							t.Fatal(err)
						}
						pp.Contract.Payment.Address = a.EncodeAddress()
					} else {
						if coin == "ltc" {
							params.Bech32HRPSegwit = "ltc"
						}
						a, err := btcutil.NewAddressWitnessPubKeyHash(make([]byte, 20), &params)
						if err != nil {
							t.Fatal(err)
						}
						pp.Contract.Payment.Address = a.EncodeAddress()
					}
				}
				badRequest = parsed
				hash := Hash(eventBytes(pp.Contract))
				badRequest.ContractSHA256 = hash
				pp.Consent.Tags = [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", id}, {"privacy", pp.Contract.PrivacySHA256}}
				pp.Consent = signedEvent(t, pp.Consent, 2)
				pp.ProviderSignature = signature(t, hash, 4)
				var ep Event
				_ = json.Unmarshal(publication, &ep)
				ep.Tags = [][]string{{"t", "swarma-rental-package-v1"}, {"contract", hash}, {"booking", id}, {"e", pp.Consent.ID}}
				ep.Content = string(eventBytes(pp))
				ep = signedEvent(t, ep, 4)
				badRequest.PackageEventID = ep.ID
				reason := "QUOTE_RATE"
				if mode == "wrong-network-address" {
					reason = "PAYMENT_ADDRESS"
				}
				deny(mode, reason, eventBytes(badRequest), eventBytes(ep), ip, nodes, 500)
			}
			deny("missing-route", "PAYMENT_NODE_UNAVAILABLE", request, publication, ip, nil, 500)
			deny("swapped-route", "NODE_PRODUCT", request, publication, ip, map[string]su.Node{coin: labs[other].issuer}, 500)
			stricter := ip
			stricter.PaymentPolicies = map[string]PaymentAdmissionPolicy{coin: ip.PaymentPolicies[coin]}
			policy := stricter.PaymentPolicies[coin]
			policy.MinConfirmations = 3
			stricter.PaymentPolicies[coin] = policy
			deny("issuer-minimum", "PAYMENT_POLICY", request, publication, stricter, nodes, 500)
			deny("expired-hold", "hold_expired_at_admission", request, publication, ip, nodes, ready.HoldExpiresAt)
			var badPub Event
			_ = json.Unmarshal(publication, &badPub)
			badPub.Sig = fmt.Sprintf("%0128d", 0)
			deny("publication-signature", "PACKAGE_EVENT", request, eventBytes(badPub), ip, nodes, 500)
			pay.rpc("", "invalidateblock", block)
			deny("issuer-reorg", "PAYMENT_CONFIRMATIONS", request, publication, ip, nodes, 500)
			pay.rpc("", "reconsiderblock", block)
			tip := text(t, l.rpc("", "getbestblockhash"))
			issued := IssueGrantWithNodes(ctx, l.observer, nodes, ip, request, publication, seal, spec, keyPath, 500)
			requirePrepared(t, issued)
			if issued.PaymentAdmission == nil || issued.PaymentAdmission.Coin != coin || issued.PaymentAdmission.Observation == nil || issued.PaymentAdmission.Observation.SurplusAtoms != 1000 {
				t.Fatal("coin/surplus evidence missing")
			}
			if text(t, l.rpc("", "getbestblockhash")) != tip {
				t.Fatal("issuer mutated chain")
			}
			signed, e := ParseSignedGrant(issued.SignedGrant)
			if e != nil || signed.Grant.ContractSHA256 != b.Contract.Hash() || signed.Grant.Budget == nil || *signed.Grant.Budget != 10000 {
				t.Fatal("v2 hash or NMC execution budget changed", e)
			}
			pay.noise()
			f.refresh(t)
			unchanged := f.get(t, id)
			if unchanged.Payment == nil || unchanged.Payment.TxID != full || !bytes.Equal(eventBytes(unchanged.Issuance), request) {
				t.Fatal("unrelated many-input/segwit noise changed watcher verdict")
			}
			readmission := AdmitIssuanceV2(ctx, nodes, ip, request, publication, 500)
			if readmission.Verdict != "admit" || readmission.Observation == nil || readmission.Observation.Payment.TxID != full {
				t.Fatal("noise changed issuer verdict", readmission)
			}
			l.rows = append(l.rows, map[string]any{"p1_coin": coin, "control": "unrelated-many-input-segwit-noise", "pass": true})
			issuanceTx := l.sendPlan(*issued.Plan, true)
			proof, e := PresentIssuedGrant(issued.SignedGrant, issuanceTx)
			if e != nil {
				t.Fatal(e)
			}
			l.checkGrant("p1-"+coin+"-live", p, signed.Grant, proof, 501, "live", "LIVE", false)
			replay := IssueGrantWithNodes(ctx, nil, nil, ip, request, publication, seal, spec, "", ready.HoldExpiresAt+1)
			requirePrepared(t, replay)
			if !replay.Replay || !bytes.Equal(replay.SignedGrant, issued.SignedGrant) || !sameJSON(replay.Plan, issued.Plan) || !sameJSON(replay.PaymentAdmission, issued.PaymentAdmission) {
				t.Fatal("exact offline replay changed")
			}
			issueBytes, _ := os.ReadFile(filepath.Join(f.cfg.StateDir, "issue-"+id+".json"))
			pay.rpc("", "invalidateblock", block)
			f.refresh(t)
			revoked := f.get(t, id)
			if revoked.Revoke == nil || revoked.Payment != nil || revoked.Status != "revoked" {
				t.Fatal("postissue reorg not revoked")
			}
			revokeBytes := eventBytes(revoked.Revoke)
			f.restart(t, l)
			pay.rpc("", "reconsiderblock", block)
			f.refresh(t)
			recovered := f.get(t, id)
			issueAfter, _ := os.ReadFile(filepath.Join(f.cfg.StateDir, "issue-"+id+".json"))
			if recovered.Payment != nil || !bytes.Equal(eventBytes(recovered.Revoke), revokeBytes) || !bytes.Equal(issueBytes, issueAfter) {
				t.Fatal("restart resurrected revoked booking")
			}
			for _, label := range []string{"cross-coin-capacity", "underpayment", "no-aggregation", "mempool", "threshold", "consent-required", "preissue-reorg", "prepared", "live", "exact-replay", "postissue-reorg", "sticky-restart"} {
				l.rows = append(l.rows, map[string]any{"p1_coin": coin, "control": label, "pass": true})
			}
			l.save("p1-"+coin+"-result.json", map[string]any{"contract": b.Contract, "request": json.RawMessage(request), "issued": issued, "revoke": revoked.Revoke, "live_issuance_txid": issuanceTx})
			// A separate fresh public branch keeps late/RBF examples independent of
			// earlier payment history and the already-burned issuance record.
			modes := []string{"late", "rbf", "drop"}
			if coin != "ltc" {
				modes = append(modes, "full-rbf")
			} else {
				modes = append(modes, "miner-conflict")
			}
			for _, mode := range modes {
				extra := newPaymentBooking(t, l, labs, coin+"-"+mode)
				bookingRow, err := extra.s.Book(ctx, booking.BookInputV2{SlotID: "slot", Coin: pc.Coin(coin), RenterPubkey: renterPub, PrivacyAcknowledged: true})
				if err != nil {
					t.Fatal(err)
				}
				ev := booking.ConsentV2(bookingRow.Contract, extra.now)
				if err = ev.Sign(renter); err != nil {
					t.Fatal(err)
				}
				if _, err = extra.s.AcceptConsent(ctx, bookingRow.Contract.BookingID, ev); err != nil {
					t.Fatal(err)
				}
				paymentID := pay.paySignaling(bookingRow.Contract.Payment.Address, bookingRow.Contract.Payment.AmountAtoms, mode != "full-rbf" && mode != "miner-conflict")
				extra.refresh(t)
				if mode == "late" {
					pay.mine(1)
					extra.now = bookingRow.HoldExpiresAt - 1
					extra.refresh(t)
					pay.mine(1)
					extra.now++
					extra.refresh(t)
					late := extra.get(t, bookingRow.Contract.BookingID)
					if late.Payment != nil || late.Issuance != nil || late.Status != "expired" {
						t.Fatal("late full threshold admitted")
					}
				} else if mode == "miner-conflict" {
					conflicting := pay.nonSignalingReplacement(paymentID, bookingRow.Script, true)
					pay.rpc("", "generateblock", pay.miner, []string{conflicting})
					pay.mine(1)
					extra.refresh(t)
					missing := extra.get(t, bookingRow.Contract.BookingID)
					if missing.Payment != nil || missing.Issuance != nil || len(missing.Receipts) != 1 || missing.Receipts[0].Disposition != "refund_review" {
						t.Fatal("miner-conflicted payment issued")
					}
					goodID := pay.pay(bookingRow.Contract.Payment.Address, bookingRow.Contract.Payment.AmountAtoms)
					pay.mine(2)
					extra.refresh(t)
					valid := extra.get(t, bookingRow.Contract.BookingID)
					if valid.Payment == nil || valid.Payment.TxID != goodID || valid.Issuance == nil {
						t.Fatal("miner conflict valid neighbor")
					}
				} else if mode == "full-rbf" {
					replacementID := pay.replaceNonSignaling(paymentID, bookingRow.Script)
					extra.refresh(t)
					if extra.get(t, bookingRow.Contract.BookingID).Payment != nil {
						t.Fatal("full-RBF pending marked paid")
					}
					pay.mine(2)
					extra.refresh(t)
					replacement := extra.get(t, bookingRow.Contract.BookingID)
					if replacement.Payment == nil || replacement.Payment.TxID != replacementID || replacement.Issuance == nil {
						t.Fatal("full-RBF replacement not selected")
					}
				} else if mode == "drop" {
					var tx struct {
						Hex string `json:"hex"`
					}
					if err = json.Unmarshal(pay.rpc("lab", "gettransaction", paymentID), &tx); err != nil {
						t.Fatal(err)
					}
					pay.restart()
					extra.refresh(t)
					dropped := extra.get(t, bookingRow.Contract.BookingID)
					if dropped.Payment != nil || dropped.Issuance != nil || len(dropped.Receipts) != 1 || dropped.Receipts[0].Disposition != "refund_review" {
						t.Fatal("dropped payment became paid or lost its audit receipt")
					}
					pay.rpc("", "sendrawtransaction", tx.Hex)
					pay.mine(2)
					extra.refresh(t)
					valid := extra.get(t, bookingRow.Contract.BookingID)
					if valid.Payment == nil || valid.Payment.TxID != paymentID || valid.Issuance == nil {
						t.Fatal("drop recovery positive control")
					}
				} else {
					var bumped struct {
						TxID   string   `json:"txid"`
						Errors []string `json:"errors"`
					}
					if err = json.Unmarshal(pay.rpc("lab", "bumpfee", paymentID, map[string]any{"fee_rate": 1000}), &bumped); err != nil || len(bumped.Errors) != 0 || bumped.TxID == "" || bumped.TxID == paymentID {
						t.Fatal("RBF fixture failed", err)
					}
					var tx struct {
						Hex string `json:"hex"`
					}
					if err = json.Unmarshal(pay.rpc("lab", "gettransaction", bumped.TxID), &tx); err != nil {
						t.Fatal(err)
					}
					pay.rpc("", "sendrawtransaction", tx.Hex)
					extra.refresh(t)
					pending := extra.get(t, bookingRow.Contract.BookingID)
					if pending.Payment != nil || pending.Issuance != nil {
						t.Fatal("RBF mempool admitted")
					}
					pay.mine(2)
					extra.refresh(t)
					replacement := extra.get(t, bookingRow.Contract.BookingID)
					if replacement.Payment == nil || replacement.Payment.TxID != bumped.TxID || replacement.Issuance == nil {
						t.Fatal("confirmed replacement missing")
					}
					oldSeen := false
					for _, receipt := range replacement.Receipts {
						if receipt.Payment.TxID == paymentID {
							oldSeen = true
							if receipt.Disposition != "refund_review" || receipt.EligibleAt != 0 {
								t.Fatal("replaced receipt still eligible")
							}
						}
					}
					if !oldSeen {
						t.Fatal("replacement lost audit receipt")
					}
				}
				if mode != "late" {
					exact := extra.get(t, bookingRow.Contract.BookingID)
					checked := AdmitIssuanceV2(ctx, nodes, ip, eventBytes(exact.Issuance), eventBytes(exact.PackageEvent), extra.now)
					if checked.Verdict != "admit" || checked.Observation == nil || checked.Observation.SurplusAtoms != 0 {
						t.Fatal("exact payment issuer control", checked)
					}
				}
				l.rows = append(l.rows, map[string]any{"p1_coin": coin, "control": mode, "pass": true})
			}

		})
	}
	l.save("p1-controls.json", l.rows)
}
