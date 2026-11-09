package smoke

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type Observation struct {
	Gate string `json:"gate"`
	AtMS int64  `json:"at_ms"`
}
type Attestation struct {
	Request Request `json:"request"`
	Receipt Receipt `json:"receipt"`
}
type Report struct {
	Version              int           `json:"version"`
	RunID                string        `json:"run_id"`
	Mode                 string        `json:"mode"`
	Scenario             string        `json:"scenario"`
	Outcome              string        `json:"outcome"`
	Failure              string        `json:"failure,omitempty"`
	ConfigSHA256         string        `json:"config_sha256"`
	EnvironmentSHA256    string        `json:"environment_sha256"`
	StartedMS            int64         `json:"started_ms"`
	FinishedMS           int64         `json:"finished_ms"`
	BookingID            string        `json:"booking_id,omitempty"`
	ContractSHA256       string        `json:"contract_sha256,omitempty"`
	PresentationSHA256   string        `json:"presentation_sha256,omitempty"`
	ApplicationIdleMS    int64         `json:"application_idle_ms"`
	ClosureLatencyMS     int64         `json:"closure_latency_ms"`
	Client               []Observation `json:"client_observed"`
	Operator             []Attestation `json:"operator_attested"`
	NativeClosureNotices []string      `json:"native_closure_notices"`
	Limits               []string      `json:"limits"`
}
type runner struct {
	c           Config
	p           profile
	op          Operator
	report      Report
	contract    *booking.ContractV2
	grant       *rental.GrantPresentation
	lastReceipt int64
	seenRumors  int64
}

func (r *runner) mark(s string) {
	r.report.Client = append(r.report.Client, Observation{s, time.Now().UnixMilli()})
}
func Run(ctx context.Context, c Config, op Operator) (Report, error) { return run(ctx, c, op, host()) }

// RunSelfTest is deliberately library-only for the existing IT2 Darwin adapter.
// It changes the fixture profile and can never produce a host outcome.
func RunSelfTest(ctx context.Context, c Config, op Operator) (Report, error) {
	return run(ctx, c, op, rehearsal(c))
}
func run(ctx context.Context, c Config, op Operator, p profile) (Report, error) {
	id, e := freshID()
	if e != nil {
		return Report{}, e
	}
	r := runner{seenRumors: -1, c: c, p: p, op: op, report: Report{Version: 1, RunID: id, Mode: p.mode, Scenario: c.Scenario, Outcome: "FAIL", ConfigSHA256: rental.Hash(encode(c)), EnvironmentSHA256: c.EnvironmentSHA256, StartedMS: time.Now().UnixMilli(), Client: []Observation{}, Operator: []Attestation{}, Limits: []string{"Operator receipts are assertions, not independently verified host evidence.", "No physical erasure claim. Infra must retain and review underlying sanitized observations."}}}
	if p.mode == "self-test" {
		r.report.Limits = append(r.report.Limits, "Darwin runner self-test: fake helper, registrar overlay, one Core/shared outbox and fixture-only signer cycles; no Linux UID, peer, remote mirror, running signer or storage acceptance.")
	}
	if e = c.validate(p); e == nil {
		if op == nil {
			e = refuse("OPERATOR_MISSING")
		} else {
			e = r.drive(ctx)
		}
	}
	if e != nil {
		r.report.Failure = code(e)
	} else if p.mode == "host" {
		r.report.Outcome = "CLIENT_PASS_OPERATOR_ATTESTED"
	} else {
		r.report.Outcome = "PASS_SELF_TEST"
	}
	r.report.FinishedMS = time.Now().UnixMilli()
	return r.report, e
}
func (r *runner) drive(ctx context.Context) error {
	c, p := r.c, r.p
	if _, e := r.observe(ctx, "preflight", time.Now().Add(10*time.Minute)); e != nil {
		return e
	}
	peer, e := connect(ctx, c.Relay, c.AgentPubkey)
	if e != nil {
		return e
	}
	defer peer.close()
	defer func() { r.report.NativeClosureNotices = append([]string{}, peer.notices...) }()
	command := func(s, want string) error {
		if e := peer.send(ctx, s, 0, p.pace); e != nil {
			return e
		}
		return peer.expect(ctx, want, 15*time.Second)
	}
	if e = peer.send(ctx, "terms", p.pow, p.pace); e != nil {
		return e
	}
	var terms exchange.Terms
	if e = peer.object(ctx, "terms", &terms, 15*time.Second); e != nil {
		return e
	}
	if e = checkTerms(c, p, terms); e != nil {
		return e
	}
	r.mark("terms_pins")
	book := "book " + p.template + " " + p.slot
	if e = command(book, exchange.Help); e != nil {
		return e
	}
	r.mark("missing_coin_refused")
	if e = command(book+" btc", exchange.CoinNotOffered); e != nil {
		return e
	}
	r.mark("unoffered_coin_refused")
	var cat booking.CatalogueV2
	if e = get(ctx, c.Booking, "/catalogue?until="+strconv.FormatInt(time.Now().Unix()+86400, 10)+"&limit=16", &cat); e != nil {
		return e
	}
	available := false
	for _, s := range cat.Slots {
		if s.ID == p.slot && s.NotBefore == c.NotBefore && s.NotAfter == c.NotAfter {
			available = true
		}
	}
	if !available || cat.TemplateSHA256 != c.TemplateSHA256 {
		return refuse("CATALOGUE_PRESERVED")
	}
	r.mark("catalogue_preserved")
	if e = peer.send(ctx, book+" nmc", 0, p.pace); e != nil {
		return e
	}
	var reply contractEnvelope
	if e = peer.object(ctx, "contract", &reply, 15*time.Second); e != nil {
		return e
	}
	raw, e := base64.StdEncoding.DecodeString(reply.Contract)
	if e != nil {
		return refuse("CONTRACT_BASE64")
	}
	var contract booking.ContractV2
	if e = Strict(raw, &contract); e != nil {
		return e
	}
	if reply.Expires <= time.Now().Unix() || !bytes.Equal(raw, contract.Bytes()) || reply.Hash != contract.Hash() || reply.ID != contract.BookingID {
		return refuse("CONTRACT_CANONICAL")
	}
	if e = checkContract(c, p, contract, peer.key.PubKeyHex()); e != nil {
		return e
	}
	r.contract = &contract
	r.report.BookingID = contract.BookingID
	r.report.ContractSHA256 = contract.Hash()
	r.mark("contract_bound")
	wrong, e := nostr.GeneratePrivKey()
	if e != nil {
		return refuse("CONSENT_KEY")
	}
	consent := func(k *nostr.PrivKey) (string, error) {
		b := k.Bytes()
		sk, _ := btcec.PrivKeyFromBytes(b)
		clear(b)
		defer sk.Zero()
		ev := booking.ConsentV2(contract, time.Now().Unix())
		if ev.Sign(sk) != nil {
			return "", refuse("CONSENT_SIGN")
		}
		return "consent " + string(encode(ev)), nil
	}
	bad, e := consent(wrong)
	if e != nil {
		return e
	}
	if e = command(bad, exchange.Help); e != nil {
		return e
	}
	var before booking.BookingV2
	if e = get(ctx, c.Booking, "/booking?id="+contract.BookingID, &before); e != nil {
		return e
	}
	if before.Package != nil || before.Issuance != nil || before.Contract.Hash() != contract.Hash() || before.HoldExpiresAt != reply.Expires {
		return refuse("FOREIGN_CONSENT_STATE")
	}
	r.mark("foreign_consent_preserved")
	good, e := consent(peer.key)
	if e != nil {
		return e
	}
	if e = peer.send(ctx, good, 0, p.pace); e != nil {
		return e
	}
	var pay paymentEnvelope
	if e = peer.object(ctx, "pay", &pay, 15*time.Second); e != nil {
		return e
	}
	if e = checkPaymentEnvelope(pay, contract, reply.Expires, p.depth, time.Now().Unix()); e != nil {
		return e
	}
	r.mark("payment_bound")
	if _, e = r.observe(ctx, "pregrant", time.Now().Add(2*time.Minute)); e != nil {
		return e
	}
	if _, e = r.observe(ctx, "unconfirmed_payment", time.Now().Add(5*time.Minute)); e != nil {
		return e
	}
	var unpaid booking.BookingV2
	if e = get(ctx, c.Booking, "/booking?id="+contract.BookingID, &unpaid); e != nil {
		return e
	}
	if unpaid.Issuance != nil || unpaid.Contract.Hash() != contract.Hash() {
		return refuse("UNCONFIRMED_ISSUANCE")
	}
	r.mark("unconfirmed_issuance_absent")
	issuedReceipt, e := r.observe(ctx, "issue", time.Now().Add(5*time.Minute))
	if e != nil {
		return e
	}
	var issued struct {
		BookingID    string `json:"booking_id"`
		GrantID      string `json:"grant_id"`
		Presentation string `json:"presentation_base64"`
		NotBefore    int64  `json:"not_before"`
		NotAfter     int64  `json:"not_after"`
		Notice       string `json:"notice"`
	}
	if e = peer.object(ctx, "issued", &issued, 15*time.Second); e != nil {
		return e
	}
	proof, e := base64.StdEncoding.DecodeString(issued.Presentation)
	if e != nil {
		return refuse("PRESENTATION_BASE64")
	}
	grant, e := rental.ParseGrantPresentation(proof)
	if e != nil {
		return refuse("PRESENTATION_SIGNATURE")
	}
	if issued.BookingID != contract.BookingID || issued.GrantID != grant.SignedGrant.ID() || issued.NotBefore != contract.NotBefore || issued.NotAfter != contract.NotAfter || issuedReceipt.Hashes["presentation"] != rental.Hash(proof) {
		return refuse("ISSUED_BINDING")
	}
	if e = checkGrant(c, contract, grant); e != nil {
		return e
	}
	r.grant = &grant
	r.report.PresentationSHA256 = rental.Hash(proof)
	r.mark("signed_presentation_bound")
	if e = peer.expect(ctx, "ready", time.Until(time.Unix(contract.NotBefore+25, 0))); e != nil {
		return e
	}
	if time.Now().Unix() < contract.NotBefore || time.Now().Unix() >= contract.NotAfter {
		return refuse("READY_WINDOW")
	}
	r.mark("ready")
	tag, e := gateway.GrantCertTag(proof)
	if e != nil {
		return refuse("PRESENTATION_TAG")
	}
	if e = peer.send(ctx, "first model request", 0, 0, tag); e != nil {
		return e
	}
	if e = peer.expect(ctx, "model fixture reply", 15*time.Second); e != nil {
		return e
	}
	r.mark("first_model_reply")
	if _, e = r.observe(ctx, "running", time.Now().Add(2*time.Minute)); e != nil {
		return e
	}
	for i := 1; i < p.requests; i++ {
		if e = peer.send(ctx, fmt.Sprintf("model request %d", i+1), 0, 0); e != nil {
			return e
		}
		if e = peer.expect(ctx, "model fixture reply", 15*time.Second); e != nil {
			return e
		}
	}
	r.mark("model_replies")
	for i := 0; i < 2; i++ {
		if e = peer.send(ctx, "request beyond cap", 0, 0); e != nil {
			return e
		}
		if e = peer.expect(ctx, "MODEL_CAP", 15*time.Second); e != nil {
			return e
		}
	}
	r.mark("cap_and_terminal_refused")
	idleStart := peer.lastSend
	if _, e = r.observe(ctx, "caps", time.Now().Add(2*time.Minute)); e != nil {
		return e
	}
	deadline := time.Unix(contract.NotAfter+25, 0)
	closureBase := time.Unix(contract.NotAfter, 0)
	if c.Scenario == "expiry" {
		if time.Unix(contract.NotAfter, 0).Sub(idleStart) <= 90*time.Second {
			return refuse("IDLE_WINDOW")
		}
	} else {
		receipt, e := r.observe(ctx, "revoke", time.Now().Add(2*time.Minute))
		if e != nil {
			return e
		}
		// The clock starts at observed spend, not after the operator handoff returns.
		closureBase = time.UnixMilli(receipt.ObservedMS)
		deadline = closureBase.Add(30 * time.Second)
		if e = peer.send(ctx, "must not reach revoked slot", 0, 0); e != nil {
			return e
		}
		r.mark("revoked_probe_sent")
	}
	closure, e := r.observe(ctx, "close", deadline)
	if e != nil {
		return e
	}
	if e = checkClosure(c.Scenario, contract.NotAfter, closure.ObservedMS, time.Since(idleStart), time.Now()); e != nil {
		return e
	}
	r.report.ApplicationIdleMS = time.Since(idleStart).Milliseconds()
	r.report.ClosureLatencyMS = closure.ObservedMS - closureBase.UnixMilli()
	if e = peer.quiet(c.Scenario, contract.NotAfter); e != nil {
		return e
	}
	r.mark("closure_timing")
	peer.restartAt = time.Now().Unix()
	if _, e = r.observe(ctx, "restart", time.Now().Add(5*time.Minute)); e != nil {
		return e
	}
	// A restarted gateway may asynchronously replay old input through its
	// non-grantee exchange. Observe a bounded quiet interval without sending
	// more application messages; allow only its exact fresh control refusals.
	if e = pause(ctx, 2*time.Second); e != nil {
		return e
	}
	if e = peer.quiet(c.Scenario, contract.NotAfter); e != nil {
		return e
	}
	r.mark("restart_two_second_observation")
	return nil
}
func checkTerms(c Config, p profile, t exchange.Terms) error {
	if t.AgentName != c.AgentName || t.LandlordName != c.LandlordName || t.PrivacyNotice != booking.PrivacyNotice || t.PrivacySHA256 != privacy() || t.PowBits != p.pow || len(t.Templates) != 1 {
		return refuse("TERMS_PINS")
	}
	v := t.Templates[0]
	if v.ID != p.template || v.SHA256 != c.TemplateSHA256 || v.ProfileID != c.ProfileID || v.ProfileVersion != c.ProfileVersion || v.ProfileSHA256 != c.ProfileSHA256 || v.PriceUSDCents != p.price || !same(v.SlotLengths, []int64{p.window}) || !same(v.Coins, []exchange.Coin{exchange.NMC}) {
		return refuse("TERMS_TEMPLATE")
	}
	for _, s := range t.Slots {
		if s.ID == p.slot && s.TemplateID == p.template && s.NotBefore == c.NotBefore && s.NotAfter == c.NotAfter && same(s.Coins, []exchange.Coin{exchange.NMC}) {
			return nil
		}
	}
	return refuse("TERMS_SLOT")
}
func checkContract(c Config, p profile, v booking.ContractV2, renter string) error {
	if v.Validate() != nil {
		return refuse("CONTRACT_NATIVE")
	}
	if v.AgentPubkey != c.AgentPubkey || v.RenterPubkey != renter || v.RenterName != "" || v.StationName != c.AgentName || v.NotBefore != c.NotBefore || v.NotAfter != c.NotAfter || v.TemplateID != p.template || v.TemplateSHA256 != c.TemplateSHA256 || v.ProfileID != c.ProfileID || v.ProfileVersion != c.ProfileVersion || v.ProfileSHA256 != c.ProfileSHA256 || v.PrivacySHA256 != privacy() || !same(v.Allowed, c.Allowed) || !same(v.Forbidden, c.Forbidden) || v.BudgetSat != c.BudgetSat || v.PaymentPolicy != "advance" {
		return refuse("CONTRACT_BINDING")
	}
	if v.Payment.Coin != "nmc" || v.Payment.Network != "regtest" || v.Payment.Genesis != su.RegtestGenesis || v.Payment.PriceUSDCents != p.price || v.Payment.MinConfirmations != p.depth || v.Payment.RateAsOf > time.Now().Unix() || time.Now().Unix()-v.Payment.RateAsOf > v.Payment.MaxRateAgeSeconds {
		return refuse("CONTRACT_PAYMENT")
	}
	return nil
}
func checkGrant(c Config, v booking.ContractV2, p rental.GrantPresentation) error {
	g := p.SignedGrant.Grant
	if g.Network != "regtest" || g.Genesis != su.RegtestGenesis || g.IssuerKey != c.IssuerPubkey || g.GranteeKey != v.RenterPubkey || g.GranteeName != v.RenterName || g.AgentName != c.AgentName || g.LandlordName != c.LandlordName || g.ContractSHA256 != v.Hash() || g.NotBefore != v.NotBefore || g.NotAfter != v.NotAfter || g.BudgetSat() != v.BudgetSat || !same(g.Scope, v.Allowed) || g.Consent.ConsentEvent.Tags[2][1] != v.BookingID || g.Consent.ConsentEvent.Tags[3][1] != privacy() {
		return refuse("GRANT_BINDING")
	}
	return nil
}
