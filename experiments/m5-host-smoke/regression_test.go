package smoke

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Regression: native envelopes include hold expiry and pay booking ID. Keep
// the complete native shape accepted while rejecting changed/missing binding.
func TestNativeEnvelopeRegression(t *testing.T) {
	_, c, _ := publicFixture(t)
	expiry := time.Now().Unix() + 600
	wire := map[string]any{"booking_id": c.BookingID, "contract_sha256": c.Hash(), "contract_base64": base64.StdEncoding.EncodeToString(c.Bytes()), "hold_expires_at": expiry}
	var contract contractEnvelope
	if e := Strict(encode(wire), &contract); e != nil || contract.Expires != expiry || contract.ID != c.BookingID {
		t.Fatal("native contract envelope regression", e)
	}
	good := paymentEnvelope{c.BookingID, expiry, c.Payment.Address, c.Payment.AmountAtoms, "nmc", 1}
	var parsed paymentEnvelope
	if e := Strict(encode(good), &parsed); e != nil {
		t.Fatal(e)
	}
	if e := checkPaymentEnvelope(parsed, c, expiry, 1, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	typ := reflect.TypeOf(good)
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			bad := good
			f := reflect.ValueOf(&bad).Elem().Field(i)
			if f.Kind() == reflect.String {
				f.SetString("wrong")
			} else {
				f.SetInt(f.Int() + 1)
			}
			wantCode(t, checkPaymentEnvelope(bad, c, expiry, 1, time.Now().Unix()), "PAYMENT_BOUND")
		})
	}
	wantCode(t, checkPaymentEnvelope(good, c, expiry, 1, expiry), "PAYMENT_BOUND")
	wire["unknown"] = true
	if Strict(encode(wire), &contract) == nil {
		t.Fatal("unknown field accepted")
	}
}

// Regression: native same-text/same-second replies have identical rumor IDs.
// Fresh wrapping is not a fresh response. The client suppresses replay, admits
// the next-second response and rejects foreign sender/recipient/stale input.
func TestNativeReplyIdentityAndAuthentication(t *testing.T) {
	renter, _ := nostr.GeneratePrivKey()
	agent, _ := nostr.GeneratePrivKey()
	other, _ := nostr.GeneratePrivKey()
	now := time.Now().Unix()
	c := &conversation{key: renter, agent: agent.PubKeyHex(), started: now - 1, seen: map[string]bool{}, inbox: make(chan received, 16), fault: make(chan error, 1)}
	first, r1, e := nostr.WrapDM(agent, renter.PubKeyHex(), exchange.Help, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	replay, r2, e := nostr.WrapDM(agent, renter.PubKeyHex(), exchange.Help, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	if r1.ID != r2.ID || first.ID == replay.ID {
		t.Fatal("collision witness no longer applies")
	}
	if e = c.accept(first); e != nil {
		t.Fatal(e)
	}
	if e = c.accept(replay); e != nil {
		t.Fatal(e)
	}
	if len(c.inbox) != 1 {
		t.Fatal("rewrapped replay counted twice")
	}
	next, _, _ := nostr.WrapDM(agent, renter.PubKeyHex(), exchange.Help, nil, now+1)
	if e = c.accept(next); e != nil || len(c.inbox) != 2 {
		t.Fatal("paced neighbor", e)
	}
	for _, spec := range []struct {
		sender    *nostr.PrivKey
		recipient string
		at        int64
	}{{other, renter.PubKeyHex(), now}, {agent, other.PubKeyHex(), now}, {agent, renter.PubKeyHex(), now - 2}, {agent, renter.PubKeyHex(), now + 60}} {
		bad, _, _ := nostr.WrapDM(spec.sender, spec.recipient, "not trusted", nil, spec.at)
		wantCode(t, c.accept(bad), "REPLY_AUTH")
	}
	if len(c.inbox) != 2 {
		t.Fatal("rejected reply had delivery effect")
	}
}

// Expiry requires both real time and >90-second idle; closure receipts have
// separate fresh/deadline plants. Unexpected closed payload text cannot hide
// behind positive operator claims; the exact revoke refusal is permitted.
func TestClosureAndQuietPlants(t *testing.T) {
	end := time.Now().Unix()
	now := time.Unix(end+1, 0)
	if e := checkClosure("expiry", end, end*1000, 91*time.Second, now); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		observed int64
		idle     time.Duration
		now      time.Time
	}{{end*1000 - 1, 91 * time.Second, now}, {end * 1000, 90 * time.Second, now}, {end * 1000, 91 * time.Second, time.Unix(end-1, 0)}} {
		wantCode(t, checkClosure("expiry", end, tc.observed, tc.idle, tc.now), "EXPIRY_TIME")
	}
	for _, tc := range []struct {
		scenario, text string
		valid          bool
	}{{"expiry", "", true}, {"expiry", "slot ended", true}, {"revoke", exchange.NotLive, true}, {"revoke", exchange.Help, true}, {"expiry", exchange.NotLive, false}, {"revoke", "model fixture reply", false}, {"expiry", "model fixture reply", false}} {
		c := &conversation{inbox: make(chan received, 1), fault: make(chan error, 1)}
		if tc.text != "" {
			c.inbox <- received{tc.text, end}
		}
		e := c.quiet(tc.scenario, end)
		if tc.valid {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			wantCode(t, e, "UNEXPECTED_CLOSED_REPLY")
		}
	}
}

// A native valid signed presentation is the positive control. Bad signature
// bytes fail the native parser; independently changed identity/contract/scope/
// time/budget/consent bindings fail the client's expected-contract check.
func TestPresentationSignatureAndBindingPlants(t *testing.T) {
	c, v, _ := publicFixture(t)
	issuer, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	c.IssuerPubkey = issuer.PubKeyHex()
	v.RenterPubkey = renter.PubKeyHex()
	rb := renter.Bytes()
	rk, _ := btcec.PrivKeyFromBytes(rb)
	clear(rb)
	defer rk.Zero()
	ib := issuer.Bytes()
	ik, _ := btcec.PrivKeyFromBytes(ib)
	clear(ib)
	defer ik.Zero()
	sign := func(h string) string {
		raw, e := hex.DecodeString(h)
		if e != nil {
			t.Fatal(e)
		}
		sig, e := schnorr.Sign(ik, raw)
		if e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(sig.Serialize())
	}
	consent := booking.ConsentV2(v, time.Now().Unix())
	if e := consent.Sign(rk); e != nil {
		t.Fatal(e)
	}
	var event rental.Event
	if e := json.Unmarshal(encode(consent), &event); e != nil {
		t.Fatal(e)
	}
	budget := v.BudgetSat
	g := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: c.AgentName, LandlordName: c.LandlordName, IssuerKey: c.IssuerPubkey, GranteeKey: v.RenterPubkey, ContractSHA256: v.Hash(), Scope: v.Allowed, NotBefore: v.NotBefore, NotAfter: v.NotAfter, Seal: rental.Point{TxID: strings.Repeat("2", 64), Vout: 0}, Budget: &budget, Consent: rental.GrantConsent{ContractSHA256: v.Hash(), ConsentEvent: event, LandlordSig: sign(v.Hash())}}
	h, e := g.SigningHash()
	if e != nil {
		t.Fatal(e)
	}
	p := rental.GrantPresentation{SignedGrant: rental.SignedGrant{Grant: g, Signature: sign(h)}, Issuance: rental.IssuanceProof{TxID: strings.Repeat("3", 64)}}
	parsed, e := rental.ParseGrantPresentation(encode(p))
	if e != nil {
		t.Fatal(e)
	}
	if e = checkGrant(c, v, parsed); e != nil {
		t.Fatal(e)
	}
	badSig := p
	badSig.SignedGrant.Signature = strings.Repeat("0", 128)
	if _, e = rental.ParseGrantPresentation(encode(badSig)); e == nil {
		t.Fatal("signature plant accepted")
	}
	for name, mutate := range map[string]func(*rental.Grant){
		"network": func(g *rental.Grant) { g.Network = "main" }, "genesis": func(g *rental.Grant) { g.Genesis = strings.Repeat("4", 64) }, "agent": func(g *rental.Grant) { g.AgentName = "id/other" }, "landlord": func(g *rental.Grant) { g.LandlordName = "id/other" }, "issuer": func(g *rental.Grant) { g.IssuerKey = renter.PubKeyHex() }, "renter": func(g *rental.Grant) { g.GranteeKey = issuer.PubKeyHex() },
		"renter_name": func(g *rental.Grant) { g.GranteeName = "id/other" }, "contract": func(g *rental.Grant) { g.ContractSHA256 = strings.Repeat("4", 64) }, "start": func(g *rental.Grant) { g.NotBefore++ }, "end": func(g *rental.Grant) { g.NotAfter++ }, "scope": func(g *rental.Grant) { g.Scope = []string{"pay"} }, "budget": func(g *rental.Grant) { n := budget + 1; g.Budget = &n }, "booking": func(g *rental.Grant) { g.Consent.ConsentEvent.Tags[2][1] = strings.Repeat("4", 64) }, "privacy": func(g *rental.Grant) { g.Consent.ConsentEvent.Tags[3][1] = strings.Repeat("4", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var bad rental.GrantPresentation
			_ = json.Unmarshal(encode(p), &bad)
			mutate(&bad.SignedGrant.Grant)
			wantCode(t, checkGrant(c, v, bad), "GRANT_BINDING")
		})
	}
}

// A native-looking end notice signed before not_after remains invalid even if
// delivered after expiry; an arbitrary prefix cannot stand in for the notice.
func TestPrematureExpiryNotice(t *testing.T) {
	now := time.Now().Unix()
	for _, m := range []received{{"slot ended", now - 1}, {"slot ended injected", now}} {
		c := &conversation{inbox: make(chan received, 1), fault: make(chan error, 1)}
		c.inbox <- m
		wantCode(t, c.quiet("expiry", now), "UNEXPECTED_CLOSED_REPLY")
	}
}

// Revoke probes can enter the native exchange non-grantee fallback and receive
// exact Help. Stale Help and a similar-looking arbitrary reply remain invalid.
func TestRevokeFallbackNotice(t *testing.T) {
	now := time.Now().Unix()
	for _, tc := range []struct {
		message received
		ok      bool
	}{{received{exchange.Help, now}, true}, {received{exchange.Help, now - 1}, false}, {received{exchange.Help + " extra", now}, false}} {
		c := &conversation{lastRequestAt: now, inbox: make(chan received, 1), fault: make(chan error, 1)}
		c.inbox <- tc.message
		e := c.quiet("revoke", now+100)
		if tc.ok {
			if e != nil || len(c.notices) != 1 || c.notices[0] != "revoke_exchange_help" {
				t.Fatal("native refusal control")
			}
		} else {
			wantCode(t, e, "UNEXPECTED_CLOSED_REPLY")
		}
	}
}

// Restart replay may produce native exchange refusals in either scenario.
// Only exact control text timestamped after the handoff is admitted; stale
// control text and a real model payload remain forbidden.
func TestRestartControlReplies(t *testing.T) {
	now := time.Now().Unix()
	for _, scenario := range []string{"expiry", "revoke"} {
		for _, tc := range []struct {
			m  received
			ok bool
		}{{received{exchange.Help, now}, true}, {received{exchange.NotLive, now}, true}, {received{exchange.Help, now - 1}, false}, {received{"model fixture reply", now}, false}} {
			c := &conversation{lastRequestAt: now, restartAt: now, inbox: make(chan received, 1), fault: make(chan error, 1)}
			c.inbox <- tc.m
			e := c.quiet(scenario, now)
			if tc.ok {
				if e != nil || len(c.notices) != 1 || c.notices[0] != "restart_exchange_refusal" {
					t.Fatal("restart control classification", e)
				}
			} else {
				wantCode(t, e, "UNEXPECTED_CLOSED_REPLY")
			}
		}
	}
}
