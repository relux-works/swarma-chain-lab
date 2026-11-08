package rental

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// Non-regtest policies fail before node access or reservations. The original
// regtest policy remains valid for offline issuance with the same signed data.
func TestRuntimeNetworkBoundary(t *testing.T) {
	p, s, cert, req, event := unitIssue(t)
	for _, network := range []string{"mainnet", "testnet", "regtest-wrong-genesis"} {
		q := p
		if network == "regtest-wrong-genesis" {
			q.Policy.Genesis = strings.Repeat("0", 64)
		} else {
			q.Policy.Network = network
		}
		r := CheckLegacy(context.Background(), nil, q.Policy, cert, q.Policy.StationName, testCertificate().GranteePubkey, 500)
		if r.Verdict != "refused" || r.Reason != "REGTEST_ONLY" || r.Calls != 0 {
			t.Fatal(r)
		}
		if _, e := MakeLegacyPlan(q, s, cert, req, event, 500); e == nil || e.Error() != "REGTEST_ONLY" {
			t.Fatal(e)
		}
		files, e := os.ReadDir(p.Policy.StateDir)
		if e != nil || len(files) != 0 {
			t.Fatal("network refusal wrote state", e)
		}
	}
	if _, e := MakeLegacyPlan(p, s, cert, req, event, 500); e != nil {
		t.Fatal("positive control", e)
	}
}

func signature(t *testing.T, hash string, key byte) string {
	t.Helper()
	k, _ := testKey(key)
	b, _ := hex.DecodeString(hash)
	s, e := schnorr.Sign(k, b)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(s.Serialize())
}
func signedEvent(t *testing.T, e Event, key byte) Event {
	t.Helper()
	_, e.Pubkey = testKey(key)
	e.ID = Hash(eventBytes([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content}))
	e.Sig = signature(t, e.ID, key)
	return e
}

// Correct signatures do not widen the agreed printable-ASCII event subset.
// Each rejected shape is re-signed, with a valid ASCII event beside it.
func TestEventASCIIProfile(t *testing.T) {
	valid := Event{CreatedAt: 100, Kind: 8182, Tags: [][]string{{"t", "value"}}, Content: "ASCII <>&"}
	for _, mode := range []string{"unicode-content", "control-content", "unicode-tag", "control-tag", "long-tag", "empty-tag", "wide-tag"} {
		t.Run(mode, func(t *testing.T) {
			e := valid
			switch mode {
			case "unicode-content":
				e.Content = "\u2028"
			case "control-content":
				e.Content = "\n"
			case "unicode-tag":
				e.Tags = [][]string{{"t", "\u2029"}}
			case "control-tag":
				e.Tags = [][]string{{"t", "\t"}}
			case "long-tag":
				e.Tags = [][]string{{"t", strings.Repeat("a", 513)}}
			case "empty-tag":
				e.Tags = [][]string{{}}
			case "wide-tag":
				e.Tags = [][]string{{"a", "b", "c", "d"}}
			}
			if eventValid(signedEvent(t, e, 4), 500) {
				t.Fatal("out-of-profile event accepted")
			}
			if !eventValid(signedEvent(t, valid, 4), 500) {
				t.Fatal("positive control")
			}
		})
	}
}
func packageFixture(t *testing.T, c Certificate, address string, payment Point, height int64, block, policy string, bookingIDs ...string) (Certificate, IssuanceRequest, Event) {
	t.Helper()
	booking := strings.Repeat("c", 64)
	if len(bookingIDs) == 1 {
		booking = bookingIDs[0]
	}
	_, provider := testKey(4)
	forbidden := []string{}
	for _, s := range []string{"deliver", "pay", "publish", "repository.push", "secret.release"} {
		found := false
		for _, a := range c.Scope {
			found = found || s == a
		}
		if !found {
			forbidden = append(forbidden, s)
		}
	}
	contract := Contract{Version: 1, BookingID: booking, RenterPubkey: c.GranteePubkey, AgentPubkey: c.AgentPubkey, StationName: c.StationName, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Allowed: c.Scope, Forbidden: forbidden, BudgetSat: c.BudgetSat, TemplateID: "lab-template", TemplateSHA256: strings.Repeat("1", 64), ProfileID: "lab-profile", ProfileVersion: "1", ProfileSHA256: strings.Repeat("2", 64), PriceUSDCents: 100, USDMicrosPerNMC: 100000000, RateAsOf: 100, PriceNMCSat: 1000000, PaymentPolicy: policy, PaymentAddress: address, PrivacySHA256: strings.Repeat("3", 64)}
	c.ContractSHA256 = Hash(eventBytes(contract))
	consent := signedEvent(t, Event{CreatedAt: 200, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", c.ContractSHA256}, {"booking", booking}, {"privacy", contract.PrivacySHA256}}}, 2)
	pack := Package{1, contract, consent, provider, signature(t, c.ContractSHA256, 4), 100, contract.PrivacySHA256, 100, 900}
	event := signedEvent(t, Event{CreatedAt: 300, Kind: 8182, Tags: [][]string{{"t", "swarma-rental-package-v1"}, {"contract", c.ContractSHA256}, {"booking", booking}, {"e", consent.ID}}, Content: string(eventBytes(pack))}, 4)
	r := IssuanceRequest{1, booking, c.StationName, c.AgentPubkey, c.GranteePubkey, c.ContractSHA256, c.Scope, c.BudgetSat, c.NotBefore, c.NotAfter, policy, payment.TxID, payment.Vout, height, block, strings.Repeat("d", 64), event.ID}
	return c, r, event
}
func unitPolicy(t *testing.T) IssuerPolicy {
	t.Helper()
	c := testCertificate()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	_, provider := testKey(4)
	return IssuerPolicy{Policy{Network: "regtest", Genesis: su.RegtestGenesis, IssuerPubkey: c.IssuerPubkey, AgentPubkey: c.AgentPubkey, StationName: c.StationName, StationScript: "76a914" + strings.Repeat("11", 20) + "88ac", StateDir: root}, provider}
}
func unitIssue(t *testing.T) (IssuerPolicy, PlanSpec, []byte, []byte, []byte) {
	p := unitPolicy(t)
	c := testCertificate()
	c, r, event := packageFixture(t, c, "mfixtureAddress000000000000000000000", Point{strings.Repeat("4", 64), 0}, 1, strings.Repeat("5", 64), "advance")
	script, _ := hex.DecodeString(p.Policy.StationScript)
	s := PlanSpec{Kind: "issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: strings.Repeat("6", 64)}, ValueSat: 1000000, Script: hex.EncodeToString(su.NameUpdateScript(c.StationName, "{}", script)), Role: "name"}, {Point: su.Point{TxID: strings.Repeat("7", 64)}, ValueSat: 2000000, Script: p.Policy.StationScript, Role: "funding"}}, ChangeScript: p.Policy.StationScript, Pool: PoolOutput{c.Seal, 1000000, p.Policy.StationScript, 1, strings.Repeat("8", 64)}}
	rb, _ := json.Marshal(r)
	return p, s, signTest(t, c, 1), rb, eventBytes(event)
}

// Request, provider publication, countersignature and renter consent must bind
// the same contract. An independently signed package is the positive control;
// changing a request does not grant scope or budget and writes no pool record.
func TestIssuancePackageBoundary(t *testing.T) {
	p, _, _, request, event := unitIssue(t)
	if _, _, e := VerifyIssuancePackage(p, request, event, 500); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		edit   func(*IssuanceRequest)
		reason string
	}{
		{"wrong-contract", func(r *IssuanceRequest) { r.ContractSHA256 = strings.Repeat("9", 64) }, "PROVIDER_SIGNATURE"},
		{"wrong-scope", func(r *IssuanceRequest) { r.Scope = []string{"pay"} }, "PACKAGE_REQUEST_BINDING"},
		{"wrong-budget", func(r *IssuanceRequest) { r.BudgetSat++ }, "PACKAGE_REQUEST_BINDING"},
		{"wrong-event", func(r *IssuanceRequest) { r.PackageEventID = strings.Repeat("9", 64) }, "PACKAGE_EVENT"},
		{"height-block-mismatch", func(r *IssuanceRequest) { r.PaymentHeight = 0 }, "PAYMENT_OBSERVATION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r IssuanceRequest
			_ = json.Unmarshal(request, &r)
			tc.edit(&r)
			b, _ := json.Marshal(r)
			if _, _, e := VerifyIssuancePackage(p, b, event, 500); e == nil || e.Error() != tc.reason {
				t.Fatalf("%s: %v", tc.reason, e)
			}
			if _, _, e := VerifyIssuancePackage(p, request, event, 500); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// An issue plan conserves atoms, references rather than spends the pool seal,
// and durably burns the reservation. Reopening cannot reuse it. Invalid pool
// claims produce no reservation, with the unmodified plan accepted afterward.
func TestPoolReservationAndRefusals(t *testing.T) {
	for _, mode := range []string{"foreign-script", "unconfirmed", "spends-seal", "wrong-change", "valid"} {
		t.Run(mode, func(t *testing.T) {
			p, s, cert, req, event := unitIssue(t)
			original := s
			want := ""
			switch mode {
			case "foreign-script":
				s.Pool.Script = "76a914" + strings.Repeat("22", 20) + "88ac"
				want = "POOL_STATION_BINDING"
			case "unconfirmed":
				s.Pool.Height = 0
				s.Pool.Block = ""
				want = "POOL_UNCONFIRMED"
			case "spends-seal":
				s.Inputs = append([]su.PlanInput{}, s.Inputs...)
				s.Inputs[1].Point = su.Point{TxID: s.Pool.Point.TxID, Vout: s.Pool.Point.Vout}
				want = "ISSUE_SPENDS_SEAL"
			case "wrong-change":
				s.ChangeScript = "76a914" + strings.Repeat("22", 20) + "88ac"
				want = "CHANGE_PIN"
			}
			if want != "" {
				if _, e := MakeLegacyPlan(p, s, cert, req, event, 500); e == nil || e.Error() != want {
					t.Fatalf("%s: %v", want, e)
				}
				files, _ := filepath.Glob(filepath.Join(p.Policy.StateDir, "pool-*"))
				if len(files) != 0 {
					t.Fatal("refusal reserved pool")
				}
			}
			plan, e := MakeLegacyPlan(p, original, cert, req, event, 500)
			if e != nil {
				t.Fatal(e)
			}
			var in, out int64
			for _, v := range plan.Inputs {
				in += v.ValueSat
				if v.Point.TxID == s.Pool.Point.TxID && v.Point.Vout == s.Pool.Point.Vout {
					t.Fatal("issue spends seal")
				}
			}
			for _, v := range plan.Outputs {
				out += v.ValueSat
			}
			if in-out != plan.FeeSat || plan.FeeSat != int64(plan.MaxSignedVBytes)*200 {
				t.Fatal("fee conservation")
			}
			if _, e := MakeLegacyPlan(p, original, cert, req, event, 500); e == nil || e.Error() != "POOL_ALREADY_RESERVED" {
				t.Fatal("pool reuse", e)
			}
		})
	}
}

// Valid provider publication cannot substitute for renter consent or provider
// countersignature. Re-signing the wrapper isolates each inner signature guard.
func TestPackageSignatureLayers(t *testing.T) {
	p, _, _, req, event := unitIssue(t)
	for _, mode := range []string{"publication-signature", "provider-signature", "renter-signature", "hold-binding", "privacy-binding"} {
		t.Run(mode, func(t *testing.T) {
			var r IssuanceRequest
			var pub Event
			var pack Package
			_ = json.Unmarshal(req, &r)
			_ = json.Unmarshal(event, &pub)
			_ = json.Unmarshal([]byte(pub.Content), &pack)
			want := ""
			switch mode {
			case "publication-signature":
				pub.Sig = strings.Repeat("0", 128)
				want = "PACKAGE_EVENT"
			case "provider-signature":
				pack.ProviderSignature = strings.Repeat("0", 128)
				want = "PROVIDER_SIGNATURE"
			case "renter-signature":
				pack.Consent.Sig = strings.Repeat("0", 128)
				want = "RENTER_CONSENT"
			case "hold-binding":
				pack.HoldExpiresAt = 0
				want = "HOLD_BINDING"
			case "privacy-binding":
				pack.PrivacySHA256 = strings.Repeat("f", 64)
				want = "PACKAGE_PRIVACY_BINDING"
			}
			if mode != "publication-signature" {
				pub.Content = string(eventBytes(pack))
				pub = signedEvent(t, pub, 4)
				r.PackageEventID = pub.ID
			}
			request, _ := json.Marshal(r)
			if _, _, e := VerifyIssuancePackage(p, request, eventBytes(pub), 500); e == nil || e.Error() != want {
				t.Fatalf("want%s got%v", want, e)
			}
			if _, _, e := VerifyIssuancePackage(p, req, event, 500); e != nil {
				t.Fatal("positive", e)
			}
		})
	}
}

// Height-zero payment claims cannot burn either reservation or create a lock;
// both payment policies retain a valid positive-height neighbor afterward.
func TestPlannerPaymentConfirmation(t *testing.T) {
	for _, policy := range []string{"advance", "start_now"} {
		t.Run(policy, func(t *testing.T) {
			p, s, _, _, _ := unitIssue(t)
			c, r, event := packageFixture(t, testCertificate(), "mfixtureAddress000000000000000000000", Point{strings.Repeat("4", 64), 0}, 0, "", policy)
			cert := signTest(t, c, 1)
			req, _ := json.Marshal(r)
			if _, e := MakeLegacyPlan(p, s, cert, req, eventBytes(event), 500); e == nil || e.Error() != "payment_unconfirmed" {
				t.Fatal(e)
			}
			files, e := os.ReadDir(p.Policy.StateDir)
			if e != nil || len(files) != 0 {
				t.Fatal("unconfirmed payment wrote state", e)
			}
			r.PaymentHeight = 1
			r.PaymentBlockHash = strings.Repeat("5", 64)
			req, _ = json.Marshal(r)
			if _, e := MakeLegacyPlan(p, s, cert, req, eventBytes(event), 500); e != nil {
				t.Fatal("confirmed neighbor", e)
			}
		})
	}
}

// A previously reserved booking cannot switch to a fresh seal on retry.
func TestBookingReservation(t *testing.T) {
	p, s, cert, req, event := unitIssue(t)
	if _, e := MakeLegacyPlan(p, s, cert, req, event, 500); e != nil {
		t.Fatal(e)
	}
	var env Envelope
	_ = json.Unmarshal(cert, &env)
	env.Certificate.Seal.TxID = strings.Repeat("a", 64)
	s.Pool.Point = env.Certificate.Seal
	cert = signTest(t, env.Certificate, 1)
	if _, e := MakeLegacyPlan(p, s, cert, req, event, 500); e == nil || e.Error() != "BOOKING_ALREADY_RESERVED" {
		t.Fatal(e)
	}
}

// A different, otherwise valid booking and certificate cannot claim a seal
// already burned by the first booking. The booking-id guard is not sufficient.
func TestPoolDifferentBooking(t *testing.T) {
	p, s, cert, req, event := unitIssue(t)
	if _, e := MakeLegacyPlan(p, s, cert, req, event, 500); e != nil {
		t.Fatal(e)
	}
	var env Envelope
	_ = json.Unmarshal(cert, &env)
	c, r, pub := packageFixture(t, env.Certificate, "mfixtureAddress000000000000000000000", Point{strings.Repeat("4", 64), 0}, 1, strings.Repeat("5", 64), "advance", strings.Repeat("f", 64))
	raw, _ := json.Marshal(r)
	if _, e := MakeLegacyPlan(p, s, signTest(t, c, 1), raw, eventBytes(pub), 500); e == nil || e.Error() != "POOL_ALREADY_RESERVED" {
		t.Fatal("different booking reused seal", e)
	}
}

// A process exits after reservation but before emitting a plan. Reopening
// refuses retry; this covers process interruption, not a storage power failure.
func TestPoolCrashAfterReservation(t *testing.T) {
	p, s, cert, req, event := unitIssue(t)
	if os.Getenv("M1_CRASH_CHILD") == "1" {
		p.Policy.StateDir = os.Getenv("M1_CRASH_ROOT")
		if _, e := MakeLegacyPlan(p, s, cert, req, event, 500); e != nil {
			os.Exit(84)
		}
		os.Exit(85)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPoolCrashAfterReservation$")
	cmd.Env = append(os.Environ(), "M1_CRASH_CHILD=1", "M1_CRASH_ROOT="+p.Policy.StateDir)
	out, e := cmd.Output()
	exit, ok := e.(*exec.ExitError)
	if !ok || exit.ExitCode() != 85 || len(out) != 0 {
		t.Fatalf("crash control: %v output%d", e, len(out))
	}
	t.Logf("reservation child PID %d exited 85 before output", cmd.ProcessState.Pid())
	pool, _ := filepath.Glob(filepath.Join(p.Policy.StateDir, "pool-*.json"))
	booking, _ := filepath.Glob(filepath.Join(p.Policy.StateDir, "booking-*.json"))
	if len(pool) != 1 || len(booking) != 1 {
		t.Fatal("missing durable records")
	}
	if _, e := MakeLegacyPlan(p, s, cert, req, event, 500); e == nil || e.Error() != "POOL_ALREADY_RESERVED" {
		t.Fatal(e)
	}
}
