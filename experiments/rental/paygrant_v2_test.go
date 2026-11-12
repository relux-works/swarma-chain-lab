package rental

// Owner S4. Issuance tests for the terms-v2 pay-grant helper: terms bytes
// equal the golden fixture; signer call order; digest recomputation by a
// conforming signer; refusal on a wrong key or an invalid signature with no
// partial result; a ParseSignedGrant round trip and the IssuanceCommitment
// value; and the offline file-exchange transport.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// px1SignLog records signer calls across both signers, in call order.
type px1SignLog struct {
	mu    sync.Mutex
	calls []string
	reqs  []PayGrantSigningRequest
}

func (l *px1SignLog) add(who string, req PayGrantSigningRequest) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, who+":"+req.Purpose)
	l.reqs = append(l.reqs, req)
}

// px1MemSigner is a conforming in-memory DigestSigner over a public test
// scalar. It recomputes the digest before signing, like the real signer must.
// The hooks inject one fault each.
type px1MemSigner struct {
	who      string
	key      byte
	keyOver  string // XOnlyKey override
	log      *px1SignLog
	fail     map[string]error                                 // purpose -> Sign error
	forge    map[string]func(*PayGrantSignature)              // purpose -> response rewrite
	scribble bool                                             // rewrite request bytes after signing
	check    func(PayGrantSigningRequest) (PayTermsV2, error) // conforming check (default Verify...)
}

func (s *px1MemSigner) XOnlyKey() string {
	if s.keyOver != "" {
		return s.keyOver
	}
	_, pub := testKey(s.key)
	return pub
}

func (s *px1MemSigner) Sign(ctx context.Context, req PayGrantSigningRequest) (PayGrantSignature, error) {
	if s.log != nil {
		s.log.add(s.who, req)
	}
	if e := s.fail[req.Purpose]; e != nil {
		return PayGrantSignature{}, e
	}
	check := s.check
	if check == nil {
		check = VerifyPayGrantSigningRequest
	}
	if _, e := check(req); e != nil {
		return PayGrantSignature{}, e
	}
	priv, _ := testKey(s.key)
	sig, e := schnorr.Sign(priv, mustDecodeKey(req.Digest))
	if e != nil {
		return PayGrantSignature{}, e
	}
	out := PayGrantSignature{Version: 1, Purpose: req.Purpose, SignerKey: req.SignerKey, Digest: req.Digest, Signature: hex.EncodeToString(sig.Serialize())}
	if f := s.forge[req.Purpose]; f != nil {
		f(&out)
	}
	if s.scribble {
		for i := range req.Terms {
			req.Terms[i] = 'x'
		}
		for i := range req.Payload {
			req.Payload[i] = 'x'
		}
	}
	return out, nil
}

func px1Signers(log *px1SignLog) (*px1MemSigner, *px1MemSigner) {
	return &px1MemSigner{who: "grantee", key: 2, log: log}, &px1MemSigner{who: "landlord", key: 1, log: log}
}

const px1NotBefore = int64(1794000000)

func px1PayInput() PayGrantV2Input {
	_, issuer := testKey(1)
	_, grantee := testKey(2)
	return PayGrantV2Input{
		Network: "main", Genesis: su.MainGenesis,
		AgentName: "id/ivanopcode-cedar", LandlordName: "id/ivanopcode",
		IssuerKey: issuer, GranteeKey: grantee,
		NotBefore: px1NotBefore, NotAfter: px1NotBefore + 30*86400,
		Seal: Point{TxID: strings.Repeat("b", 64), Vout: 1}, BudgetSat: 500000,
		Terms: px1PayTermsAllow(), ConsentCreatedAt: px1NotBefore + 60,
		PrivacyNoticeSHA256: Hash([]byte("g2-privacy-notice")),
	}
}

func px1Golden(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/px1/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// px1MainAddress encodes a Namecoin main address for a hash160 and version.
func px1MainAddress(t *testing.T, seed byte, script bool) string {
	t.Helper()
	params := chaincfg.MainNetParams
	params.PubKeyHashAddrID, params.ScriptHashAddrID = 52, 13
	h := bytes.Repeat([]byte{seed}, 20)
	var a btcutil.Address
	var e error
	if script {
		a, e = btcutil.NewAddressScriptHashFromHash(h, &params)
	} else {
		a, e = btcutil.NewAddressPubKeyHash(h, &params)
	}
	if e != nil {
		t.Fatal(e)
	}
	return a.EncodeAddress()
}

func px1RegtestAddress(t *testing.T, seed byte) string {
	t.Helper()
	a, e := btcutil.NewAddressPubKeyHash(bytes.Repeat([]byte{seed}, 20), &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	return a.EncodeAddress()
}

func px1Code(e error) string {
	if e == nil {
		return "<nil>"
	}
	return e.Error()
}

// Claim: EncodePayTermsV2 yields exactly the frozen golden bytes (and hash) of
// both terms modes, and the fixture executor key is testKey(9), as the shared
// fixture table states.
func TestPayGrantV2TermsGolden(t *testing.T) {
	if _, pub := testKey(9); pub != px1ExecutorKey {
		t.Fatal("fixture executor key is not testKey(9)")
	}
	for _, c := range []struct {
		file, sha string
		terms     PayTermsV2
	}{{"terms-v2-allow.json", px1TermsAllowSHA256, px1PayTermsAllow()}, {"terms-v2-any.json", px1TermsAnySHA256, px1PayTermsAny()}} {
		got, e := EncodePayTermsV2(c.terms)
		if e != nil || !bytes.Equal(got, px1Golden(t, c.file)) || Hash(got) != c.sha {
			t.Fatalf("%s: %v\n got %s", c.file, e, got)
		}
	}
}

// Claim: EncodePayTermsV2 refuses every rows 3-10 violation with the frozen
// code of the first failing row and returns no bytes; each refusal sits next
// to a boundary-valid neighbour that encodes. Row 6 (executor pin) and the
// grant-budget bound are deliberately not applied here.
func TestPayGrantV2TermsRefusals(t *testing.T) {
	a, b := px1PayTermsAllow().Recipients[0], px1PayTermsAllow().Recipients[1]
	many := make([]string, 33)
	for i := range many {
		many[i] = px1MainAddress(t, byte(i+1), false)
	}
	sort.Strings(many)
	p2sh, reg7, reg9 := px1MainAddress(t, 9, true), px1RegtestAddress(t, 7), px1RegtestAddress(t, 9)
	cases := []struct {
		name, want string
		edit       func(*PayTermsV2)
	}{
		{"valid-allow", "<nil>", func(*PayTermsV2) {}},
		{"version-1", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Version = 1 }},
		{"version-3", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Version = 3 }},
		{"service", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Service = "wallet.btc" }},
		{"day-basis", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.DayBasis = "rolling-24h" }},
		{"executor-off-curve", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.ExecutorKey = strings.Repeat("f", 64) }},
		{"executor-uppercase", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.ExecutorKey = strings.ToUpper(px1ExecutorKey) }},
		{"executor-other-valid", "<nil>", func(t *PayTermsV2) { _, t.ExecutorKey = testKey(4) }},
		{"network-unpinned", "TERMS_NETWORK", func(t *PayTermsV2) { t.Network = "regtest" }},
		{"genesis-unpinned", "TERMS_NETWORK", func(t *PayTermsV2) { t.Genesis = su.RegtestGenesis }},
		{"regtest-pair-valid", "<nil>", func(t *PayTermsV2) {
			t.Network, t.Genesis, t.Recipients = "regtest", su.RegtestGenesis, []string{reg7}
		}},
		{"mode-unknown", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.RecipientMode = "free" }},
		{"recipients-null", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Recipients = nil }},
		{"allow-empty", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Recipients = []string{} }},
		{"allow-33", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Recipients = many }},
		{"allow-32-valid", "<nil>", func(t *PayTermsV2) { t.Recipients = many[:32] }},
		{"allow-unsorted", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Recipients = []string{b, a} }},
		{"any-nonempty", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.RecipientMode = "any"; t.Recipients = []string{a} }},
		{"any-null", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.RecipientMode = "any"; t.Recipients = nil }},
		{"any-empty-valid", "<nil>", func(t *PayTermsV2) { t.RecipientMode = "any"; t.Recipients = []string{} }},
		// T15-shaped address rows, mirrored from the executor's row 8.
		{"p2sh", "ADDRESS_P2PKH_ONLY", func(t *PayTermsV2) { t.Recipients = []string{p2sh} }},
		{"bech32", "ADDRESS_MAIN", func(t *PayTermsV2) { t.Recipients = []string{"nc1qw508d6qejxtdg4y5r3zarvary0c5xw7kq3dtz0"} }},
		{"testnet", "ADDRESS_MAIN", func(t *PayTermsV2) { t.Recipients = []string{reg9} }},
		{"bitcoin-main", "ADDRESS_MAIN", func(t *PayTermsV2) { t.Recipients = []string{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"} }},
		{"mixed-case", "ADDRESS_MAIN", func(t *PayTermsV2) { t.Recipients = []string{"N35GKXNzPPRWWJipjt3svASBzetRtSNCw6"} }},
		{"single-valid", "<nil>", func(t *PayTermsV2) { t.Recipients = []string{a} }},
		{"duplicate", "CONTRACT_RECIPIENTS", func(t *PayTermsV2) { t.Recipients = []string{a, a} }},
		{"transfer-zero", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.TransferCap = 0 }},
		{"transfer-over-day", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.TransferCap = t.DayCap + 1 }},
		{"day-over-spend", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.DayCap = t.SpendCap + 1 }},
		{"caps-equal-valid", "<nil>", func(t *PayTermsV2) { t.TransferCap, t.DayCap = t.SpendCap, t.SpendCap }},
		{"spend-over-maxmoney", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.SpendCap = MaxMoney + 1 }},
		{"spend-maxmoney-valid", "<nil>", func(t *PayTermsV2) { t.SpendCap = MaxMoney }},
		{"count-zero", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.DayCountCap = 0 }},
		{"count-1001", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.DayCountCap = 1001 }},
		{"count-1000-valid", "<nil>", func(t *PayTermsV2) { t.DayCountCap = 1000 }},
		{"fee-zero", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.FeeCap = 0 }},
		{"fee-over-max", "CONTRACT_BUDGET", func(t *PayTermsV2) { t.FeeCap = 1000001 }},
		{"fee-max-valid", "<nil>", func(t *PayTermsV2) { t.FeeCap = 1000000 }},
		// First failing row wins: row 4 before row 10.
		{"order-schema-before-budget", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Service = ""; t.TransferCap = 0 }},
		// Row 7 before row 8: an unsorted list of bad addresses is a schema error.
		{"order-sort-before-address", "CONTRACT_SCHEMA", func(t *PayTermsV2) { t.Recipients = []string{"z", "a"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			terms := px1PayTermsAllow()
			c.edit(&terms)
			got, e := EncodePayTermsV2(terms)
			if px1Code(e) != c.want {
				t.Fatalf("want %s got %s", c.want, px1Code(e))
			}
			if (e != nil) != (got == nil) {
				t.Fatal("refusal returned bytes, or success returned none")
			}
			if e == nil {
				want, _ := json.Marshal(terms)
				if !bytes.Equal(got, want) {
					t.Fatal("encoded bytes are not the canonical marshal")
				}
			}
		})
	}
}

// Claim: the booking tag is SHA256 over the frozen domain and the terms bytes:
// it differs from the plain terms hash and changes with any terms byte.
func TestPayGrantV2BookingRef(t *testing.T) {
	terms := px1Golden(t, "terms-v2-allow.json")
	want := Hash(append([]byte("swarma-g2-pay-booking-v1"), terms...))
	if PayGrantBookingRef(terms) != want || want == Hash(terms) {
		t.Fatal("booking ref is not domain separated")
	}
	if PayGrantBookingRef(px1Golden(t, "terms-v2-any.json")) == want {
		t.Fatal("booking ref ignores the terms bytes")
	}
}

// Claim: ValidatePayGrantV2Input accepts the smoke input (multi-day window,
// budget exactly at spend_cap, consent at both window edges) and refuses each
// listed violation with its code; it never calls a signer (it takes none).
func TestPayGrantV2ValidateInput(t *testing.T) {
	_, other := testKey(4)
	cases := []struct {
		name, want string
		edit       func(*PayGrantV2Input)
	}{
		{"valid", "<nil>", func(*PayGrantV2Input) {}},
		{"terms-refused", "CONTRACT_BUDGET", func(in *PayGrantV2Input) { in.Terms.TransferCap = 0 }},
		{"network-not-terms", "PAY_GRANT_NETWORK", func(in *PayGrantV2Input) { in.Network, in.Genesis = "regtest", su.RegtestGenesis }},
		{"genesis-unpinned", "PAY_GRANT_NETWORK", func(in *PayGrantV2Input) { in.Genesis = strings.Repeat("0", 64) }},
		{"agent-name", "GRANT_NAME", func(in *PayGrantV2Input) { in.AgentName = "d/cedar" }},
		{"landlord-name", "GRANT_NAME", func(in *PayGrantV2Input) { in.LandlordName = "id/Ivan" }},
		{"same-names", "GRANT_NAME", func(in *PayGrantV2Input) { in.LandlordName = in.AgentName }},
		{"issuer-key", "GRANT_KEY", func(in *PayGrantV2Input) { in.IssuerKey = strings.Repeat("f", 64) }},
		{"grantee-key", "GRANT_KEY", func(in *PayGrantV2Input) { in.GranteeKey = "" }},
		{"grantee-is-issuer", "PAY_GRANT_KEY_ROLES", func(in *PayGrantV2Input) { in.GranteeKey = in.IssuerKey }},
		{"grantee-is-executor", "PAY_GRANT_KEY_ROLES", func(in *PayGrantV2Input) { in.GranteeKey = px1ExecutorKey }},
		{"issuer-is-executor", "PAY_GRANT_KEY_ROLES", func(in *PayGrantV2Input) { in.IssuerKey = px1ExecutorKey }},
		{"other-grantee-valid", "<nil>", func(in *PayGrantV2Input) { in.GranteeKey = other }},
		{"seal", "GRANT_HASH", func(in *PayGrantV2Input) { in.Seal.TxID = "b" }},
		{"window-empty", "GRANT_TIME", func(in *PayGrantV2Input) { in.NotAfter = in.NotBefore }},
		{"window-negative", "GRANT_TIME", func(in *PayGrantV2Input) { in.NotBefore = -1 }},
		{"window-beyond-9999", "GRANT_TIME", func(in *PayGrantV2Input) { in.NotAfter = 253402300800 }},
		{"window-year-valid", "<nil>", func(in *PayGrantV2Input) { in.NotAfter = in.NotBefore + 365*86400 }},
		{"budget-over-maxmoney", "GRANT_BUDGET", func(in *PayGrantV2Input) { in.BudgetSat = MaxMoney + 1 }},
		{"budget-absent", "CONTRACT_BUDGET", func(in *PayGrantV2Input) { in.BudgetSat = 0 }},
		{"budget-below-spend", "CONTRACT_BUDGET", func(in *PayGrantV2Input) { in.BudgetSat = in.Terms.SpendCap - 1 }},
		{"budget-equal-valid", "<nil>", func(in *PayGrantV2Input) { in.BudgetSat = in.Terms.SpendCap }},
		{"consent-before-window", "PAY_GRANT_CONSENT_TIME", func(in *PayGrantV2Input) { in.ConsentCreatedAt = in.NotBefore - 1 }},
		{"consent-at-end", "PAY_GRANT_CONSENT_TIME", func(in *PayGrantV2Input) { in.ConsentCreatedAt = in.NotAfter }},
		{"consent-zero", "PAY_GRANT_CONSENT_TIME", func(in *PayGrantV2Input) { in.NotBefore, in.ConsentCreatedAt = 0, 0 }},
		{"consent-start-valid", "<nil>", func(in *PayGrantV2Input) { in.ConsentCreatedAt = in.NotBefore }},
		{"consent-last-second-valid", "<nil>", func(in *PayGrantV2Input) { in.ConsentCreatedAt = in.NotAfter - 1 }},
		{"privacy", "PAY_GRANT_PRIVACY", func(in *PayGrantV2Input) { in.PrivacyNoticeSHA256 = strings.ToUpper(in.PrivacyNoticeSHA256) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := px1PayInput()
			c.edit(&in)
			if got := px1Code(ValidatePayGrantV2Input(in)); got != c.want {
				t.Fatalf("want %s got %s", c.want, got)
			}
		})
	}
}

// Claim: a successful issuance calls the signers exactly three times in the
// frozen order (grantee consent, landlord contract countersign, landlord
// grant), each request names the expected key and purpose and carries the
// canonical terms bytes equal to the golden fixture.
func TestPayGrantV2SignerOrder(t *testing.T) {
	log := &px1SignLog{}
	g, l := px1Signers(log)
	r, e := IssuePayGrantV2(context.Background(), px1PayInput(), g, l)
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"grantee:" + SignPurposeConsentEvent, "landlord:" + SignPurposeContract, "landlord:" + SignPurposeGrant}
	if !reflect.DeepEqual(log.calls, want) {
		t.Fatalf("signer order %v", log.calls)
	}
	golden := px1Golden(t, "terms-v2-allow.json")
	keys := []string{g.XOnlyKey(), l.XOnlyKey(), l.XOnlyKey()}
	for i, req := range log.reqs {
		if req.Version != 1 || req.SignerKey != keys[i] || !bytes.Equal(req.Terms, golden) {
			t.Fatalf("request %d binding", i)
		}
	}
	if !bytes.Equal(r.Terms, golden) || r.ContractSHA256 != px1TermsAllowSHA256 {
		t.Fatal("result terms are not the golden bytes")
	}
	if log.reqs[1].Digest != px1TermsAllowSHA256 {
		t.Fatal("countersign digest is not contract_sha256")
	}
}

// Claim: the result is one ParseSignedGrant-valid v3 grant whose id, contract,
// consent binding, scope, budget, window and seal equal the input; the
// IssuanceCommitment equals both the library value and an independent
// recomputation; the presentation round-trips; and the grant is a pay grant
// only (no deliver scope, no grantee name).
func TestPayGrantV2RoundTrip(t *testing.T) {
	in := px1PayInput()
	g, l := px1Signers(nil)
	r, e := IssuePayGrantV2(context.Background(), in, g, l)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := ParseSignedGrant(r.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	gr := signed.Grant
	if r.GrantID != signed.ID() || r.GrantID != Hash(r.SignedGrant) || r.ContractSHA256 != Hash(r.Terms) || gr.ContractSHA256 != r.ContractSHA256 {
		t.Fatal("ids or contract hash")
	}
	if !reflect.DeepEqual(gr.Scope, []string{"pay"}) || !reflect.DeepEqual(PayGrantScope, []string{"pay"}) || gr.BudgetSat() != in.BudgetSat || gr.Budget == nil {
		t.Fatal("scope or budget")
	}
	if gr.Version != 3 || gr.Network != in.Network || gr.Genesis != in.Genesis || gr.AgentName != in.AgentName || gr.LandlordName != in.LandlordName || gr.IssuerKey != in.IssuerKey || gr.GranteeKey != in.GranteeKey || gr.GranteeName != "" || gr.NotBefore != in.NotBefore || gr.NotAfter != in.NotAfter || gr.Seal != in.Seal {
		t.Fatalf("grant fields %+v", gr)
	}
	ev := gr.Consent.ConsentEvent
	wantTags := [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", r.ContractSHA256}, {"booking", PayGrantBookingRef(r.Terms)}, {"privacy", in.PrivacyNoticeSHA256}}
	if ev.Pubkey != in.GranteeKey || ev.Kind != 8181 || ev.CreatedAt != in.ConsentCreatedAt || ev.Content != "" || !reflect.DeepEqual(ev.Tags, wantTags) {
		t.Fatalf("consent event %+v", ev)
	}
	if !VerifySignature(in.IssuerKey, r.ContractSHA256, gr.Consent.LandlordSig) || !VerifySignature(in.GranteeKey, ev.ID, ev.Sig) {
		t.Fatal("consent signatures")
	}
	lib, e := IssuanceCommitment(signed)
	if e != nil || lib != r.IssuanceCommitment {
		t.Fatal("commitment differs from IssuanceCommitment")
	}
	data := []byte("swarma-issue-v1")
	for _, v := range []string{gr.ContractSHA256, ev.ID, ev.Sig, gr.Consent.LandlordSig, r.GrantID} {
		data = append(data, mustDecodeKey(v)...)
	}
	if Hash(data) != r.IssuanceCommitment {
		t.Fatal("commitment differs from the independent recomputation")
	}
	p, e := PresentIssuedGrant(r.SignedGrant, strings.Repeat("c", 64))
	if e != nil {
		t.Fatal(e)
	}
	if pr, e := ParseGrantPresentation(p); e != nil || pr.SignedGrant.ID() != r.GrantID {
		t.Fatal("presentation round trip", e)
	}
	// The result serializes with the frozen member names.
	b, _ := json.Marshal(r)
	for _, k := range []string{`"grant_id":`, `"contract_sha256":`, `"terms":{`, `"signed_grant":{`, `"issuance_commitment":`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Fatal("result JSON lacks", k)
		}
	}
	// The any-mode fixture issues too, with its own (lower) budget.
	in.Terms, in.BudgetSat = px1PayTermsAny(), 100000
	if r2, e := IssuePayGrantV2(context.Background(), in, g, l); e != nil || r2.ContractSHA256 != px1TermsAnySHA256 {
		t.Fatal("any-mode issuance", e)
	}
}

// Claim: a conforming signer's recomputation accepts each of the three real
// requests and refuses each tampered variant with a specific code: it never
// signs a digest that does not follow from Terms and Payload.
func TestPayGrantV2DigestRecomputation(t *testing.T) {
	log := &px1SignLog{}
	g, l := px1Signers(log)
	if _, e := IssuePayGrantV2(context.Background(), px1PayInput(), g, l); e != nil {
		t.Fatal(e)
	}
	consent, contract, grant := log.reqs[0], log.reqs[1], log.reqs[2]
	for _, req := range log.reqs {
		terms, e := VerifyPayGrantSigningRequest(req)
		if e != nil || !reflect.DeepEqual(terms, px1PayTermsAllow()) {
			t.Fatal("real request refused", req.Purpose, e)
		}
	}
	anyTerms := px1Golden(t, "terms-v2-any.json")
	editJSON := func(raw []byte, edit func(map[string]any)) []byte {
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if e := d.Decode(&m); e != nil {
			t.Fatal(e)
		}
		edit(m)
		b, _ := json.Marshal(m)
		return b
	}
	var grantObj Grant
	if e := json.Unmarshal(grant.Payload, &grantObj); e != nil {
		t.Fatal(e)
	}
	regrant := func(edit func(*Grant)) []byte {
		g := grantObj
		g.Scope = append([]string(nil), g.Scope...)
		edit(&g)
		b, _ := json.Marshal(g)
		return b
	}
	cases := []struct {
		name, want string
		req        PayGrantSigningRequest
		edit       func(*PayGrantSigningRequest)
	}{
		{"version", "SIGNING_REQUEST_VERSION", contract, func(r *PayGrantSigningRequest) { r.Version = 2 }},
		{"signer-key", "SIGNING_REQUEST_KEY", contract, func(r *PayGrantSigningRequest) { r.SignerKey = "x" }},
		{"bare-digest", "SIGNING_REQUEST_TERMS", contract, func(r *PayGrantSigningRequest) { r.Terms, r.Payload = nil, nil }},
		{"terms-pretty", "SIGNING_REQUEST_TERMS", contract, func(r *PayGrantSigningRequest) {
			var b bytes.Buffer
			_ = json.Indent(&b, r.Terms, "", " ")
			r.Terms = b.Bytes()
		}},
		{"terms-invalid-caps", "SIGNING_REQUEST_TERMS", contract, func(r *PayGrantSigningRequest) {
			r.Terms = []byte(strings.Replace(string(r.Terms), `"transfer_cap_sat":100000`, `"transfer_cap_sat":400000`, 1))
		}},
		{"purpose", "SIGNING_REQUEST_PURPOSE", contract, func(r *PayGrantSigningRequest) { r.Purpose = "pay-grant-other" }},
		{"contract-other-terms", "SIGNING_REQUEST_PAYLOAD", contract, func(r *PayGrantSigningRequest) { r.Terms = anyTerms }},
		{"contract-digest", "SIGNING_REQUEST_DIGEST", contract, func(r *PayGrantSigningRequest) { r.Digest = strings.Repeat("a", 64) }},
		{"consent-other-terms", "SIGNING_REQUEST_PAYLOAD", consent, func(r *PayGrantSigningRequest) { r.Terms = anyTerms }},
		{"consent-booking", "SIGNING_REQUEST_PAYLOAD", consent, func(r *PayGrantSigningRequest) {
			r.Payload = []byte(strings.Replace(string(r.Payload), PayGrantBookingRef(r.Terms), strings.Repeat("d", 64), 1))
		}},
		{"consent-signer", "SIGNING_REQUEST_PAYLOAD", consent, func(r *PayGrantSigningRequest) { _, r.SignerKey = testKey(4) }},
		{"consent-kind", "SIGNING_REQUEST_PAYLOAD", consent, func(r *PayGrantSigningRequest) {
			r.Payload = []byte(strings.Replace(string(r.Payload), `"kind":8181`, `"kind":1`, 1))
		}},
		{"consent-id", "SIGNING_REQUEST_DIGEST", consent, func(r *PayGrantSigningRequest) {
			r.Payload = editJSON(r.Payload, func(m map[string]any) { m["created_at"] = json.Number("1794000061") })
			// map order is alphabetical; restore NIP-01 order by re-encoding the struct.
			var p payGrantConsentPayload
			_ = json.Unmarshal(r.Payload, &p)
			r.Payload, _ = json.Marshal(p)
		}},
		{"consent-digest", "SIGNING_REQUEST_DIGEST", consent, func(r *PayGrantSigningRequest) { r.Digest = strings.Repeat("a", 64) }},
		{"grant-other-terms", "SIGNING_REQUEST_PAYLOAD", grant, func(r *PayGrantSigningRequest) { r.Terms = anyTerms }},
		{"grant-scope", "SIGNING_REQUEST_PAYLOAD", grant, func(r *PayGrantSigningRequest) {
			r.Payload = regrant(func(g *Grant) { g.Scope = []string{"deliver", "pay"} })
		}},
		{"grant-budget-below-spend", "SIGNING_REQUEST_PAYLOAD", grant, func(r *PayGrantSigningRequest) {
			r.Payload = regrant(func(g *Grant) { b := int64(499999); g.Budget = &b })
		}},
		{"grant-budget-absent", "SIGNING_REQUEST_PAYLOAD", grant, func(r *PayGrantSigningRequest) { r.Payload = regrant(func(g *Grant) { g.Budget = nil }) }},
		{"grant-issuer", "SIGNING_REQUEST_PAYLOAD", grant, func(r *PayGrantSigningRequest) { _, r.SignerKey = testKey(4) }},
		{"grant-digest", "SIGNING_REQUEST_DIGEST", grant, func(r *PayGrantSigningRequest) { r.Digest = Hash(r.Payload) }},
		{"grant-valid-neighbour", "<nil>", grant, func(*PayGrantSigningRequest) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := c.req
			req.Terms, req.Payload = bytes.Clone(req.Terms), bytes.Clone(req.Payload)
			c.edit(&req)
			terms, e := VerifyPayGrantSigningRequest(req)
			if px1Code(e) != c.want {
				t.Fatalf("want %s got %s", c.want, px1Code(e))
			}
			if e != nil && !reflect.DeepEqual(terms, PayTermsV2{}) {
				t.Fatal("refusal returned terms")
			}
		})
	}
}

// Claim: every signer-side fault (wrong signer key, nil signer, signer error,
// cancelled context, a signature by another key or over another digest, a
// malformed signature, or a response that does not echo the request) refuses
// with its code and returns the zero result; wrong keys and invalid input are
// caught before any signer call, and no step after a failed one runs. The
// unmodified signers succeed (valid neighbour).
func TestPayGrantV2SignerRefusals(t *testing.T) {
	wrongSig := func(p *PayGrantSignature) {
		priv, _ := testKey(5)
		s, _ := schnorr.Sign(priv, mustDecodeKey(p.Digest))
		p.Signature = hex.EncodeToString(s.Serialize())
	}
	otherDigest := func(p *PayGrantSignature) {
		priv, _ := testKey(1)
		s, _ := schnorr.Sign(priv, mustDecodeKey(strings.Repeat("e", 64)))
		p.Signature = hex.EncodeToString(s.Serialize())
	}
	boom := errors.New("keychain locked")
	cases := []struct {
		name, want string
		calls      int
		cancel     bool
		edit       func(in *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner)
	}{
		{"valid", "<nil>", 3, false, nil},
		{"invalid-input", "CONTRACT_BUDGET", 0, false, func(in *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			in.BudgetSat = 1
			return g, l
		}},
		{"grantee-wrong-key", "PAY_GRANT_SIGNER_KEY", 0, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			g.key = 4
			return g, l
		}},
		{"landlord-wrong-key", "PAY_GRANT_SIGNER_KEY", 0, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.key = 4
			return g, l
		}},
		{"signers-swapped", "PAY_GRANT_SIGNER_KEY", 0, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) { return l, g }},
		{"grantee-nil", "PAY_GRANT_SIGNER_KEY", 0, false, func(_ *PayGrantV2Input, _, l *px1MemSigner) (DigestSigner, DigestSigner) { return nil, l }},
		{"landlord-nil", "PAY_GRANT_SIGNER_KEY", 0, false, func(_ *PayGrantV2Input, g, _ *px1MemSigner) (DigestSigner, DigestSigner) { return g, nil }},
		{"cancelled", "PAY_GRANT_SIGNER", 0, true, nil},
		{"consent-signer-error", "PAY_GRANT_SIGNER", 1, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			g.fail = map[string]error{SignPurposeConsentEvent: boom}
			return g, l
		}},
		{"grant-signer-error", "PAY_GRANT_SIGNER", 3, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.fail = map[string]error{SignPurposeGrant: boom}
			return g, l
		}},
		{"consent-other-key", "PAY_GRANT_SIGNATURE", 1, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			g.forge = map[string]func(*PayGrantSignature){SignPurposeConsentEvent: wrongSig}
			return g, l
		}},
		{"countersign-other-digest", "PAY_GRANT_SIGNATURE", 2, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.forge = map[string]func(*PayGrantSignature){SignPurposeContract: otherDigest}
			return g, l
		}},
		{"grant-other-key", "PAY_GRANT_SIGNATURE", 3, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.forge = map[string]func(*PayGrantSignature){SignPurposeGrant: wrongSig}
			return g, l
		}},
		{"grant-malformed", "PAY_GRANT_SIGNATURE", 3, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.forge = map[string]func(*PayGrantSignature){SignPurposeGrant: func(p *PayGrantSignature) { p.Signature = p.Signature[:127] }}
			return g, l
		}},
		{"grant-uppercase", "PAY_GRANT_SIGNATURE", 3, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.forge = map[string]func(*PayGrantSignature){SignPurposeGrant: func(p *PayGrantSignature) { p.Signature = strings.ToUpper(p.Signature) }}
			return g, l
		}},
		{"echo-purpose", "PAY_GRANT_SIGNATURE_ECHO", 2, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.forge = map[string]func(*PayGrantSignature){SignPurposeContract: func(p *PayGrantSignature) { p.Purpose = SignPurposeGrant }}
			return g, l
		}},
		{"echo-digest", "PAY_GRANT_SIGNATURE_ECHO", 1, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			g.forge = map[string]func(*PayGrantSignature){SignPurposeConsentEvent: func(p *PayGrantSignature) { p.Digest = strings.Repeat("e", 64) }}
			return g, l
		}},
		{"echo-key", "PAY_GRANT_SIGNATURE_ECHO", 3, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.forge = map[string]func(*PayGrantSignature){SignPurposeGrant: func(p *PayGrantSignature) { _, p.SignerKey = testKey(5) }}
			return g, l
		}},
		{"echo-version", "PAY_GRANT_SIGNATURE_ECHO", 3, false, func(_ *PayGrantV2Input, g, l *px1MemSigner) (DigestSigner, DigestSigner) {
			l.forge = map[string]func(*PayGrantSignature){SignPurposeGrant: func(p *PayGrantSignature) { p.Version = 2 }}
			return g, l
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			log := &px1SignLog{}
			in := px1PayInput()
			g, l := px1Signers(log)
			var gs, ls DigestSigner = g, l
			if c.edit != nil {
				gs, ls = c.edit(&in, g, l)
			}
			ctx := context.Background()
			if c.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			r, e := IssuePayGrantV2(ctx, in, gs, ls)
			if px1Code(e) != c.want || len(log.calls) != c.calls {
				t.Fatalf("want %s after %d calls, got %s after %v", c.want, c.calls, px1Code(e), log.calls)
			}
			if e != nil && !reflect.DeepEqual(r, PayGrantV2Result{}) {
				t.Fatal("refusal returned a partial result")
			}
			if c.name == "cancelled" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation cause lost")
			}
			if strings.HasSuffix(c.name, "signer-error") && !errors.Is(e, boom) {
				t.Fatal("signer cause lost")
			}
			if errors.Is(e, ErrPayGrantNotImplemented) {
				t.Fatal("stub sentinel still returned")
			}
		})
	}
}

// Claim: a signer that rewrites the request buffers after signing cannot
// change the issued terms or grant, because each request carries copies.
func TestPayGrantV2SignerCannotRewrite(t *testing.T) {
	g, l := px1Signers(nil)
	clean, e := IssuePayGrantV2(context.Background(), px1PayInput(), g, l)
	if e != nil {
		t.Fatal(e)
	}
	g.scribble, l.scribble = true, true
	r, e := IssuePayGrantV2(context.Background(), px1PayInput(), g, l)
	if e != nil || !bytes.Equal(r.Terms, px1Golden(t, "terms-v2-allow.json")) || r.GrantID != clean.GrantID {
		t.Fatal("signer rewrote issuance state", e)
	}
}

// px1RemoteSigner plays Ivan's Mac: it watches outbox, recomputes each
// request, signs and publishes the answer atomically in inbox.
func px1RemoteSigner(ctx context.Context, outbox, inbox string, keys map[string]byte, seen *sync.Map) {
	for {
		entries, _ := os.ReadDir(outbox)
		for _, en := range entries {
			name := en.Name()
			if !strings.HasSuffix(name, ".request.json") {
				continue
			}
			if _, done := seen.LoadOrStore(name, true); done {
				continue
			}
			raw, e := os.ReadFile(filepath.Join(outbox, name))
			if e != nil {
				continue
			}
			var req PayGrantSigningRequest
			if canonical(raw, &req) != nil {
				continue
			}
			if _, e := VerifyPayGrantSigningRequest(req); e != nil {
				continue
			}
			priv, _ := testKey(keys[req.SignerKey])
			s, _ := schnorr.Sign(priv, mustDecodeKey(req.Digest))
			b, _ := json.Marshal(PayGrantSignature{1, req.Purpose, req.SignerKey, req.Digest, hex.EncodeToString(s.Serialize())})
			out := filepath.Join(inbox, strings.TrimSuffix(name, ".request.json")+".signature.json")
			_ = os.WriteFile(out+".part", b, 0600)
			_ = os.Rename(out+".part", out)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// Claim: two file-exchange signers sharing one outbox/inbox pair carry a full
// issuance to a remote conforming signer: three 0600 request files named
// <purpose>-<digest>.request.json in canonical JSON, and a result identical to
// the in-memory issuance.
func TestPayGrantV2FileExchangeIssue(t *testing.T) {
	outbox, inbox := t.TempDir(), t.TempDir()
	in := px1PayInput()
	keys := map[string]byte{in.IssuerKey: 1, in.GranteeKey: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var seen sync.Map
	go px1RemoteSigner(ctx, outbox, inbox, keys, &seen)
	r, e := IssuePayGrantV2(ctx, in, NewFileExchangeSigner(outbox, inbox, in.GranteeKey, time.Millisecond), NewFileExchangeSigner(outbox, inbox, in.IssuerKey, time.Millisecond))
	if e != nil {
		t.Fatal(e)
	}
	g, l := px1Signers(nil)
	mem, e := IssuePayGrantV2(context.Background(), in, g, l)
	if e != nil || !reflect.DeepEqual(r, mem) {
		t.Fatal("file exchange result differs from in-memory issuance")
	}
	entries, _ := os.ReadDir(outbox)
	var names []string
	for _, en := range entries {
		info, _ := en.Info()
		if info.Mode().Perm() != 0600 {
			t.Fatal("request mode", en.Name(), info.Mode())
		}
		raw, _ := os.ReadFile(filepath.Join(outbox, en.Name()))
		var req PayGrantSigningRequest
		if canonical(raw, &req) != nil || en.Name() != req.Purpose+"-"+req.Digest+".request.json" {
			t.Fatal("request file", en.Name())
		}
		names = append(names, req.Purpose)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{SignPurposeConsentEvent, SignPurposeContract, SignPurposeGrant}) {
		t.Fatalf("request files %v", names)
	}
}

// Claim: the file-exchange signer refuses a foreign key, an unknown purpose
// and a non-hex digest before writing anything; refuses a conflicting earlier
// request, a symlinked or non-canonical answer, and an expired wait; and
// accepts a byte-identical earlier request (re-run neighbour). A non-positive
// poll interval does not panic.
func TestPayGrantV2FileExchangeRefusals(t *testing.T) {
	in := px1PayInput()
	base := PayGrantSigningRequest{Version: 1, Purpose: SignPurposeContract, SignerKey: in.IssuerKey, Digest: px1TermsAllowSHA256, Terms: px1Golden(t, "terms-v2-allow.json"), Payload: []byte(`{"contract_sha256":"` + px1TermsAllowSHA256 + `"}`)}
	priv, _ := testKey(1)
	s, _ := schnorr.Sign(priv, mustDecodeKey(base.Digest))
	answer, _ := json.Marshal(PayGrantSignature{1, base.Purpose, base.SignerKey, base.Digest, hex.EncodeToString(s.Serialize())})
	name := base.Purpose + "-" + base.Digest
	short := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 30*time.Millisecond)
	}
	cases := []struct {
		name, want string
		wrote      bool
		setup      func(t *testing.T, outbox, inbox string, req *PayGrantSigningRequest)
	}{
		{"valid-answer", "<nil>", true, func(t *testing.T, _, inbox string, _ *PayGrantSigningRequest) {
			_ = os.WriteFile(filepath.Join(inbox, name+".signature.json"), answer, 0600)
		}},
		{"rerun-identical-request", "<nil>", true, func(t *testing.T, outbox, inbox string, req *PayGrantSigningRequest) {
			b, _ := json.Marshal(*req)
			_ = os.WriteFile(filepath.Join(outbox, name+".request.json"), b, 0600)
			_ = os.WriteFile(filepath.Join(inbox, name+".signature.json"), answer, 0600)
		}},
		{"foreign-key", "PAY_GRANT_SIGNER_KEY", false, func(_ *testing.T, _, _ string, req *PayGrantSigningRequest) { _, req.SignerKey = testKey(4) }},
		{"unknown-purpose", "SIGNING_REQUEST_PURPOSE", false, func(_ *testing.T, _, _ string, req *PayGrantSigningRequest) { req.Purpose = "../escape" }},
		{"digest-path", "SIGNING_REQUEST_KEY", false, func(_ *testing.T, _, _ string, req *PayGrantSigningRequest) {
			req.Digest = "../../" + strings.Repeat("a", 58)
		}},
		{"conflicting-request", "SIGNING_REQUEST_CONFLICT", false, func(t *testing.T, outbox, _ string, _ *PayGrantSigningRequest) {
			_ = os.WriteFile(filepath.Join(outbox, name+".request.json"), []byte(`{"other":1}`), 0600)
		}},
		{"answer-symlink", "SIGNATURE_FILE", true, func(t *testing.T, _, inbox string, _ *PayGrantSigningRequest) {
			target := filepath.Join(t.TempDir(), "a.json")
			_ = os.WriteFile(target, answer, 0600)
			if e := os.Symlink(target, filepath.Join(inbox, name+".signature.json")); e != nil {
				t.Fatal(e)
			}
		}},
		{"answer-noncanonical", "SIGNATURE_FILE_ENCODING", true, func(t *testing.T, _, inbox string, _ *PayGrantSigningRequest) {
			_ = os.WriteFile(filepath.Join(inbox, name+".signature.json"), append(answer, '\n'), 0600)
		}},
		{"answer-absent", "SIGNATURE_WAIT", true, func(*testing.T, string, string, *PayGrantSigningRequest) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outbox, inbox := t.TempDir(), t.TempDir()
			req := base
			c.setup(t, outbox, inbox, &req)
			ctx, cancel := short()
			defer cancel()
			got, e := NewFileExchangeSigner(outbox, inbox, in.IssuerKey, 0).Sign(ctx, req)
			if px1Code(e) != c.want {
				t.Fatalf("want %s got %s", c.want, px1Code(e))
			}
			if e != nil && !reflect.DeepEqual(got, PayGrantSignature{}) {
				t.Fatal("refusal returned a signature")
			}
			if e == nil && !VerifySignature(got.SignerKey, got.Digest, got.Signature) {
				t.Fatal("accepted answer is not the published signature")
			}
			if c.name == "answer-absent" && !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal("wait cause lost")
			}
			entries, _ := os.ReadDir(outbox)
			if wrote := len(entries) == 1 && entries[0].Name() == name+".request.json"; c.want != "SIGNING_REQUEST_CONFLICT" && wrote != c.wrote {
				t.Fatalf("request written=%v want %v (%d entries)", wrote, c.wrote, len(entries))
			}
		})
	}
}
