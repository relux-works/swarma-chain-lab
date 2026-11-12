package wallet

// PX1 FROZEN contract tests for freeze amendment 1 (owner S0). They exercise
// the frozen helpers in the API files directly, so they stay green after every
// stream lands; each refusal sits beside a valid neighbour.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// px1ReconcileVectors is testdata/px1/reconcile-v2-vectors.json.
type px1ReconcileVectors struct {
	ReceiptKey string          `json:"receipt_key"`
	HeaderA    JournalHeaderV2 `json:"header_a"`
	HeaderB    JournalHeaderV2 `json:"header_b"`
	HeaderAOut string          `json:"header_a_canonical"`
	Record     JournalRecordV2 `json:"record"`
	Preimage   string          `json:"preimage_a"`
	Digest     string          `json:"digest_a"`
}

func px1LoadReconcileVectors(t *testing.T) px1ReconcileVectors {
	t.Helper()
	var v px1ReconcileVectors
	if e := json.Unmarshal(px1Golden(t, "reconcile-v2-vectors.json"), &v); e != nil || v.Record.Reconcile == nil {
		t.Fatal("reconcile vectors", e)
	}
	return v
}

// px1SignReconcile signs rec for header h with the fixture receipt key
// (testKey(9)) through the frozen digest, as the operator CLI would.
func px1SignReconcile(t *testing.T, h JournalHeaderV2, rec JournalRecordV2) JournalRecordV2 {
	t.Helper()
	key, _ := testKey(9)
	d, e := ReconcileDigestV2(h, rec)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := schnorr.Sign(key, d)
	if e != nil {
		t.Fatal(e)
	}
	payload := *rec.Reconcile
	payload.Signature = hex.EncodeToString(sig.Serialize())
	rec.Reconcile = &payload
	return rec
}

// Claim (A1): the status golden's grant day is the UTC day of generated_at,
// the same clock rule as the budget read. Negative control: the pre-amendment
// day "2026-11-12" is reported as inconsistent.
func TestPX1StatusFixtureDayMatchesGeneratedAt(t *testing.T) {
	var golden StatusProjectionV1
	if e := json.Unmarshal(px1Golden(t, "status-projection-v1.json"), &golden); e != nil || len(golden.Grants) != 1 {
		t.Fatal("status golden", e)
	}
	consistent := func(p StatusProjectionV1) bool {
		want := time.Unix(p.GeneratedAt, 0).UTC().Format(time.DateOnly)
		for _, g := range p.Grants {
			if g.Day != want {
				return false
			}
		}
		return true
	}
	if !consistent(golden) || golden.Grants[0].Day != "2026-11-06" {
		t.Fatalf("golden day %q is not UTC day of generated_at %d", golden.Grants[0].Day, golden.GeneratedAt)
	}
	old := golden
	old.Grants = []StatusGrant{golden.Grants[0]}
	old.Grants[0].Day = "2026-11-12"
	if consistent(old) {
		t.Fatal("negative control: the pre-amendment day was accepted")
	}
}

// Claim (A5): JournalHeaderV2 carries receipt_key as its last member, the
// vector header marshals to the frozen bytes, and two headers that differ only
// in ReceiptKey are unequal (so the JOURNAL_SEGMENT header check pins the key).
func TestPX1JournalHeaderReceiptKey(t *testing.T) {
	v := px1LoadReconcileVectors(t)
	if got := string(canonical(v.HeaderA)); got != v.HeaderAOut || !strings.HasSuffix(got, `,"receipt_key":"`+px1ExecutorKey+`"}`) {
		t.Fatalf("header bytes drifted\n got %s\nwant %s", got, v.HeaderAOut)
	}
	other := v.HeaderA
	other.ReceiptKey = strings.Repeat("0", 63) + "1"
	if other == v.HeaderA {
		t.Fatal("a changed receipt key is not a header difference")
	}
	if same := v.HeaderA; same != v.HeaderA {
		t.Fatal("positive control: identical headers differ")
	}
}

// Claim (A5): VerifyReconcileV2 accepts a record signed by the header's
// receipt key, and refuses RECONCILE_AUTHORIZATION when the header key is
// empty, malformed or another valid key, or the signature is absent.
func TestPX1ReconcileReceiptKey(t *testing.T) {
	v := px1LoadReconcileVectors(t)
	rec := px1SignReconcile(t, v.HeaderA, v.Record)
	if e := VerifyReconcileV2(v.HeaderA, rec); e != nil {
		t.Fatal("positive control: own receipt key refused", e)
	}
	_, otherKey := testKey(4)
	for _, c := range []struct{ name, key string }{
		{"empty", ""},
		{"uppercase", strings.ToUpper(v.HeaderA.ReceiptKey)},
		{"short", v.HeaderA.ReceiptKey[:62]},
		{"off-curve", strings.Repeat("f", 64)},
		{"other-key", otherKey},
	} {
		h := v.HeaderA
		h.ReceiptKey = c.key
		if e := VerifyReconcileV2(h, rec); e == nil || e.Error() != CodeReconcileAuthorization {
			t.Fatalf("%s receipt key: got %v, want %s", c.name, e, CodeReconcileAuthorization)
		}
	}
	unsigned := rec
	payload := *rec.Reconcile
	payload.Signature = ""
	unsigned.Reconcile = &payload
	if e := VerifyReconcileV2(v.HeaderA, unsigned); e == nil || e.Error() != CodeReconcileAuthorization {
		t.Fatal("unsigned reconcile accepted", e)
	}
	notReconcile := rec
	notReconcile.Kind = RecordReserve
	if e := VerifyReconcileV2(v.HeaderA, notReconcile); e == nil {
		t.Fatal("a non-reconcile kind verified as a release")
	}
}

// Claim (A6): the frozen preimage and digest equal the vector (domain v2,
// member order binding, grant_id, nonce, seq, reconcile with signature ""),
// and the signature does not enter its own preimage.
func TestPX1ReconcileDigestVector(t *testing.T) {
	v := px1LoadReconcileVectors(t)
	p := ReconcilePreimageV2{Binding: v.HeaderA.Binding, GrantID: v.Record.GrantID, Nonce: v.Record.Nonce, Seq: v.Record.Seq, Reconcile: *v.Record.Reconcile}
	p.Reconcile.Signature = ""
	if got := string(canonical(p)); got != v.Preimage {
		t.Fatalf("preimage drifted\n got %s\nwant %s", got, v.Preimage)
	}
	d, e := ReconcileDigestV2(v.HeaderA, v.Record)
	if e != nil || hex.EncodeToString(d) != v.Digest {
		t.Fatalf("digest drifted: %x, want %s (%v)", d, v.Digest, e)
	}
	signed := px1SignReconcile(t, v.HeaderA, v.Record)
	if d2, _ := ReconcileDigestV2(v.HeaderA, signed); !bytes.Equal(d, d2) {
		t.Fatal("the signature entered its own preimage")
	}
}

// Claim (A6): a release signed for one journal, request or position verifies
// only there. Each case signs a fresh record for header A and its own
// (grant_id, nonce, seq), checks that it verifies there (positive control),
// then moves exactly one bound value and requires RECONCILE_AUTHORIZATION.
// Limit: target_seq, amount, evidence and note were already bound by the
// freeze and are covered by the vector digest, not by a case here.
func TestPX1ReconcileBinding(t *testing.T) {
	v := px1LoadReconcileVectors(t)
	if v.HeaderA.ReceiptKey != v.HeaderB.ReceiptKey || v.HeaderA.Binding == v.HeaderB.Binding {
		t.Fatal("vector journals must share the receipt key and differ in binding")
	}
	rec := px1SignReconcile(t, v.HeaderA, v.Record)
	if e := VerifyReconcileV2(v.HeaderA, rec); e != nil {
		t.Fatal("positive control: own journal refused", e)
	}
	for _, c := range []struct {
		name, marker string
		move         func(h *JournalHeaderV2, r *JournalRecordV2)
	}{
		{"cross-journal", "release signed for journal A verified in journal B", func(h *JournalHeaderV2, r *JournalRecordV2) { *h = v.HeaderB }},
		{"cross-grant", "release moved to another grant_id", func(h *JournalHeaderV2, r *JournalRecordV2) { r.GrantID = strings.Repeat("9", 64) }},
		{"cross-nonce", "release moved to another nonce", func(h *JournalHeaderV2, r *JournalRecordV2) { r.Nonce = strings.Repeat("8", 64) }},
		{"cross-seq", "release moved to another seq", func(h *JournalHeaderV2, r *JournalRecordV2) { r.Seq++ }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, r := v.HeaderA, rec
			c.move(&h, &r)
			if e := VerifyReconcileV2(h, r); e == nil || e.Error() != CodeReconcileAuthorization {
				t.Fatalf("%s (got %v)", c.marker, e)
			}
		})
	}
}

// px1AdmitRules is a fake of the S1 cap rules that admits every executor and
// cap check and applies allow-list membership, so the frozen network binding
// is visible on its own.
type px1AdmitRules struct{}

func (px1AdmitRules) CheckExecutor(TermsV2, string) error { return nil }
func (px1AdmitRules) CheckRecipient(l EffectiveLimits, a string) error {
	for _, r := range l.Recipients {
		if r == a {
			return nil
		}
	}
	return errors.New(CodeAddressNotAllowed)
}
func (px1AdmitRules) CheckPrePlan(EffectiveLimits, SpendIntent, LedgerView) error  { return nil }
func (px1AdmitRules) CheckPostPlan(EffectiveLimits, SpendIntent, LedgerView) error { return nil }

// Claim (A4): the network-bearing checker admits, in any mode, a canonical
// P2PKH of its own pinned network and refuses ADDRESS_NOT_ALLOWED for the other
// network, a non-canonical spelling and an unknown mode; allow mode still
// needs membership. Limit: the S1 rules are a fake here; the real rules are
// S1's tests.
func TestPX1CapCheckerForNetwork(t *testing.T) {
	anyMode := EffectiveLimits{RecipientMode: RecipientModeAny, Recipients: []string{}}
	allow := EffectiveLimits{RecipientMode: RecipientModeAllow, Recipients: []string{px1AllowA, px1AllowB}}
	main := newPinnedCapChecker("main", su.MainGenesis, px1AdmitRules{})
	reg := newPinnedCapChecker("regtest", su.RegtestGenesis, px1AdmitRules{})
	regAddr := testAddress(4)
	for _, c := range []struct {
		name   string
		c      CapChecker
		l      EffectiveLimits
		addr   string
		admits bool
	}{
		{"main-any-main", main, anyMode, px1Outsider, true},
		{"main-any-regtest", main, anyMode, regAddr, false},
		{"main-any-case", main, anyMode, strings.ToLower(px1Outsider), false},
		{"regtest-any-regtest", reg, anyMode, regAddr, true},
		{"regtest-any-main", reg, anyMode, px1Outsider, false},
		{"main-allow-member", main, allow, px1AllowA, true},
		{"main-allow-outsider", main, allow, px1Outsider, false},
		{"main-unknown-mode", main, EffectiveLimits{RecipientMode: "all"}, px1Outsider, false},
	} {
		e := c.c.CheckRecipient(c.l, c.addr)
		if c.admits && e != nil || !c.admits && (e == nil || e.Error() != CodeAddressNotAllowed) {
			t.Fatalf("%s: got %v, admits=%v", c.name, e, c.admits)
		}
	}
}

// Claim (A4): a checker built without a pinned network (empty, unknown, or a
// genesis of the other network) refuses NETWORK_PIN on every method even when
// the wrapped rules admit everything; the public constructor with a valid pin
// returns that same binding. Negative control for "no network, allow-all".
func TestPX1CapCheckerNoNetworkRefuses(t *testing.T) {
	anyMode := EffectiveLimits{GrantID: strings.Repeat("a", 64), RecipientMode: RecipientModeAny, Recipients: []string{}}
	in := SpendIntent{GrantID: anyMode.GrantID, Recipient: px1Outsider, AmountSat: 1000, FeeLimitSat: 1000, Day: "2026-11-06"}
	if e := newPinnedCapChecker("main", su.MainGenesis, px1AdmitRules{}).CheckExecutor(px1TermsAny(), px1ExecutorKey); e != nil {
		t.Fatal("positive control: pinned checker refused", e)
	}
	for _, pin := range [][2]string{{"", ""}, {"main", ""}, {"main", su.RegtestGenesis}, {"testnet", su.MainGenesis}} {
		c := newPinnedCapChecker(pin[0], pin[1], px1AdmitRules{})
		for name, e := range map[string]error{
			"executor":  c.CheckExecutor(px1TermsAny(), px1ExecutorKey),
			"recipient": c.CheckRecipient(anyMode, px1Outsider),
			"preplan":   c.CheckPrePlan(anyMode, in, nil),
			"postplan":  c.CheckPostPlan(anyMode, in, nil),
		} {
			if e == nil || e.Error() != "NETWORK_PIN" {
				t.Fatalf("no network %q/%q: %s admitted or wrong code: %v", pin[0], pin[1], name, e)
			}
		}
	}
	if _, ok := NewCapCheckerFor("main", su.MainGenesis).(pinnedCapChecker); !ok {
		t.Fatal("NewCapCheckerFor does not return the frozen network binding")
	}
}

// Claim (A4, rev 2): the PUBLIC constructor itself keeps the caller's pin. In
// any mode (implemented in the frozen wrapper, so no fake rules are involved)
// NewCapCheckerFor("main") admits a main P2PKH and refuses a regtest one, and
// NewCapCheckerFor("regtest") admits a regtest P2PKH and refuses a main one.
// Empty, half, crossed, unknown and mis-cased pins refuse NETWORK_PIN on every
// method through the public constructor. Limit: allow-mode membership and the
// cap rules are S1's real rules (TestPX1CapCheckerForNetwork isolates the
// wrapper with a fake).
func TestPX1PublicCapCheckerPin(t *testing.T) {
	anyMode := EffectiveLimits{GrantID: strings.Repeat("a", 64), RecipientMode: RecipientModeAny, Recipients: []string{}}
	pubMain := NewCapCheckerFor("main", su.MainGenesis)
	pubReg := NewCapCheckerFor("regtest", su.RegtestGenesis)
	regAddr := testAddress(4)
	for _, c := range []struct {
		name   string
		c      CapChecker
		addr   string
		admits bool
	}{
		{"public-main-any-main", pubMain, px1Outsider, true},
		{"public-main-any-regtest", pubMain, regAddr, false},
		{"public-regtest-any-regtest", pubReg, regAddr, true},
		{"public-regtest-any-main", pubReg, px1Outsider, false},
	} {
		e := c.c.CheckRecipient(anyMode, c.addr)
		if c.admits && e != nil || !c.admits && (e == nil || e.Error() != CodeAddressNotAllowed) {
			t.Errorf("%s: got %v, admits=%v", c.name, e, c.admits)
		}
	}
	in := SpendIntent{GrantID: anyMode.GrantID, Recipient: px1Outsider, AmountSat: 1000, FeeLimitSat: 1000, Day: "2026-11-06"}
	for _, pin := range [][2]string{{"", ""}, {"main", ""}, {"", su.MainGenesis}, {"main", su.RegtestGenesis}, {"regtest", su.MainGenesis}, {"testnet", su.MainGenesis}, {"MAIN", su.MainGenesis}, {"main", strings.ToUpper(su.MainGenesis)}} {
		c := NewCapCheckerFor(pin[0], pin[1])
		for _, m := range []struct {
			name string
			e    error
		}{
			{"recipient-main", c.CheckRecipient(anyMode, px1Outsider)},
			{"recipient-regtest", c.CheckRecipient(anyMode, regAddr)},
			{"executor", c.CheckExecutor(px1TermsAny(), px1ExecutorKey)},
			{"preplan", c.CheckPrePlan(anyMode, in, nil)},
			{"postplan", c.CheckPostPlan(anyMode, in, nil)},
		} {
			if m.e == nil || m.e.Error() != "NETWORK_PIN" {
				t.Errorf("public constructor admitted without a valid pin %q/%q: %s %v", pin[0], pin[1], m.name, m.e)
			}
		}
	}
}

// px1SharesDir reports whether binding the directory of either socket would
// expose the other: same directory, or one directory nested in the other.
func px1SharesDir(a, b string) bool {
	da, db := path.Dir(a)+"/", path.Dir(b)+"/"
	return strings.HasPrefix(da, db) || strings.HasPrefix(db, da)
}

// Claim (A8): the operator status socket has its own 0750 directory and keeps
// 0660; the agent-facing wallet socket (/run/swarma-wallet/wallet.sock, the
// only path bound into a slot) does not share a directory with it; and no
// non-test Go source of this module names the old /run/swarma-wallet status
// path. The checker flags the old and a nested layout (controls) and does not
// confuse the -status prefix with the wallet directory.
func TestPX1StatusSocketSplit(t *testing.T) {
	const agentSocket = "/run/swarma-wallet/wallet.sock"
	if !px1SharesDir(agentSocket, "/run/swarma-wallet/status.sock") || !px1SharesDir(agentSocket, "/run/swarma-wallet/s/status.sock") || px1SharesDir(agentSocket, "/run/swarma-wallet-status/status.sock") {
		t.Fatal("shared-directory checker is broken")
	}
	if StatusSocketPath != "/run/swarma-wallet-status/status.sock" || path.Dir(StatusSocketPath) != StatusSocketDir || StatusSocketDirMode != 0o750 || StatusSocketMode != 0o660 {
		t.Errorf("status socket placement drifted: %s %o %o", StatusSocketPath, StatusSocketDirMode, StatusSocketMode)
	}
	for _, a := range []string{agentSocket, path.Dir(agentSocket) + "/"} {
		if px1SharesDir(a, StatusSocketPath) {
			t.Errorf("agent-facing path shares a directory with the status socket: %s", a)
		}
	}
	e := filepath.WalkDir(".", func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == ".temp") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, e := os.ReadFile(p)
		if e == nil && strings.Contains(string(b), "/run/swarma-wallet/status.sock") {
			t.Errorf("old status socket path in %s (A8 migration)", p)
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
}

// Claim (A4): the deprecated networkless NewCapChecker never admits an
// any-mode recipient. At the frozen base the stub refuses everything; after S1
// lands this pins the amended contract on S1's real rules.
func TestPX1NetworklessCapCheckerNoAnyMode(t *testing.T) {
	anyMode := EffectiveLimits{RecipientMode: RecipientModeAny, Recipients: []string{}}
	for _, a := range []string{px1Outsider, testAddress(4)} {
		if NewCapChecker().CheckRecipient(anyMode, a) == nil {
			t.Fatalf("networkless checker admitted %s in any mode", a)
		}
	}
	if e := NewCapCheckerFor("", "").CheckRecipient(anyMode, px1Outsider); e == nil {
		t.Fatal("public constructor without a network admitted an any-mode recipient")
	}
}
