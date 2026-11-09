package booking

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testModelCaps() *ModelCaps {
	return &ModelCaps{InputTokens: 100000, OutputTokens: 20000, Requests: 200, MaxTokens: 1024, CostNanoUSD: 500000, DefaultMaxOutputTokens: 512}
}

func modelConfig(f *ledgerFixture, t *testing.T) ConfigV2 {
	c := f.cfg
	c.StateDir = privateDir(t)
	c.Template.Version = 2
	c.Template.ModelCaps = testModelCaps()
	c.ModelCaps = testModelCaps()
	c.TemplateSHA256 = Hash(canonical(c.Template))
	return c
}

// Every configured cap must exactly equal its signed template counterpart.
// Both smaller and larger mismatches, missing defaults and profile tampering
// refuse before state or node effects, beside a successfully opened service.
func TestModelCapsAdmission(t *testing.T) {
	f := newLedger(t)
	for field := 0; field < reflect.TypeFor[ModelCaps]().NumField(); field++ {
		for _, delta := range []int64{-1, 1} {
			t.Run(reflect.TypeFor[ModelCaps]().Field(field).Name+map[int64]string{-1: "-smaller", 1: "-larger"}[delta], func(t *testing.T) {
				c := modelConfig(f, t)
				v := reflect.ValueOf(c.ModelCaps).Elem().Field(field)
				v.SetUint(uint64(int64(v.Uint()) + delta))
				assertModelConfigRefused(t, f, c, f.profile, "MODEL_CAPS_MISMATCH")
			})
		}
	}
	for _, mode := range []string{"missing-default", "missing-caps", "tampered-profile", "unsafe-browser-integer", "default-over-limit", "legacy-template"} {
		t.Run(mode, func(t *testing.T) {
			c := modelConfig(f, t)
			profile, want := f.profile, "TEMPLATE_MODEL_CAPS"
			switch mode {
			case "missing-default":
				c.Template.ModelCaps.DefaultMaxOutputTokens = 0
			case "missing-caps":
				c.Template.ModelCaps = nil
			case "tampered-profile":
				profile, want = []byte("altered profile"), "TEMPLATE_PROFILE_PIN"
			case "unsafe-browser-integer":
				c.Template.ModelCaps.CostNanoUSD = 1 << 53
			case "default-over-limit":
				c.Template.ModelCaps.DefaultMaxOutputTokens = c.Template.ModelCaps.MaxTokens + 1
			case "legacy-template":
				c.Template.Version = 1
			}
			c.TemplateSHA256 = Hash(canonical(c.Template))
			assertModelConfigRefused(t, f, c, profile, want)
		})
	}
	c := modelConfig(f, t)
	s, e := NewServiceV2(c, f.profile, f.provider, f.nodes, nil, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if e != nil {
		t.Fatal("valid signed caps refused", e)
	}
	s.Close()
}

func assertModelConfigRefused(t *testing.T, f *ledgerFixture, c ConfigV2, profile []byte, want string) {
	t.Helper()
	before := 0
	for _, n := range f.concrete {
		before += n.calls
	}
	s, e := NewServiceV2(c, profile, f.provider, f.nodes, nil, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if s != nil {
		s.Close()
	}
	if s != nil || e == nil || e.Error() != want {
		t.Fatalf("model config: want %s got %v", want, e)
	}
	after := 0
	for _, n := range f.concrete {
		after += n.calls
	}
	files, err := os.ReadDir(c.StateDir)
	if err != nil || len(files) != 0 || before != after {
		t.Fatal("model refusal had state/node effects", err)
	}
}

// The actual HTTP page, produced contract and signed consent use identical
// numbers; mutation invalidates consent and cannot alter persisted terms.
// Restart preserves the original contract bytes and the old non-model vectors
// continue to be checked by the existing wire tests.
func TestModelContractConsentAndPage(t *testing.T) {
	f := newLedger(t)
	f.s.Close()
	f.cfg = modelConfig(f, t)
	f.open(t)
	b := f.book(t, "slot0", "nmc")
	if !EqualModelCaps(b.Contract.ModelCaps, f.cfg.Template.ModelCaps) {
		t.Fatal("booking omitted signed model caps")
	}
	raw := b.Contract.Bytes()
	ev := ConsentV2(b.Contract, f.now)
	if e := ev.Sign(f.renter); e != nil {
		t.Fatal(e)
	}
	if e := CheckConsentV2(b.Contract, ev, b.HoldCreatedAt, b.HoldExpiresAt, f.now); e != nil {
		t.Fatal(e)
	}
	h, e := NewHTTPHandlerV2(f.s, "http://127.0.0.1:18819")
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18819/", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), b.Contract.ModelCaps.Text()) || !strings.Contains(w.Body.String(), `id="model-terms"`) {
		t.Fatal("page does not disclose exact signed caps")
	}
	b.Contract.ModelCaps.Requests++
	if e := CheckConsentV2(b.Contract, ev, b.HoldCreatedAt, b.HoldExpiresAt, f.now); e == nil {
		t.Fatal("changed caps retained consent")
	}
	stored, e := f.s.Get(b.Contract.BookingID)
	if e != nil || !bytes.Equal(raw, stored.Contract.Bytes()) {
		t.Fatal("returned cap pointer altered stored contract", e)
	}
	if _, e := f.s.AcceptConsent(context.Background(), stored.Contract.BookingID, ev); e != nil {
		t.Fatal(e)
	}
	f.s.Close()
	f.open(t)
	stored, e = f.s.Get(b.Contract.BookingID)
	if e != nil || !bytes.Equal(raw, stored.Contract.Bytes()) {
		t.Fatal("restart changed signed terms", e)
	}
}

// Caller-owned config and detached catalogue pointers cannot rewrite the
// validated template or any subsequently signed rental terms.
func TestModelCapsSnapshotOwnership(t *testing.T) {
	f := newLedger(t)
	f.s.Close()
	f.cfg = modelConfig(f, t)
	f.open(t)
	expected := *f.cfg.Template.ModelCaps
	f.cfg.Template.ModelCaps.Requests++
	f.cfg.ModelCaps.InputTokens++
	cat, e := f.s.Catalogue(f.now+86400, 16)
	if e != nil {
		t.Fatal(e)
	}
	if cat.Template.ModelCaps == nil || *cat.Template.ModelCaps != expected {
		t.Fatal("caller mutated service caps")
	}
	cat.Template.ModelCaps.CostNanoUSD++
	b := f.book(t, "slot0", "nmc")
	if b.Contract.ModelCaps == nil || *b.Contract.ModelCaps != expected {
		t.Fatal("catalogue mutated signed terms")
	}
}
