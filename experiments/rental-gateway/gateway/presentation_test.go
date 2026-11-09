package gateway_test

// V3 inline-presentation controls. The stub kernel doubles as the
// scripted Presenter: transport fixtures contain a marker grant,
// and the Handler scripts verdicts and
// records every envelope it was asked to Check, so cache behaviour
// is observable without a chain. The genuine-Core version of these
// flows lives in kernelbind's opt-in e2e.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// presScript makes the stub kernel decide by envelope marker:
//
//	"cert-revoked"      -> refused/SEAL_SPENT, Closed (revocation)
//	"cert-of-<pubkey>"  -> live only for that sender, else GRANTEE_MISMATCH
//	contains "REFUSED"  -> refused/STUB_REFUSED
//	anything else       -> live
//
// It records every checked envelope in order.
type presScript struct {
	mu      sync.Mutex
	checked []string
}

func (s *presScript) install(h *harness) {
	h.kern.Handler = func(ctx context.Context, env []byte, agentName, sender string, now int64) (kernel.Receipt, error) {
		s.mu.Lock()
		s.checked = append(s.checked, string(env))
		s.mu.Unlock()
		r := kernel.Receipt{Verdict: kernel.Live, Reason: "LIVE", AgentName: agentName, CheckedAt: now}
		var parsed struct {
			SignedGrant struct {
				Grant struct {
					Marker string `json:"marker"`
				} `json:"grant"`
			} `json:"signed_grant"`
		}
		_ = json.Unmarshal(env, &parsed)
		marker := parsed.SignedGrant.Grant.Marker
		switch {
		case marker == "cert-revoked":
			r.Verdict, r.Reason, r.Closed = kernel.Refused, "SEAL_SPENT", true
		case strings.HasPrefix(marker, "cert-of-") && strings.TrimPrefix(marker, "cert-of-") != sender:
			r.Verdict, r.Reason = kernel.Refused, "GRANTEE_MISMATCH"
		case strings.Contains(marker, "REFUSED"):
			r.Verdict, r.Reason = kernel.Refused, "STUB_REFUSED"
		}
		return r, nil
	}
}

func (s *presScript) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.checked) == 0 {
		return ""
	}
	return s.checked[len(s.checked)-1]
}

func wrapTagged(t *testing.T, sender *nostr.PrivKey, agentPub, content string, tags [][]string, at int64) *nostr.Event {
	t.Helper()
	wrap, _, err := nostr.WrapDM(sender, agentPub, content, tags, at)
	if err != nil {
		t.Fatal(err)
	}
	return wrap
}

func dmWithCert(t *testing.T, sender *nostr.PrivKey, agentPub, content string, cert []byte, at int64) *nostr.Event {
	t.Helper()
	return wrapTagged(t, sender, agentPub, content, [][]string{mustTag(t, cert)}, at)
}

func stationFor(t *testing.T, h *harness, slotID, stationName string) *stationlink.Client {
	t.Helper()
	c, err := dialStation(h)
	if err != nil {
		t.Fatal(err)
	}
	sys, err := c.Hello(slotID, stationName, h.slotSecret(slotID))
	if err != nil {
		t.Fatal(err)
	}
	if sys.Type != stationlink.TypeSystem {
		t.Fatalf("hello %s = %s %s, want system", slotID, sys.Type, sys.Reason)
	}
	return c
}

func hasDM(h *harness, priv *nostr.PrivKey, substr string) bool {
	for _, dm := range h.pub.dmsTo(priv) {
		if strings.Contains(dm, substr) {
			return true
		}
	}
	return false
}

// TestPresentationFirstMessageAndLazyStart proves: no bytes known
// -> presentation_required + deterministic notice + rumor id not
// burned; first tagged message Presents, lazily starts the
// instance and delivers content only (tag stripped); the next
// untagged message rides the cached bytes with a fresh Check and
// no second Present.
func TestPresentationFirstMessageAndLazyStart(t *testing.T) {
	h := newHarness(t, harnessOpts{presenter: true, noCert: true, skipStart: true})
	script := &presScript{}
	script.install(h)
	cert := markerPresentation("cert-of-" + h.renter.PubKeyHex())

	plain := h.renterDM("too early", nowMid)
	res := h.handle(plain)
	if !res.Refused || res.Reason != "kernel_refused:presentation_required" || !res.WarningSent {
		t.Fatalf("untagged first = %+v, want presentation_required + notice", res)
	}
	if !hasDM(h, h.renter, "presentation required:") {
		t.Fatal("deterministic presentation_required notice not sent")
	}
	res = h.handle(plain) // identical bytes again: id must not be burned
	if !res.Refused || res.Reason != "kernel_refused:presentation_required" {
		t.Fatalf("untagged replay = %+v, want presentation_required again (id burned?)", res)
	}
	if slot, _ := h.store.Get("slot-1"); slot.Started {
		t.Fatal("station started before any live presentation")
	}

	res = h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "first real", cert, nowMid))
	if !res.Delivered {
		t.Fatalf("presented first message = %+v, want delivered", res)
	}
	if h.kern.PresentCalls != 1 {
		t.Fatalf("PresentCalls = %d, want 1", h.kern.PresentCalls)
	}
	if slot, _ := h.store.Get("slot-1"); !slot.Started || slot.StationHome == "" {
		t.Fatalf("lazy start missing: %+v", slot)
	}
	c := stationFor(t, h, "slot-1", "id/swarma-station-1")
	f := pull(t, c)
	if f.Type != stationlink.TypeDeliver || f.Content != "first real" {
		t.Fatalf("station got %+v, want content-only delivery (tag stripped)", f)
	}

	res = h.handle(h.renterDM("second plain", nowMid))
	if !res.Delivered {
		t.Fatalf("untagged after presentation = %+v, want delivered via cache", res)
	}
	if h.kern.PresentCalls != 1 || script.last() != string(cert) {
		t.Fatalf("cache path wrong: PresentCalls=%d lastChecked=%q", h.kern.PresentCalls, script.last())
	}
	if f := pull(t, c); f.Content != "second plain" {
		t.Fatalf("station got %+v, want second message", f)
	}
}

// TestPresentationParallelGrantees proves two grantees present in
// parallel and are routed to separate station instances (distinct
// homes, distinct queues), each seeing only its own traffic.
func TestPresentationParallelGrantees(t *testing.T) {
	h := newHarness(t, harnessOpts{presenter: true, noCert: true, skipStart: true})
	script := &presScript{}
	script.install(h)
	renter2, _ := nostr.GeneratePrivKey()
	if err := h.gw.RegisterSlot(gateway.SlotSpec{
		ID: "slot-2", StationName: "id/swarma-station-2",
		RenterPubKey: renter2.PubKeyHex(), ContractSHA256: strings.Repeat("b", 64),
		NotBefore: slotNotBefore, NotAfter: slotNotAfter,
	}); err != nil {
		t.Fatal(err)
	}
	res1 := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "for one",
		markerPresentation("cert-of-"+h.renter.PubKeyHex()), nowMid))
	res2 := h.handle(dmWithCert(t, renter2, h.agent.PubKeyHex(), "for two",
		markerPresentation("cert-of-"+renter2.PubKeyHex()), nowMid))
	if !res1.Delivered || !res2.Delivered || res1.SlotID != "slot-1" || res2.SlotID != "slot-2" {
		t.Fatalf("parallel presentations = %+v / %+v", res1, res2)
	}
	s1, _ := h.store.Get("slot-1")
	s2, _ := h.store.Get("slot-2")
	if !s1.Started || !s2.Started || s1.StationHome == "" || s1.StationHome == s2.StationHome {
		t.Fatalf("instances not separate: %q vs %q", s1.StationHome, s2.StationHome)
	}
	c1 := stationFor(t, h, "slot-1", "id/swarma-station-1")
	c2 := stationFor(t, h, "slot-2", "id/swarma-station-2")
	if f := pull(t, c1); f.Content != "for one" {
		t.Fatalf("station 1 got %+v", f)
	}
	if f := pull(t, c2); f.Content != "for two" {
		t.Fatalf("station 2 got %+v", f)
	}
	// Cross-traffic stays separated on the cached path too.
	if res := h.handle(wrapTagged(t, renter2, h.agent.PubKeyHex(), "two again", nil, nowMid)); !res.Delivered {
		t.Fatalf("renter2 cached follow-up = %+v", res)
	}
	if f := pull(t, c2); f.Content != "two again" {
		t.Fatalf("station 2 got %+v", f)
	}
	if f := pull(t, c1); f.Type != stationlink.TypeNone {
		t.Fatalf("station 1 leaked other grantee traffic: %+v", f)
	}
}

// TestPresentationForeignCertificateRefused proves a sender
// presenting another grantee's certificate is refused by the
// kernel identity binding, with a deterministic notice, no start,
// and a valid own presentation still works afterwards.
func TestPresentationForeignCertificateRefused(t *testing.T) {
	h := newHarness(t, harnessOpts{presenter: true, noCert: true, skipStart: true})
	script := &presScript{}
	script.install(h)
	other, _ := nostr.GeneratePrivKey()

	res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "borrowed cert",
		markerPresentation("cert-of-"+other.PubKeyHex()), nowMid))
	if !res.Refused || res.Reason != "kernel_refused:GRANTEE_MISMATCH" || !res.WarningSent {
		t.Fatalf("foreign cert = %+v, want GRANTEE_MISMATCH + notice", res)
	}
	if !hasDM(h, h.renter, "presentation refused: refused:GRANTEE_MISMATCH") {
		t.Fatal("deterministic refusal notice not sent")
	}
	if slot, _ := h.store.Get("slot-1"); slot.Started {
		t.Fatal("station started on a foreign certificate")
	}
	res = h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "my own cert",
		markerPresentation("cert-of-"+h.renter.PubKeyHex()), nowMid))
	if !res.Delivered {
		t.Fatalf("valid neighbour after foreign refusal = %+v", res)
	}
}

// TestPresentationRevokedCertificateRefused proves a revoked
// certificate in the first message is refused with kernel closure:
// the slot ends, nothing starts, nothing is delivered.
func TestPresentationRevokedCertificateRefused(t *testing.T) {
	h := newHarness(t, harnessOpts{presenter: true, noCert: true, skipStart: true})
	script := &presScript{}
	script.install(h)

	res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "revoked hello",
		markerPresentation("cert-revoked"), nowMid))
	if !res.Refused || !res.SlotEnded || res.Reason != "kernel_closed:SEAL_SPENT" {
		t.Fatalf("revoked presentation = %+v, want kernel_closed:SEAL_SPENT", res)
	}
	slot, _ := h.store.Get("slot-1")
	if !slot.Ended || slot.Started {
		t.Fatalf("slot state after revoked presentation: %+v", slot)
	}
}

// TestPresentationReplacementOnlyIfLive proves a different
// certificate for the same sender replaces the cached bytes only
// when it presents live; a refused replacement leaves the cached
// bytes authoritative for later Checks.
func TestPresentationReplacementOnlyIfLive(t *testing.T) {
	h := newHarness(t, harnessOpts{presenter: true, noCert: true, skipStart: true})
	script := &presScript{}
	script.install(h)
	me := h.renter.PubKeyHex()
	certA := markerPresentation("cert-of-" + me)
	badB := markerPresentation("cert-of-" + me + "-REFUSED")
	certB := markerPresentation("cert-B-live") // distinct live bytes for the same sender

	if res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "with A", certA, nowMid)); !res.Delivered {
		t.Fatalf("present A = %+v", res)
	}
	if res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "with bad B", badB, nowMid)); !res.Refused {
		t.Fatalf("present refused-B = %+v, want refused", res)
	}
	if res := h.handle(h.renterDM("still A?", nowMid)); !res.Delivered {
		t.Fatalf("follow-up after refused replacement = %+v", res)
	}
	if got := script.last(); got != string(certA) {
		t.Fatalf("cache replaced by refused presentation: last checked %q, want A", got)
	}
	if res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "with B", certB, nowMid)); !res.Delivered {
		t.Fatalf("present live B = %+v", res)
	}
	if res := h.handle(h.renterDM("now B?", nowMid)); !res.Delivered {
		t.Fatalf("follow-up after live replacement = %+v", res)
	}
	if got := script.last(); got != string(certB) {
		t.Fatalf("live replacement not cached: last checked %q, want B", got)
	}
}

// TestPresentationCacheFullRefuses proves a full presentation
// cache refuses a new sender (kernel capacity is 64; the stub is
// shrunk to 1 to exercise the same gate) while the admitted sender
// keeps working.
func TestPresentationCacheFullRefuses(t *testing.T) {
	h := newHarness(t, harnessOpts{presenter: true, noCert: true, skipStart: true})
	script := &presScript{}
	script.install(h)
	h.kern.PresentCapacity = 1
	renter2, _ := nostr.GeneratePrivKey()
	if err := h.gw.RegisterSlot(gateway.SlotSpec{
		ID: "slot-2", StationName: "id/swarma-station-2",
		RenterPubKey: renter2.PubKeyHex(), ContractSHA256: strings.Repeat("b", 64),
		NotBefore: slotNotBefore, NotAfter: slotNotAfter,
	}); err != nil {
		t.Fatal(err)
	}
	if res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "first in",
		markerPresentation("cert-of-"+h.renter.PubKeyHex()), nowMid)); !res.Delivered {
		t.Fatalf("first presentation = %+v", res)
	}
	res := h.handle(dmWithCert(t, renter2, h.agent.PubKeyHex(), "cache is full",
		markerPresentation("cert-of-"+renter2.PubKeyHex()), nowMid))
	if !res.Refused || res.Reason != "kernel_refused:PRESENTATION_CACHE_FULL" || !res.WarningSent {
		t.Fatalf("full-cache presentation = %+v, want PRESENTATION_CACHE_FULL + notice", res)
	}
	if res := h.handle(h.renterDM("still in", nowMid)); !res.Delivered {
		t.Fatalf("admitted sender after full refusal = %+v", res)
	}
}

// TestPresentationMalformedVariants proves every malformed shape
// refuses before screening with no strike and a deterministic
// notice, and a valid presentation still delivers afterwards.
func TestPresentationMalformedVariants(t *testing.T) {
	h := newHarness(t, harnessOpts{presenter: true, noCert: true, skipStart: true})
	script := &presScript{}
	script.install(h)
	cert := markerPresentation("cert-of-" + h.renter.PubKeyHex())
	good := mustTag(t, cert)
	badID := append([]string(nil), good...)
	badID[1] = strings.Repeat("0", 64)
	badJSON := []string{"grant-cert", good[1], base64.StdEncoding.EncodeToString([]byte("not JSON"))}
	legacy := []string{"grant-cert", good[1], base64.StdEncoding.EncodeToString([]byte(`{"certificate":{"version":2}}`))}
	variants := [][][]string{
		{badJSON}, {legacy},
		{good, good},                     // two tags
		{badID},                          // id != stable signed-grant hash
		{{"grant-cert", good[1], "!!!"}}, // bad base64
		{{"grant-cert", good[1]}},        // wrong arity
		{{"grant-cert", "XYZ", good[2]}}, // bad id form
		{{"grant-cert", good[1], base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 17000)))}}, // oversize
	}
	for i, tags := range variants {
		wrapped := wrapTagged(t, h.renter, h.agent.PubKeyHex(), "malformed", tags, nowMid)
		res := h.handle(wrapped)
		if !res.Refused || res.Reason != "presentation_malformed" || !res.WarningSent {
			t.Fatalf("variant %d = %+v, want presentation_malformed + notice", i, res)
		}
		if replay := h.handle(wrapped); replay.Reason != "presentation_malformed" {
			t.Fatalf("malformed replay burned id: %+v", replay)
		}
	}
	if h.kern.Calls != 0 || h.kern.PresentCalls != 0 || h.scr.Calls != 0 {
		t.Fatal("malformed presentation reached kernel or screening")
	}
	if slot, _ := h.store.Get("slot-1"); slot.Refusals != 0 {
		t.Fatalf("malformed presentations spent strikes: %d", slot.Refusals)
	}
	if !hasDM(h, h.renter, "presentation refused: malformed grant-cert tag") {
		t.Fatal("deterministic malformed notice not sent")
	}
	if res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "now proper", cert, nowMid)); !res.Delivered {
		t.Fatalf("valid neighbour after malformed flood = %+v", res)
	}
}

// TestPresentationUnsupportedWithoutPresenter proves a gateway
// with no Presenter wired refuses a grant-cert tag
// deterministically and still serves the stored-certificate path.
func TestPresentationUnsupportedWithoutPresenter(t *testing.T) {
	h := newHarness(t, harnessOpts{}) // stored cert, started, no presenter
	res := h.handle(dmWithCert(t, h.renter, h.agent.PubKeyHex(), "tagged anyway",
		markerPresentation("cert-of-"+h.renter.PubKeyHex()), nowMid))
	if !res.Refused || res.Reason != "presentation_unsupported" || !res.WarningSent {
		t.Fatalf("tagged without presenter = %+v, want presentation_unsupported + notice", res)
	}
	if res := h.handle(h.renterDM("plain still works", nowMid)); !res.Delivered {
		t.Fatalf("stored-cert neighbour = %+v", res)
	}
}

// markerPresentation is a transport fixture only. Its placeholder signature
// never reaches the real kernel; genuine signed grants are tested in kernelbind.
func markerPresentation(marker string) []byte {
	b, _ := json.Marshal(marker)
	return []byte(`{"signed_grant":{"grant":{"version":3,"marker":` + string(b) + `},"signature":"` + strings.Repeat("a", 128) + `"},"issuance":{"txid":"` + strings.Repeat("b", 64) + `"}}`)
}

func mustTag(t *testing.T, raw []byte) []string {
	t.Helper()
	tag, err := gateway.GrantCertTag(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tag
}
