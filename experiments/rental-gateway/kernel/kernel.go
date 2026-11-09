// Package kernel is the gateway's boundary to the grant kernel.
// Originally it mirrored the frozen M1 v1 interface; since M1-04
// (detached grants, LIP-0003) it binds the landed v2 surface:
// Check / Present / CachedCertificate over detached certificate
// envelopes, with verdicts live/pending/refused of which only live
// admits. senderPubkey must be the authenticated NIP-17 inner seal
// key; the gateway enforces that at its side of the call. The name
// argument is the rented agent's pinned name (Policy.AgentName);
// the v1 station-name slot is gone from the kernel contract (the
// receipt's StationName field carries the agent name in v2).
package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// Verdict values, spelled exactly as in the frozen M1 receipt.
const (
	Live    = "live"
	Pending = "pending"
	Refused = "refused"
)

// Receipt mirrors the frozen rental.Receipt fields the gateway uses.
// Scope and BudgetSat are authenticated data, never effect authority:
// the gateway must not judge action scope (architecture R3).
type Receipt struct {
	Verdict           string   `json:"verdict"`
	Reason            string   `json:"reason"`
	CertificateSHA256 string   `json:"certificate_sha256"`
	StationName       string   `json:"station_name"`
	CheckedAt         int64    `json:"checked_at"`
	Closed            bool     `json:"closed"`
	Scope             []string `json:"scope"`
	BudgetSat         int64    `json:"budget_sat"`
}

// Admits reports whether this receipt admits. Only live admits.
func (r Receipt) Admits() bool { return r.Verdict == Live }

// Checker is the gateway-side kernel interface. The real kernel
// never returns an error (every failure is a refused/pending
// receipt); the error return exists for stubs and transport adapters,
// and the gateway treats any error as a refusal.
type Checker interface {
	Check(ctx context.Context, envelopeBytes []byte, agentName, senderPubkey string, nowUnix int64) (Receipt, error)
}

// ErrNoPresentation reports that a sender has no cached presented
// certificate bytes: its next message must present one inline.
var ErrNoPresentation = errors.New("kernel: no cached presentation")

// Presenter is the inline-presentation half of the kernel boundary
// (detached grants): Present runs a fresh Check and, only on a live
// verdict, admits the envelope into the kernel's bounded live-only
// per-sender cache (a different certificate for the same sender
// replaces the cached one only by presenting live). CachedCertificate
// returns cached public bytes — never a verdict; every message
// still needs a fresh Check against them. id is the lowercase hex
// SHA-256 of the exact envelope bytes.
type Presenter interface {
	Present(ctx context.Context, envelopeBytes []byte, id, agentName, senderPubkey string, nowUnix int64) (Receipt, error)
	CachedCertificate(senderPubkey string) ([]byte, error)
}

// Stub is a scripted Checker (+ Presenter) for unit tests that do
// not need a chain.
type Stub struct {
	// Verdict/Reason are returned when Handler and Err are unset.
	Verdict string
	Reason  string
	Err     error
	Scope   []string
	// Handler, when set, fully controls the answer (per-sender scripts,
	// call counting in tests via closure).
	Handler func(ctx context.Context, envelopeBytes []byte, agentName, senderPubkey string, nowUnix int64) (Receipt, error)
	// PresentHandler, when set, fully controls Present; otherwise
	// the stub mirrors the kernel contract: id must be the SHA-256
	// of the bytes, the Check script decides, and only a live
	// verdict stores/replaces the sender's cached bytes, bounded by
	// PresentCapacity distinct senders (default 64, like the kernel).
	PresentHandler  func(ctx context.Context, envelopeBytes []byte, id, agentName, senderPubkey string, nowUnix int64) (Receipt, error)
	PresentCapacity int
	Calls           int
	PresentCalls    int
	Cached          map[string][]byte // sender -> presented bytes (seedable by tests)
	mu              sync.Mutex
}

// Check implements Checker.
func (s *Stub) Check(ctx context.Context, envelopeBytes []byte, agentName, senderPubkey string, nowUnix int64) (Receipt, error) {
	s.mu.Lock()
	s.Calls++
	s.mu.Unlock()
	if s.Handler != nil {
		return s.Handler(ctx, envelopeBytes, agentName, senderPubkey, nowUnix)
	}
	if s.Err != nil {
		return Receipt{Verdict: Refused, Reason: "stub error"}, s.Err
	}
	v := s.Verdict
	if v == "" {
		v = Live
	}
	return Receipt{
		Verdict: v, Reason: s.Reason, StationName: agentName,
		CheckedAt: nowUnix, Scope: s.Scope,
	}, nil
}

// Present implements Presenter (see the contract on Stub above).
func (s *Stub) Present(ctx context.Context, envelopeBytes []byte, id, agentName, senderPubkey string, nowUnix int64) (Receipt, error) {
	s.mu.Lock()
	s.PresentCalls++
	s.mu.Unlock()
	if s.PresentHandler != nil {
		return s.PresentHandler(ctx, envelopeBytes, id, agentName, senderPubkey, nowUnix)
	}
	sum := sha256.Sum256(envelopeBytes)
	if len(envelopeBytes) == 0 || len(envelopeBytes) > 16384 || hex.EncodeToString(sum[:]) != id {
		return Receipt{Verdict: Refused, Reason: "PRESENTATION_ID",
			CertificateSHA256: id, StationName: agentName, CheckedAt: nowUnix}, nil
	}
	r, err := s.Check(ctx, envelopeBytes, agentName, senderPubkey, nowUnix)
	if err != nil || !r.Admits() {
		return r, err
	}
	capacity := s.PresentCapacity
	if capacity <= 0 {
		capacity = 64
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Cached == nil {
		s.Cached = map[string][]byte{}
	}
	if _, ok := s.Cached[senderPubkey]; !ok && len(s.Cached) >= capacity {
		r.Verdict, r.Reason = Refused, "PRESENTATION_CACHE_FULL"
		return r, nil
	}
	s.Cached[senderPubkey] = append([]byte(nil), envelopeBytes...)
	return r, nil
}

// CachedCertificate implements Presenter.
func (s *Stub) CachedCertificate(senderPubkey string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.Cached[senderPubkey]
	if !ok {
		return nil, ErrNoPresentation
	}
	return append([]byte(nil), raw...), nil
}
