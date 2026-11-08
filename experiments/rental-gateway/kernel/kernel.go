// Package kernel is the gateway's boundary to the M1 grant kernel.
// It mirrors the frozen interface in grants-dev/m1/INTERFACE.md
// (sha256 49f7942d…): Check(ctx, envelopeBytes, stationName,
// senderPubkey, nowUnix) with verdicts live/pending/refused, of which
// only live admits. senderPubkey must be the authenticated NIP-17
// inner seal key; the gateway enforces that at its side of the call.
package kernel

import "context"

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

// Checker is the gateway-side kernel interface. The real M1 kernel
// never returns an error (every failure is a refused/pending
// receipt); the error return exists for stubs and transport adapters,
// and the gateway treats any error as a refusal.
type Checker interface {
	Check(ctx context.Context, envelopeBytes []byte, stationName, senderPubkey string, nowUnix int64) (Receipt, error)
}

// Stub is a scripted Checker for unit tests that do not need a chain.
type Stub struct {
	// Verdict/Reason are returned when Handler and Err are unset.
	Verdict string
	Reason  string
	Err     error
	Scope   []string
	// Handler, when set, fully controls the answer (per-sender scripts,
	// call counting in tests via closure).
	Handler func(ctx context.Context, envelopeBytes []byte, stationName, senderPubkey string, nowUnix int64) (Receipt, error)
	Calls   int
}

// Check implements Checker.
func (s *Stub) Check(ctx context.Context, envelopeBytes []byte, stationName, senderPubkey string, nowUnix int64) (Receipt, error) {
	s.Calls++
	if s.Handler != nil {
		return s.Handler(ctx, envelopeBytes, stationName, senderPubkey, nowUnix)
	}
	if s.Err != nil {
		return Receipt{Verdict: Refused, Reason: "stub error"}, s.Err
	}
	v := s.Verdict
	if v == "" {
		v = Live
	}
	return Receipt{
		Verdict: v, Reason: s.Reason, StationName: stationName,
		CheckedAt: nowUnix, Scope: s.Scope,
	}, nil
}
