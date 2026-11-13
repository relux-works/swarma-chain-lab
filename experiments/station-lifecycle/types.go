// Package lifecycle implements the demo station-lifecycle role of the platform
// user manager and curator-run. It has no gateway, relay or a2a dependency.
package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"strconv"
	"time"
)

const MaxLive = 16
const MaxRetained = 64
const MaxBody = 65536

// Range bounds the broker's numeric namespace. Numbers are canonical decimal;
// aliases such as 01 refuse, and terminal records are never recycled.
type Range struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}
type Secret []byte

func (Secret) String() string   { return "[private bootstrap]" }
func (Secret) GoString() string { return "[private bootstrap]" }

type Slot struct {
	Version       int          `json:"version"`
	ID            string       `json:"slot"`
	GrantID       string       `json:"grant_id"`
	NotBefore     int64        `json:"not_before"`
	NotAfter      int64        `json:"not_after"`
	PayloadID     string       `json:"payload_id"`
	PayloadSHA256 string       `json:"payload_sha256"`
	Bootstrap     PrivateBytes `json:"bootstrap"`
}

func (s Slot) String() string   { return "slot:" + s.ID }
func (s Slot) GoString() string { return s.String() }

type Status struct {
	SlotID   string `json:"slot"`
	Binding  string `json:"binding"`
	Phase    string `json:"phase"`
	Reason   string `json:"reason"`
	NotAfter int64  `json:"not_after"`
}
type API interface {
	Start(context.Context, Slot) (Status, error)
	Stop(context.Context, string) (Status, error)
	Status(context.Context, string) (Status, error)
}

// Payload pins a local operator label and the hash reported by the helper.
// No executable, argv or root-owned execution policy is accepted remotely.
type Payload struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

// Host is the typed slotd r4 helper boundary. Tests use explicit fakes; the
// adapter has no shell/OS executor or authority to alter helper policy.
type Host interface {
	Start(context.Context, Slot, func(CreateFence) error) error
	// allowAbsent is true only when durable state proves no Start attempt;
	// a recorded host-local fence can separately establish a later safe probe.
	Stop(context.Context, Slot, bool, *CreateFence) error
	Status(context.Context, Slot) (string, error)
}
type Config struct {
	StateDir     string
	Range        Range
	Payload      Payload
	Host         Host
	Now          func() time.Time
	StepTimeout  time.Duration
	TickInterval time.Duration
}

func fail(code string) error { return errors.New(code) }
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func label(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func privateCanonical(v any) []byte { b, _ := json.Marshal(privateValue(v)); return b }
func hash(b []byte) string          { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func strict(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > MaxBody {
		return fail("ENCODING")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !bytes.Equal(raw, privateCanonical(v)) {
		return fail("ENCODING")
	}
	return nil
}
func (r Range) valid() bool { return r.Last >= r.First && r.Last <= 9999 }
func (r Range) contains(id string) bool {
	n, e := strconv.Atoi(id)
	return e == nil && strconv.Itoa(n) == id && n >= int(r.First) && n <= int(r.Last)
}
func (r Range) validateSlot(s Slot) error {
	if s.Version != 1 || !r.contains(s.ID) || !digest(s.GrantID) || s.NotBefore < 1 || s.NotAfter <= s.NotBefore || s.NotAfter-s.NotBefore > 3600 || (len(s.Bootstrap.Reveal()) < 1 || len(s.Bootstrap.Reveal()) > 4096) || !label(s.PayloadID) || !digest(s.PayloadSHA256) {
		return fail("SLOT_POLICY")
	}
	return nil
}
