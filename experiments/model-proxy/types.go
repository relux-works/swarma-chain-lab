// Package modelproxy implements a bounded demo model gateway, not an identity
// authority. The local registrar supplies the approved booking/grant/window.
package modelproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/modelprofile"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
)

const MaxBody = 65536
const MaxRecords = 64
const MaxLive = 16
const MaxResponse = 8 << 20
const MaxEvent = 65536

type Secret string

func (Secret) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[private]") }
func (Secret) String() string             { return "[private]" }
func (Secret) GoString() string           { return "[private]" }
func fail(code string) error              { return errors.New(code) }
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func sum(b []byte) string            { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func privateCanonical(v any) []byte  { b, _ := json.Marshal(privateValue(v)); return b }
func add(a, b uint64) (uint64, bool) { c := a + b; return c, c >= a }
func mul(a, b uint64) (uint64, bool) {
	if b != 0 && a > ^uint64(0)/b {
		return 0, false
	}
	return a * b, true
}

// Prices are integer nano-USD per token. ContextTokens is the documented model
// context window, conservatively reserved as input on every generation attempt.
type Model = modelprofile.Model
type Caps struct {
	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`
	Requests     uint64 `json:"requests"`
	MaxTokens    uint64 `json:"max_tokens"`
	CostNanoUSD  uint64 `json:"cost_nano_usd"`
	// Signed future coding-profile default. Zero preserves old non-contract
	// bindings; the current Responses parser still requires an explicit limit.
	DefaultMaxOutputTokens uint64 `json:"default_max_output_tokens,omitempty"`
}

func (c Caps) Valid() bool {
	return c.InputTokens > 0 && c.OutputTokens > 0 && c.Requests > 0 && c.MaxTokens > 0 && c.MaxTokens <= c.OutputTokens && c.CostNanoUSD > 0 && c.DefaultMaxOutputTokens <= c.MaxTokens
}

type Binding struct {
	SlotID    string `json:"slot_id"`
	GrantID   string `json:"grant_id"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	Caps      Caps   `json:"caps"`
}

func (b Binding) Valid() bool {
	return digest(b.SlotID) && digest(b.GrantID) && b.NotBefore > 0 && b.NotAfter > b.NotBefore && b.NotAfter <= 1<<50 && b.NotAfter-b.NotBefore <= 3600 && b.Caps.Valid()
}

type Endpoint = modelprofile.Endpoint
type Credential struct {
	Bearer   codec.Secret[Secret] `json:"bearer"`
	Endpoint Endpoint             `json:"endpoint"`
}

func (Credential) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[private model credential]") }
func (Credential) String() string             { return "[private model credential]" }
func (Credential) GoString() string           { return "[private model credential]" }

type Usage struct {
	Input  uint64 `json:"input"`
	Output uint64 `json:"output"`
}
type Counts struct {
	Input    uint64 `json:"input"`
	Output   uint64 `json:"output"`
	Requests uint64 `json:"requests"`
	Cost     uint64 `json:"cost"`
}
type Status struct {
	Binding  Binding
	Phase    string
	Exposure Counts
	Observed Usage
	InFlight bool
}

// Audit carries no unrestricted strings supplied by a client or upstream.
type Audit struct {
	SlotID     string
	Code       string
	HTTPStatus int
	Usage      Usage
}
type Config struct {
	StateDir      string
	Endpoint      Endpoint
	Upstream      string
	APIKey        UpstreamKey
	Models        map[string]Model
	ModelProfiles map[string]ModelProfile
	Now           func() time.Time
	Timeout       time.Duration
	Transport     http.RoundTripper
	Dialect       Dialect
	Audit         func(Audit)
}

func validURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && !strings.Contains(raw, "#") && u.Opaque == "" && u.Host == strings.ToLower(u.Host) && u.String() == raw && u.RawPath == "" && !strings.HasSuffix(raw, "/")
}
func price(m Model, u Usage) (uint64, bool) {
	i, a := mul(m.InputNanoUSD, u.Input)
	o, b := mul(m.OutputNanoUSD, u.Output)
	n, c := add(i, o)
	return n, a && b && c
}

func validOrigin(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && validURL(raw) && u.Path == ""
}

// UpstreamKey keeps the operator key opaque until the authentication boundary.
// Generic encoders redact it; it is never part of the registry wire schema.
type UpstreamKey = codec.Secret[Secret]

func NewAPIKey(value Secret) UpstreamKey { return codec.NewSecret(value) }

// NewBearer protects a model bearer.
func NewBearer(value Secret) codec.Secret[Secret] { return codec.NewSecret(value) }

// Equal compares credential values, including independently decoded holders.
// Pointer identity is deliberately not part of the credential contract.
func (c Credential) Equal(other Credential) bool {
	return c.Endpoint == other.Endpoint && subtle.ConstantTimeCompare([]byte(c.Bearer.Reveal()), []byte(other.Bearer.Reveal())) == 1
}
