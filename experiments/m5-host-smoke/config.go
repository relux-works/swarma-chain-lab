// Package smoke drives installed rental services as an unprivileged client.
// Host assertions that require custody or privileged access are explicitly
// operator-attested; this package never turns those claims into independent proof.
package smoke

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"time"

	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
)

type Code string

func (c Code) Error() string { return string(c) }
func refuse(s string) error  { return Code(s) }
func code(e error) string {
	var c Code
	if errors.As(e, &c) {
		return string(c)
	}
	return "INTERNAL"
}
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

var label = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,95}$`)

// Config contains public, reviewed pins only. Endpoints must not embed secrets.
// EvidenceSHA256 identifies Infra's independently reviewed sanitized manifest
// (release signature, binary/helper/config hashes and host metadata).
type Config struct {
	Scenario          string   `json:"scenario"`
	Relay             string   `json:"relay"`
	Booking           string   `json:"booking"`
	AgentPubkey       string   `json:"agent_pubkey"`
	IssuerPubkey      string   `json:"issuer_pubkey"`
	AgentName         string   `json:"agent_name"`
	LandlordName      string   `json:"landlord_name"`
	TemplateSHA256    string   `json:"template_sha256"`
	ProfileSHA256     string   `json:"profile_sha256"`
	ProfileID         string   `json:"profile_id"`
	ProfileVersion    string   `json:"profile_version"`
	PayloadSHA256     string   `json:"payload_sha256"`
	EvidenceSHA256    string   `json:"evidence_sha256"`
	EnvironmentSHA256 string   `json:"environment_sha256"`
	Allowed           []string `json:"allowed"`
	Forbidden         []string `json:"forbidden"`
	BudgetSat         int64    `json:"budget_sat"`
	NotBefore         int64    `json:"not_before"`
	NotAfter          int64    `json:"not_after"`
}

type profile struct {
	mode, template, slot string
	price, window, depth int64
	pow, requests        int
	pace                 time.Duration
}

func host() profile {
	return profile{"host", "demo-60", "demo-60", 1000, 3600, 1, 16, 200, 10 * time.Second}
}
func rehearsal(c Config) profile {
	return profile{"self-test", "demo", "one", 100, c.NotAfter - c.NotBefore, 2, 4, 2, 0}
}
func (c Config) validate(p profile) error {
	if c.Scenario != "expiry" && c.Scenario != "revoke" {
		return refuse("CONFIG_SCENARIO")
	}
	for _, s := range []string{c.AgentPubkey, c.IssuerPubkey, c.TemplateSHA256, c.ProfileSHA256, c.EvidenceSHA256, c.EnvironmentSHA256, c.PayloadSHA256} {
		if !digest(s) {
			return refuse("CONFIG_PIN")
		}
	}
	for _, s := range []string{c.AgentName, c.LandlordName, c.ProfileID, c.ProfileVersion} {
		if !label.MatchString(s) {
			return refuse("CONFIG_LABEL")
		}
	}
	if c.AgentName == c.LandlordName || c.BudgetSat < 0 || c.NotBefore <= time.Now().Unix() || c.NotAfter-c.NotBefore != p.window || p.window <= 0 || p.window > 3600 {
		return refuse("CONFIG_WINDOW")
	}
	for _, set := range [][]string{c.Allowed, c.Forbidden} {
		for _, s := range set {
			if !label.MatchString(s) {
				return refuse("CONFIG_SCOPE")
			}
		}
	}
	if !endpoint(c.Relay, true) || !endpoint(c.Booking, false) {
		return refuse("CONFIG_ENDPOINT")
	}
	return nil
}
func endpoint(s string, relay bool) bool {
	u, e := url.Parse(s)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	secure, plain := "https", "http"
	if relay {
		secure, plain = "wss", "ws"
	}
	if u.Scheme == secure {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == plain && ip != nil && ip.IsLoopback()
}
func encode(v any) []byte { b, _ := json.Marshal(v); return b }
func freshID() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", refuse("RANDOM")
	}
	return hex.EncodeToString(b), nil
}

// Strict rejects duplicate keys, null, unknown fields and trailing JSON. No raw
// parser errors escape: rejected input may contain credentials or hostile text.
func Strict(b []byte, v any) error {
	if len(b) == 0 || len(b) > 256<<10 {
		return refuse("JSON_SIZE")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if e := tokens(d); e != nil {
		return refuse("JSON_SHAPE")
	}
	if _, e := d.Token(); e != io.EOF {
		return refuse("JSON_TRAILING")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return refuse("JSON_SCHEMA")
	}
	return nil
}
func tokens(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	if t == nil {
		return refuse("NULL")
	}
	if v, ok := t.(json.Delim); ok {
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return refuse("DUPLICATE")
				}
				seen[s] = true
				if e = tokens(d); e != nil {
					return e
				}
			}
			t, e = d.Token()
			if e != nil || t != json.Delim('}') {
				return refuse("OBJECT")
			}
		case '[':
			for d.More() {
				if e = tokens(d); e != nil {
					return e
				}
			}
			t, e = d.Token()
			if e != nil || t != json.Delim(']') {
				return refuse("ARRAY")
			}
		default:
			return refuse("DELIMITER")
		}
	}
	return nil
}
func same(a, b any) bool { return bytes.Equal(encode(a), encode(b)) }
func privacy() string    { return booking.Hash([]byte(booking.PrivacyNotice)) }
