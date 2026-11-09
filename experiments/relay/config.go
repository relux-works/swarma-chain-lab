// Package relay serves the bounded regular-event Nostr subset used by rental
// messaging. It has no wallet, decryption, model or public administrative API.
package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
)

const (
	maxFilters             = 4
	maxFilterBytes         = 16384
	maxSubscriptionIDBytes = 64
	// Compact outer framing: brackets, maximally escaped command and ID, commas.
	// Whitespace inside each filter is already counted in maxFilterBytes; extra
	// outer whitespace remains subject to the configured WebSocket read limit.
	maxRequestBytes int64 = 2 + (2 + 6*int64(len("REQ"))) + (2 + 6*maxSubscriptionIDBytes) + (maxFilters + 1) + maxFilters*maxFilterBytes
)

func (c Config) websocketReadLimit() int64 { return int64(c.MaxEventBytes) + 1024 }

type Config struct {
	StateDir              string   `json:"state_dir"`
	PublicURL             string   `json:"public_url"`
	TrustedProxyIP        string   `json:"trusted_proxy_ip"`
	RequireWriteAuth      bool     `json:"require_write_auth"`
	RequireReadAuth       bool     `json:"require_read_auth"`
	RestrictGiftWrapReads bool     `json:"restrict_gift_wrap_reads"`
	UnknownPowBits        int      `json:"unknown_pow_bits"`
	KnownPubkeys          []string `json:"known_pubkeys"`
	MaxEventBytes         int      `json:"max_event_bytes"`
	MaxEvents             int      `json:"max_events"`
	MaxStoreBytes         int      `json:"max_store_bytes"`
	RetentionSeconds      int64    `json:"retention_seconds"`
	FutureSeconds         int64    `json:"future_seconds"`
	MaxConnections        int      `json:"max_connections"`
	MaxConnectionsPerIP   int      `json:"max_connections_per_ip"`
	MaxIPs                int      `json:"max_ips"`
	FramesPerMinute       int      `json:"frames_per_minute"`
	FramesPerIPMinute     int      `json:"frames_per_ip_minute"`
	Subscriptions         int      `json:"subscriptions"`
	Queue                 int      `json:"queue"`
	Backlog               int      `json:"backlog"`
}

func Defaults(root, publicURL string) Config {
	return Config{StateDir: root, PublicURL: publicURL, KnownPubkeys: []string{}, MaxEventBytes: 65536, MaxEvents: 1024, MaxStoreBytes: 32 << 20, RetentionSeconds: 7 * 86400, FutureSeconds: 300, MaxConnections: 32, MaxConnectionsPerIP: 8, MaxIPs: 1024, FramesPerMinute: 120, FramesPerIPMinute: 600, Subscriptions: 8, Queue: 64, Backlog: 32}
}
func fail(code string) error { return errors.New(code) }
func hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (c Config) Validate() error {
	u, e := url.Parse(c.PublicURL)
	if e != nil || strings.Contains(c.PublicURL, "PLACEHOLDER") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Host == "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "wss" && !(u.Scheme == "ws" && u.Hostname() == "127.0.0.1")) {
		return fail("CONFIG_URL")
	}
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir {
		return fail("CONFIG_STATE")
	}
	if c.TrustedProxyIP != "" {
		ip, e := netip.ParseAddr(c.TrustedProxyIP)
		if e != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != c.TrustedProxyIP {
			return fail("CONFIG_PROXY")
		}
	}
	if c.UnknownPowBits < 0 || c.UnknownPowBits > 32 || len(c.KnownPubkeys) > 256 {
		return fail("CONFIG_POLICY")
	}
	seen := map[string]bool{}
	for _, key := range c.KnownPubkeys {
		if !hex(key, 64) || seen[key] {
			return fail("CONFIG_POLICY")
		}
		seen[key] = true
	}
	if c.MaxEventBytes < 1024 || c.MaxEventBytes > 131072 || c.MaxEvents < 1 || c.MaxEvents > 4096 || c.MaxStoreBytes < c.MaxEventBytes+1024 || c.MaxStoreBytes > 64<<20 || c.RetentionSeconds < 1 || c.RetentionSeconds > 30*86400 || c.FutureSeconds < 0 || c.FutureSeconds > 600 || c.MaxConnections < 1 || c.MaxConnections > 128 || c.MaxConnectionsPerIP < 1 || c.MaxConnectionsPerIP > c.MaxConnections || c.MaxIPs < c.MaxConnections || c.MaxIPs > 8192 || c.FramesPerMinute < 1 || c.FramesPerMinute > 10000 || c.FramesPerIPMinute < c.FramesPerMinute || c.FramesPerIPMinute > 100000 || c.Subscriptions < 1 || c.Subscriptions > 32 || c.Queue < 3 || c.Queue > 1024 || c.Backlog < 1 || c.Backlog > c.Queue-2 || int64(c.MaxConnections)*int64(c.Queue)*int64(c.MaxEventBytes) > 256<<20 {
		return fail("CONFIG_LIMIT")
	}
	if c.websocketReadLimit() < maxRequestBytes {
		return fail("CONFIG_LIMIT")
	}
	return nil
}

// Strict refuses duplicate object keys, nulls and trailing values at every
// level before typed decoding; public input errors never contain input bytes.
func strict(raw []byte, v any) error {
	if !json.Valid(raw) {
		return fail("JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, e := d.Token()
		if e != nil || tok == nil {
			return fail("JSON")
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				s = strings.ToLower(s)
				if e != nil || !ok || seen[s] {
					return fail("JSON")
				}
				seen[s] = true
				if e = walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case json.Delim('['):
			for d.More() {
				if e = walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(); e != nil {
		return fail("JSON")
	}
	if _, e := d.Token(); e != io.EOF {
		return fail("JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return fail("JSON")
	}
	return nil
}
func ParseConfig(raw []byte) (Config, error) {
	var c Config
	if len(raw) > 65536 || strict(raw, &c) != nil {
		return c, fail("CONFIG")
	}
	return c, c.Validate()
}
