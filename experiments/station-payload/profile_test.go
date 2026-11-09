package payload

import (
	"context"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

// Every new-mode startup mismatch is paired with a correctly pinned constructor.
// Construction, including rejection, must have no network/accounting effects.
func TestPinnedStartup(t *testing.T) {
	for _, dialect := range []string{DialectMessages, DialectResponses} {
		for _, kind := range []string{"dialect", "model", "endpoint", "pin", "limit", "unknown"} {
			t.Run(dialect+"/"+kind, func(t *testing.T) {
				f := newFixture(t)
				cfg := proxy.FileConfig{Endpoint: proxy.Endpoint{URL: f.doc.ModelEndpoint, CertSHA256: f.doc.ModelCertSHA256}, Models: map[string]proxy.Model{modelID: {ContextTokens: 100}}}
				if dialect == DialectResponses {
					cfg.ModelProfiles = map[string]proxy.ModelProfile{modelID: {Profile: proxy.OpenAIResponsesProfile, Upstream: "https://upstream.invalid/v1/responses"}}
				}
				o := Options{Model: modelID, MaxTokens: 10, Roots: f.roots}
				c, e := NewPinned(encoded(t, f.doc), o, dialect, cfg)
				if e != nil || c == nil {
					t.Fatal("pinned startup valid neighbor refused", e)
				}
				c.Close()
				selected := dialect
				switch kind {
				case "dialect":
					if dialect == DialectMessages {
						selected = DialectResponses
					} else {
						selected = DialectMessages
					}
				case "model":
					o.Model = "absent"
				case "endpoint":
					cfg.Endpoint.URL = "https://other.invalid"
				case "pin":
					cfg.Endpoint.CertSHA256 = strings.Repeat("a", 64)
				case "limit":
					o.MaxTokens = 101
				case "unknown":
					selected = "unknown"
				}
				c, e = NewPinned(encoded(t, f.doc), o, selected, cfg)
				if e != ErrConfig || c != nil {
					if c != nil {
						c.Close()
					}
					t.Fatal("pinned startup mismatch accepted")
				}
				st, e := f.s.Status(f.b.SlotID)
				if e != nil || st.Exposure.Requests != 0 || f.requests.Load() != 0 || f.upstream.Load() != 0 {
					t.Fatal("pinned startup caused network/accounting")
				}
			})
		}
	}
}

// Explicit Messages uses the identical landed generator after startup pairing.
func TestPinnedMessages(t *testing.T) {
	f := newFixture(t)
	cfg := proxy.FileConfig{Endpoint: proxy.Endpoint{URL: f.doc.ModelEndpoint, CertSHA256: f.doc.ModelCertSHA256}, Models: map[string]proxy.Model{modelID: {ContextTokens: 100}}}
	c, e := NewPinned(encoded(t, f.doc), Options{Model: modelID, MaxTokens: 10, Roots: f.roots}, DialectMessages, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if out, e := c.Respond(context.Background(), prompt); e != nil || out != answer {
		t.Fatal("pinned Messages changed", e)
	}
}
