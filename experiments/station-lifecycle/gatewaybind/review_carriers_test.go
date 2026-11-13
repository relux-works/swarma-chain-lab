// Regression probes adopted from the independent rev232 review; synthetic credentials only.
package gatewaybind_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

func reviewCarrierBytes(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	return secret
}

// Unsupported pointer formatting cannot expose a bearer in any of its retained forms.
func TestReviewProxyCredentialFmt(t *testing.T) {
	bearer := base64.RawURLEncoding.EncodeToString(reviewCarrierBytes(t))
	credential := proxy.Credential{Bearer: proxy.NewBearer(proxy.Secret(bearer))}
	if strings.Contains(fmt.Sprintf("%v", credential), bearer) {
		t.Fatal("normal-format redaction control failed")
	}
	for _, value := range []struct {
		Name  string
		Value any
	}{{"credential-value", credential}, {"secret-value", credential.Bearer}, {"nested-credential", struct{ Credential proxy.Credential }{credential}}} {
		t.Run(value.Name, func(t *testing.T) {
			var output bytes.Buffer
			fmt.Fprintf(&output, "%p", value.Value)
			if strings.Contains(output.String(), bearer) {
				t.Fatal("unwrapped model bearer disclosed by percent-p bad-verb diagnostic")
			}
		})
	}
}

// Private journal persistence retains a usable credential without a printable raw field.
func TestReviewJournalRevealRetention(t *testing.T) {
	channel := reviewCarrierBytes(t)
	handle := station.Station{ChannelSecret: station.NewChannelSecret(channel)}
	expectedHex := hex.EncodeToString(channel)
	for _, format := range []string{"%p", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, handle), expectedHex) {
			t.Fatal("wrapped-handle control leaked")
		}
	}
	store, err := journal.Open(t.TempDir())
	if err != nil {
		t.Fatal("journal fixture refused")
	}
	if err = store.Put(&journal.Slot{ID: "review-slot", RenterPubKey: "review-renter"}); err != nil {
		t.Fatal("journal slot fixture refused")
	}
	if err = store.SetChannelSecret("review-slot", hex.EncodeToString(handle.ChannelSecret.Reveal()), ""); err != nil {
		t.Fatal("channel persistence refused")
	}
	slot, ok := store.Get("review-slot")
	if !ok || slot.ChannelSecretHex.Reveal() != expectedHex {
		t.Fatal("retained channel positive control failed")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%p"} {
		t.Run(format, func(t *testing.T) {
			if strings.Contains(fmt.Sprintf(format, *slot), expectedHex) {
				t.Fatal("Reveal-derived channel credential retained in printable journal field")
			}
		})
	}
}

// Retained private bootstrap bytes cannot be recovered from numeric fmt diagnostics.
func TestReviewLifecycleWireFmt(t *testing.T) {
	channel := reviewCarrierBytes(t)
	bearer := base64.RawURLEncoding.EncodeToString(reviewCarrierBytes(t))
	document := codec.Bootstrap[[]byte, string]{V: 2, BookingID: strings.Repeat("a", 64), StationName: "id/review", ChannelSecret: codec.NewSecret(channel), ModelBearer: codec.NewSecret(bearer), ModelEndpoint: "https://review.example", ModelCertSHA256: strings.Repeat("b", 64)}
	raw, err := codec.Encode(document)
	if err != nil {
		t.Fatal("private wire fixture refused")
	}
	slot := lifecycle.Slot{Bootstrap: lifecycle.NewPrivateBytes(lifecycle.Secret(raw))}
	decimalBearer := strings.Trim(fmt.Sprint([]byte(bearer)), "[]")
	for _, format := range []string{"%p", "%d"} {
		t.Run(format, func(t *testing.T) {
			if strings.Contains(fmt.Sprintf(format, slot), decimalBearer) {
				t.Fatal("encoded private bootstrap bearer recoverable from numeric formatted bytes")
			}
		})
	}
}

// All retained credential carrier families must stay redacted through nested
// JSON/text logging, not merely through their top-level fmt methods.
func TestReviewCarrierStructuredOutput(t *testing.T) {
	channel := reviewCarrierBytes(t)
	bearer := base64.RawURLEncoding.EncodeToString(reviewCarrierBytes(t))
	document := codec.Bootstrap[[]byte, string]{V: 2, BookingID: strings.Repeat("a", 64), StationName: "id/review", ChannelSecret: codec.NewSecret(channel), ModelBearer: codec.NewSecret(bearer), ModelEndpoint: "https://review.example", ModelCertSHA256: strings.Repeat("b", 64)}
	raw, err := codec.Encode(document)
	if err != nil {
		t.Fatal("private wire fixture refused")
	}
	forbidden := []string{bearer, hex.EncodeToString(channel), base64.StdEncoding.EncodeToString(channel), base64.StdEncoding.EncodeToString(raw)}
	for _, carrier := range []any{proxy.Credential{Bearer: proxy.NewBearer(proxy.Secret(bearer))}, journal.Slot{ChannelSecretHex: journal.NewChannelSecretHex(hex.EncodeToString(channel))}, lifecycle.Slot{Bootstrap: lifecycle.NewPrivateBytes(lifecycle.Secret(raw))}} {
		for _, shape := range []any{carrier, &carrier, struct{ Document any }{carrier}, map[string]any{"document": carrier}, [1]any{carrier}} {
			for _, jsonHandler := range []bool{false, true} {
				for _, group := range []bool{false, true} {
					var output bytes.Buffer
					var handler slog.Handler = slog.NewTextHandler(&output, nil)
					if jsonHandler {
						handler = slog.NewJSONHandler(&output, nil)
					}
					attribute := slog.Any("document", shape)
					if group {
						attribute = slog.Group("context", attribute)
					}
					slog.New(handler).LogAttrs(context.Background(), slog.LevelInfo, "review", attribute)
					for _, needle := range forbidden {
						if strings.Contains(output.String(), needle) {
							t.Fatal("retained credential disclosed through structured logging")
						}
					}
				}
			}
		}
	}
}
