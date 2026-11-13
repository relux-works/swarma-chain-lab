// Regression probes adopted from the independent rev232 review; synthetic credentials only.
package gatewaybind_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"log/slog"
	"strings"
	"testing"
)

// The four legacy output leaks stay closed on the same synthetic carrier scenarios.
func TestReviewExistingCarrierBoundaries(t *testing.T) {
	channel := make([]byte, 32)
	entropy := make([]byte, 32)
	if _, err := rand.Read(channel); err != nil {
		t.Fatal("entropy unavailable")
	}
	if _, err := rand.Read(entropy); err != nil {
		t.Fatal("entropy unavailable")
	}
	bearer := base64.RawURLEncoding.EncodeToString(entropy)
	raw := []byte(fmt.Sprintf(`{"v":2,"booking_id":"%s","station_name":"id/review","channel_secret":"%s","model_bearer":"%s","model_endpoint":"https://review.example","model_cert_sha256":"%s"}`, strings.Repeat("a", 64), base64.StdEncoding.EncodeToString(channel), bearer, strings.Repeat("b", 64)))
	document, err := codec.Decode[[]byte, string](raw)
	if err != nil {
		t.Fatal("canonical fixture refused")
	}
	t.Run("slog-json-bootstrap", func(t *testing.T) {
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).LogAttrs(context.Background(), slog.LevelInfo, "review", slog.Any("bootstrap", document))
		if strings.Contains(output.String(), bearer) {
			t.Fatal("private JSON credential leaked through structured logging")
		}
	})
	t.Run("proxy-credential-percent-p", func(t *testing.T) {
		credential := proxy.Credential{Bearer: proxy.NewBearer(proxy.Secret(bearer))}
		if strings.Contains(fmt.Sprintf("%p", credential), bearer) {
			t.Fatal("unwrapped model bearer leaked through invalid verb")
		}
	})
	t.Run("journal-channel", func(t *testing.T) {
		encoded := hex.EncodeToString(channel)
		slot := journal.Slot{ChannelSecretHex: journal.NewChannelSecretHex(encoded)}
		if strings.Contains(fmt.Sprintf("%+v", slot), encoded) {
			t.Fatal("raw journal channel field leaked through normal formatting")
		}
	})
	t.Run("lifecycle-private-wire", func(t *testing.T) {
		slot := lifecycle.Slot{Bootstrap: lifecycle.NewPrivateBytes(lifecycle.Secret(raw))}
		needle := strings.Trim(fmt.Sprint([]byte(bearer)), "[]")
		format := "%p"
		if strings.Contains(fmt.Sprintf(format, slot), needle) {
			t.Fatal("private wire bearer recoverable from numeric formatting")
		}
	})
}
