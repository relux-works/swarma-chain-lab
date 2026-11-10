package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
	payload "github.com/relux-works/swarma-chain-lab/experiments/station-payload"
)

// The real CLI parses the public copy without opening its named credential
// paths. Valid pairing reaches the deliberately cancelled channel; mismatches
// fail earlier with CONFIG and no HTTP. Full successful CLI runs are in SP2.
func TestPinnedCLI(t *testing.T) {
	for _, kind := range []string{"dialect", "model", "endpoint", "pin", "missing-config", "unpaired-flags"} {
		t.Run(kind, func(t *testing.T) {
			root, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			if os.Chmod(root, 0700) != nil {
				t.Fatal("root")
			}
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			defer s.Close()
			cfg := proxy.FileConfig{Endpoint: proxy.Endpoint{URL: s.URL, CertSHA256: strings.Repeat("a", 64)}, APIKeyFile: "/never-open-credential", TLSKey: "/never-open-key", Models: map[string]proxy.Model{"fixture": {ContextTokens: 100}}, ModelProfiles: map[string]proxy.ModelProfile{"fixture": {Profile: proxy.OpenAIResponsesProfile, Upstream: "https://upstream.invalid/v1/responses"}}}
			b := gatewaybind.PayloadBootstrap{V: 2, BookingID: strings.Repeat("b", 64), StationName: "id/pinned-cli", ChannelSecret: []byte(strings.Repeat("s", 32)), ModelBearer: proxy.Secret(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("m", 32)))), ModelEndpoint: s.URL, ModelCertSHA256: cfg.Endpoint.CertSHA256}
			raw, e := gatewaybind.EncodeBootstrap(b)
			if e != nil {
				t.Fatal(e)
			}
			static := filepath.Join(root, "static")
			if e := os.Mkdir(static, 0750); e != nil {
				t.Fatal(e)
			}
			os.Chmod(static, 0750)
			bp, cp, mp := filepath.Join(root, "bootstrap"), filepath.Join(static, "ca"), filepath.Join(static, "public-model")
			if os.WriteFile(bp, raw, 0600) != nil {
				t.Fatal("bootstrap fixture")
			}
			writeInstalled(t, cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
			write := func() {
				raw, _ := json.Marshal(cfg)
				writeInstalled(t, mp, raw)
			}
			write()
			args := []string{"-journal-dir", journalRoot(t), "-bootstrap", bp, "-ca", cp, "-gateway", "127.0.0.1:1", "-gateway-pin", strings.Repeat("a", 64), "-model", "fixture", "-max-tokens", "10", "-dialect", "responses", "-model-config", mp}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if e := run(ctx, args); e != payload.ErrChannel {
				t.Fatal("pinned CLI neighbor did not reach channel", e)
			}
			switch kind {
			case "dialect":
				args[15] = "messages"
			case "model":
				delete(cfg.Models, "fixture")
			case "endpoint":
				cfg.Endpoint.URL = "https://other.invalid"
			case "pin":
				cfg.Endpoint.CertSHA256 = strings.Repeat("c", 64)
			case "missing-config":
				args[17] = mp + "-absent"
			case "unpaired-flags":
				args = args[:16]
			}
			write()
			if e := run(ctx, args); (kind != "missing-config" && e != payload.ErrConfig || kind == "missing-config" && (e == nil || e.Error() != "DK5_FILE_OPEN")) || calls != 0 {
				t.Fatal("pinned CLI startup guard missing", e)
			}
		})
	}
}
