package rehearsal

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
	payload "github.com/relux-works/swarma-chain-lab/experiments/station-payload"
)

// The same genuine-Core book/pay/issue/start/reply/cap/revoke-or-expiry assertions
// run with the real pinned Responses CLI and MP2 service. Existing host seams
// remain explicit; this is not a paid API, mainnet or Linux isolation test.
func TestResponsesComposition(t *testing.T) { runComposition(t, false, "responses") }

func responsesUpstream(t *testing.T, w http.ResponseWriter, r *http.Request, key string) {
	t.Helper()
	if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+key || r.Header.Get("x-api-key") != "" {
		t.Error("Responses rehearsal upstream credential boundary")
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, proxy.MaxResponsesBody+1))
	var q map[string]json.RawMessage
	if e != nil || json.Unmarshal(raw, &q) != nil || len(q) != 7 || string(q["model"]) != `"fixture"` || string(q["stream"]) != "false" || string(q["max_output_tokens"]) != "16" || string(q["store"]) != "false" || string(q["background"]) != "false" || string(q["service_tier"]) != `"default"` {
		t.Error("Responses rehearsal request shape")
	}
	var input string
	if json.Unmarshal(q["input"], &input) != nil || input == "" {
		t.Error("Responses rehearsal input")
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"id":"response_fixture","object":"response","model":"fixture","status":"completed","output":[{"id":"msg_fixture","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"model fixture reply","annotations":[]}]}],"usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}`)
}

func (l *lab) configureResponses(admin, upstream, endpoint, pin string) {
	path := admin + ".rehearsal.json"
	raw, e := os.ReadFile(path)
	checked(l.t, e, "fixture registrar config")
	var c map[string]any
	checked(l.t, json.Unmarshal(raw, &c), "fixture registrar shape")
	profiles := map[string]proxy.ModelProfile{"fixture": {Profile: proxy.OpenAIResponsesProfile, Upstream: upstream + "/v1/responses"}}
	c["Upstream"], c["ModelProfiles"] = upstream+"/v1/responses", profiles
	l.write(path, encoded(c), 0600)
	public := proxy.FileConfig{Endpoint: proxy.Endpoint{URL: endpoint, CertSHA256: pin}, Upstream: upstream + "/v1/responses", Models: map[string]proxy.Model{"fixture": {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "synthetic rehearsal pricing"}}, ModelProfiles: profiles}
	l.modelConfigPath = l.json("payload-public-model.json", public, 0600)
	l.evidence["payload_profile"] = proxy.OpenAIResponsesProfile
}

func (l *lab) checkResponsesRefusal(p tlsPaths, b gatewaybind.PayloadBootstrap, kind string) {
	roots := x509.NewCertPool()
	raw, e := os.ReadFile(p.ca)
	checked(l.t, e, "probe public CA")
	if !roots.AppendCertsFromPEM(raw) {
		l.t.Fatal("probe roots")
	}
	cfg, e := proxy.LoadConfig(l.modelConfigPath)
	checked(l.t, e, "probe public model config")
	want := error(payload.Code("MODEL_AUTH"))
	if kind == "wrong-pin" {
		b.ModelCertSHA256 = strings.Repeat("a", 64)
		cfg.Endpoint.CertSHA256 = b.ModelCertSHA256
		want = payload.ErrTransport
	}
	c, e := payload.NewPinned(encoded(b), payload.Options{Model: "fixture", MaxTokens: 16, Roots: roots}, payload.DialectResponses, cfg)
	checked(l.t, e, "pinned Responses probe startup")
	defer c.Close()
	if out, e := c.Respond(context.Background(), "rejected Responses probe"); out != "" || e != want {
		l.t.Fatal("Responses probe escaped fixed refusal", e)
	}
}
