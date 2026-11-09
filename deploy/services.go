package deploy

import (
	"bytes"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func newService(s string) bool {
	return s == "wallet" || s == "issuer" || s == "model" || s == "stations" || s == "payload"
}

// New service descriptors contain only installation identity. Native files are
// checked separately; this does not read secrets or attest host ownership.
func validateServicePolicy(p Policy) (Policy, error) {
	want := Policy{Version: 1, Network: "regtest", Service: p.Service, ReleaseVersion: p.ReleaseVersion, Commit: p.Commit, BinarySHA256: p.BinarySHA256}
	if p.Service != "payload" {
		want.StateDir = "/var/lib/swarma-" + p.Service
		want.Config = "/etc/swarma/" + p.Service + "/service.json"
	}
	if p.Service == "model" {
		want.Listen = p.Listen
		if !stationEndpoint(p.Listen) {
			return Policy{}, ErrPolicy
		}
	}
	if p != want || !label(p.ReleaseVersion) || !exactHex(p.Commit, 20) || !exactHex(p.BinarySHA256, 32) {
		return Policy{}, ErrPolicy
	}
	return p, nil
}

// ValidateServiceInputs binds each new descriptor to exactly one native public
// config. Payload has flags only, so it accepts no invented native JSON. Older
// services retain their existing supplemental-public-file validation contract.
func ValidateServiceInputs(p Policy, inputs [][]byte) error {
	if !newService(p.Service) {
		for _, raw := range inputs {
			if e := ValidatePublicJSON(raw); e != nil {
				return e
			}
		}
		return nil
	}
	if _, e := validateServicePolicy(p); e != nil {
		return e
	}
	if p.Service == "payload" {
		if len(inputs) != 0 {
			return ErrPolicy
		}
		return nil
	}
	if len(inputs) != 1 {
		return ErrPolicy
	}
	raw := inputs[0]
	if e := ValidatePublicJSON(raw); e != nil {
		return e
	}
	switch p.Service {
	case "wallet":
		return validateWallet(raw)
	case "issuer":
		return validateIssuer(raw)
	case "model":
		return validateModel(raw, p.Listen)
	case "stations":
		return validateStations(raw)
	}
	return ErrPolicy
}

// Compare typed re-encoding as well as DisallowUnknownFields: encoding/json
// alone accepts case-insensitive aliases and silently fills missing fields.
// Canonical native loaders additionally require exact field order/whitespace.
func serviceDecode(raw []byte, v any, canonical bool) error {
	if uniqueJSON(raw) != nil {
		return ErrPolicy
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrPolicy
	}
	encoded, e := json.Marshal(v)
	if e != nil {
		return ErrPolicy
	}
	if canonical {
		if !bytes.Equal(bytes.TrimSpace(raw), encoded) {
			return ErrPolicy
		}
	} else {
		normalize := func(b []byte) []byte {
			var x any
			d := json.NewDecoder(bytes.NewReader(b))
			d.UseNumber()
			if d.Decode(&x) != nil {
				return nil
			}
			out, _ := json.Marshal(x)
			return out
		}
		if !bytes.Equal(normalize(raw), normalize(encoded)) {
			return ErrPolicy
		}
	}
	return nil
}
func tlsURL(raw, path string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.Path == path && u.RawPath == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.Host == strings.ToLower(u.Host) && u.String() == raw && !strings.Contains(raw, "#")
}
func endpointPort(raw string) string {
	u, _ := url.Parse(raw)
	if u.Port() == "" {
		return "443"
	}
	return u.Port()
}
func digestPin(s string) bool { return exactHex(s, 32) && s != strings.Repeat("0", 64) }
func modelName(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

type modelSpec struct {
	ContextTokens uint64 `json:"context_tokens"`
	InputNanoUSD  uint64 `json:"input_nano_usd"`
	OutputNanoUSD uint64 `json:"output_nano_usd"`
	Source        string `json:"source"`
}
type modelProfileSpec struct {
	Profile  string `json:"profile"`
	Upstream string `json:"upstream"`
}
type modelConfig struct {
	StateDir string `json:"state_dir"`
	Listen   string `json:"listen"`
	Endpoint struct {
		URL        string `json:"url"`
		CertSHA256 string `json:"cert_sha256"`
	} `json:"endpoint"`
	TLSCert       string                      `json:"tls_cert"`
	TLSKey        string                      `json:"tls_key"`
	AdminSocket   string                      `json:"admin_socket"`
	CallerUID     *uint32                     `json:"caller_uid"`
	Upstream      string                      `json:"upstream"`
	APIKeyFile    string                      `json:"api_key_file"`
	Models        map[string]modelSpec        `json:"models"`
	ModelProfiles map[string]modelProfileSpec `json:"model_profiles,omitempty"`
}

func modelResponsesURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && strings.HasSuffix(u.Path, "/v1/responses") && tlsURL(raw, u.Path)
}

func validateModel(raw []byte, listen string) error {
	var c modelConfig
	if e := serviceDecode(raw, &c, true); e != nil {
		return e
	}
	upstreamValid := tlsURL(c.Upstream, "/v1/messages")
	if len(c.Models) > 0 && len(c.ModelProfiles) == len(c.Models) {
		upstreamValid = modelResponsesURL(c.Upstream)
	}
	if c.StateDir != "/var/lib/swarma-model" || c.Listen != listen || !stationEndpoint(c.Listen) || !tlsURL(c.Endpoint.URL, "") || !digestPin(c.Endpoint.CertSHA256) || c.TLSCert != "/etc/swarma/model/tls.pem" || c.TLSKey != "/etc/swarma/model/tls.key" || c.AdminSocket != "/run/swarma-model/admin.sock" || c.CallerUID == nil || *c.CallerUID == 0 || c.APIKeyFile != "/etc/swarma/model/api.key" || !upstreamValid || len(c.Models) < 1 || len(c.Models) > 16 {
		return ErrPolicy
	}
	_, port, _ := net.SplitHostPort(c.Listen)
	if endpointPort(c.Endpoint.URL) != port {
		return ErrPolicy
	}
	for name, m := range c.Models {
		if !modelName(name) || m.ContextTokens == 0 || m.ContextTokens > 1<<32 || m.InputNanoUSD == 0 || m.OutputNanoUSD == 0 || len(m.Source) == 0 || len(m.Source) > 1024 {
			return ErrPolicy
		}
		// The native proxy reserves a complete context window in each dimension.
		if m.InputNanoUSD > ^uint64(0)/m.ContextTokens || m.OutputNanoUSD > ^uint64(0)/m.ContextTokens {
			return ErrPolicy
		}
		a, b := m.InputNanoUSD*m.ContextTokens, m.OutputNanoUSD*m.ContextTokens
		if a > ^uint64(0)-b {
			return ErrPolicy
		}
	}
	for name, p := range c.ModelProfiles {
		if _, exists := c.Models[name]; !exists || p.Profile != "openai-responses-functions-default-v1" || !modelResponsesURL(p.Upstream) {
			return ErrPolicy
		}
	}
	return nil
}

type stationsConfig struct {
	StateDir          string `json:"state_dir"`
	Socket            string `json:"slotd_socket"`
	SlotMin           uint16 `json:"slot_min"`
	SlotMax           uint16 `json:"slot_max"`
	PayloadID         string `json:"payload_id"`
	PayloadSHA256     string `json:"payload_sha256"`
	Endpoint          string `json:"gateway_endpoint"`
	GatewayCertSHA256 string `json:"gateway_cert_sha256"`
	ClientCert        string `json:"client_cert"`
	ClientKey         string `json:"client_key"`
	ServerCA          string `json:"server_ca"`
}

func validateStations(raw []byte) error {
	var c stationsConfig
	if e := serviceDecode(raw, &c, true); e != nil {
		return e
	}
	if c.StateDir != "/var/lib/swarma-stations" || c.Socket != "/run/swarma-slotd-demo/sock" || c.SlotMin > c.SlotMax || c.SlotMax > 9999 || len(c.PayloadID) == 0 || len(c.PayloadID) > 64 || !digestPin(c.PayloadSHA256) || !digestPin(c.GatewayCertSHA256) || !tlsURL(c.Endpoint, "/v1/station-manager/poll") || c.ClientCert != "/etc/swarma/stations/client.pem" || c.ClientKey != "/etc/swarma/stations/client.key" || c.ServerCA != "/etc/swarma/stations/gateway-ca.pem" {
		return ErrPolicy
	}
	for _, v := range c.PayloadID {
		if !(v >= 'a' && v <= 'z' || v >= '0' && v <= '9' || v == '-' || v == '_') {
			return ErrPolicy
		}
	}
	u, _ := url.Parse(c.Endpoint)
	if !stationEndpoint(u.Host) {
		return ErrPolicy
	}
	// Reject port spellings that the pinned poll transport would interpret differently.
	if _, e := strconv.ParseUint(u.Port(), 10, 16); e != nil {
		return ErrPolicy
	}
	return nil
}
