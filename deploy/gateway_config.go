package deploy

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
)

type gatewayModelProxy struct {
	AdminSocket string  `json:"admin_socket"`
	ServerUID   *uint32 `json:"server_uid"`
	Origin      string  `json:"origin"`
	CertSHA256  string  `json:"cert_sha256"`
	Caps        struct {
		InputTokens  uint64 `json:"input_tokens"`
		OutputTokens uint64 `json:"output_tokens"`
		Requests     uint64 `json:"requests"`
		MaxTokens    uint64 `json:"max_tokens"`
		CostNanoUSD  uint64 `json:"cost_nano_usd"`
	} `json:"caps"`
}

// Validate exchange version/coins and the optional GA1 boundary here. The service remains responsible
// for full native startup validation; this check never reads socket/key files.
func gatewayOptions(v map[string]any) error {
	if x, present := v["exchange"]; present {
		e, ok := x.(map[string]any)
		if !ok {
			return ErrPolicy
		}
		version := e["booking_version"]
		if version != json.Number("2") && !(version == json.Number("1") && v["mode"] == "test") {
			return ErrPolicy
		}
		coins, ok := e["payment_coins"].([]any)
		if !ok || len(coins) < 1 || len(coins) > 3 {
			return ErrPolicy
		}
		seen := map[string]bool{}
		for _, value := range coins {
			coin, ok := value.(string)
			if !ok || (coin != "nmc" && coin != "btc" && coin != "ltc") || seen[coin] {
				return ErrPolicy
			}
			seen[coin] = true
		}
		if v["mode"] == "main" && (len(coins) != 1 || coins[0] != "nmc") {
			return ErrNetwork
		}
		if version == json.Number("1") && (len(coins) != 1 || coins[0] != "nmc") {
			return ErrPolicy
		}
	}

	if x, ok := v["relay_auth"]; ok {
		if x != "off" && x != "when_challenged" && x != "required" {
			return ErrPolicy
		}
	}
	x, present := v["model_proxy"]
	if !present {
		return nil
	}
	if x == nil {
		return ErrPolicy
	}
	raw, e := json.Marshal(x)
	if e != nil {
		return ErrPolicy
	}
	var m gatewayModelProxy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return ErrPolicy
	}
	if !filepath.IsAbs(m.AdminSocket) || filepath.Clean(m.AdminSocket) != m.AdminSocket || m.AdminSocket == "/" || len(m.AdminSocket) > 100 || strings.ContainsAny(m.AdminSocket, "\x00\r\n") || m.ServerUID == nil || !exactHex(m.CertSHA256, 32) {
		return ErrPolicy
	}
	if v["mode"] == "main" && *m.ServerUID == 0 {
		return ErrPolicy
	}
	if m.CertSHA256 == strings.Repeat(m.CertSHA256[:2], 32) {
		return ErrPolicy
	}
	u, e := url.Parse(m.Origin)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.RawPath != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Host != strings.ToLower(u.Host) || u.String() != m.Origin || strings.Contains(m.Origin, "#") {
		return ErrPolicy
	}
	c := m.Caps
	if c.InputTokens == 0 || c.OutputTokens == 0 || c.Requests == 0 || c.MaxTokens == 0 || c.MaxTokens > c.OutputTokens || c.CostNanoUSD == 0 {
		return ErrPolicy
	}
	station, ok := v["station"].(map[string]any)
	if !ok || station["driver"] != "manager" {
		return ErrPolicy
	}
	return nil
}
