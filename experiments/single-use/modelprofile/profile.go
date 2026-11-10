// Package modelprofile owns the public proxy-config schema and the payload's
// selected-model pairing contract. Paths are inert strings: no I/O or clock use.
package modelprofile

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"
)

type Code string

func (c Code) Error() string { return string(c) }

const (
	DialectMessages             = "messages"
	DialectResponses            = "responses"
	ErrFile                Code = "CONFIG_FILE"
	ErrPair                Code = "PAYLOAD_CONFIG"
	MaxConfigBytes              = 65536
	OpenAIResponsesProfile      = "openai-responses-functions-default-v1"
)

type Endpoint struct {
	URL        string `json:"url"`
	CertSHA256 string `json:"cert_sha256"`
}

type Model struct {
	ContextTokens uint64 `json:"context_tokens"`
	InputNanoUSD  uint64 `json:"input_nano_usd"`
	OutputNanoUSD uint64 `json:"output_nano_usd"`
	Source        string `json:"source"`
}

type ModelProfile struct {
	Profile  string `json:"profile"`
	Upstream string `json:"upstream"`
}

type FileConfig struct {
	StateDir      string                  `json:"state_dir"`
	Listen        string                  `json:"listen"`
	Endpoint      Endpoint                `json:"endpoint"`
	TLSCert       string                  `json:"tls_cert"`
	TLSKey        string                  `json:"tls_key"`
	AdminSocket   string                  `json:"admin_socket"`
	CallerUID     uint32                  `json:"caller_uid"`
	Upstream      string                  `json:"upstream"`
	APIKeyFile    string                  `json:"api_key_file"`
	Models        map[string]Model        `json:"models"`
	ModelProfiles map[string]ModelProfile `json:"model_profiles,omitempty"`
}

type TypedProfile struct {
	Dialect    string `json:"dialect"`
	Model      string `json:"model"`
	MaxTokens  uint64 `json:"max_tokens"`
	Endpoint   string `json:"model_endpoint"`
	CertSHA256 string `json:"model_cert_sha256"`
}

// DecodeFileConfig preserves LoadConfig's whitespace trimming and canonical
// JSON rules. It checks syntax, not proxy service startup or filesystem custody.
func DecodeFileConfig(b []byte) (FileConfig, error) {
	var c FileConfig
	if len(b) == 0 || len(b) > MaxConfigBytes {
		return c, ErrFile
	}
	b = bytes.TrimSpace(b)
	if unique(b) != nil || json.Unmarshal(b, &c) != nil {
		return FileConfig{}, ErrFile
	}
	canonical, e := json.Marshal(c)
	if e != nil || !bytes.Equal(b, canonical) {
		return FileConfig{}, ErrFile
	}
	return c, nil
}

// ValidatePublicModelConfig uses the same schema and pairing as the installed
// payload. It neither reads referenced paths nor starts the proxy.
func ValidatePublicModelConfig(b []byte, want TypedProfile) error {
	c, e := DecodeFileConfig(b)
	if e != nil {
		return e
	}
	return CheckModelPair(want, c)
}

// CheckModelPair preserves the payload's public selection rules; service-level
// CONFIG_PROFILE validation is deliberately a separate, stricter contract.
func CheckModelPair(p TypedProfile, c FileConfig) error {
	m, ok := c.Models[p.Model]
	if !ok || p.Model == "" || p.MaxTokens == 0 || m.ContextTokens == 0 || p.MaxTokens > m.ContextTokens || p.Endpoint != c.Endpoint.URL || p.CertSHA256 != c.Endpoint.CertSHA256 {
		return ErrPair
	}
	want := DialectMessages
	if profile, ok := c.ModelProfiles[p.Model]; ok {
		u, e := url.Parse(profile.Upstream)
		if profile.Profile != OpenAIResponsesProfile || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || !strings.HasSuffix(u.Path, "/v1/responses") {
			return ErrPair
		}
		want = DialectResponses
	}
	if p.Dialect != want {
		return ErrPair
	}
	return nil
}

func unique(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrFile
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return ErrFile
		}
		t, e := d.Token()
		if e != nil {
			return ErrFile
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					start := d.InputOffset()
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] || bytes.IndexByte(raw[start:d.InputOffset()], '\\') >= 0 {
						return ErrFile
					}
					seen[s] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return ErrFile
				}
			case '[':
				for d.More() {
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return ErrFile
				}
			default:
				return ErrFile
			}
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrFile
	}
	return nil
}
