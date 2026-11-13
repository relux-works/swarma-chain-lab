// Package codec owns the credential-bearing station bootstrap wire schema.
// Root consumers use payloadbootstrap.DecodeBootstrap for its public projection.
package codec

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// Bootstrap is private station input, not a manager credential or host
// policy. Credential consumers must use Decode before any stationlink handshake.
// The gateway address and TLS leaf pin are separate operator-pinned inputs.
type Bootstrap[C ~[]byte, B ~string] struct {
	V               int       `json:"v"`
	BookingID       string    `json:"booking_id"`
	StationName     string    `json:"station_name"`
	ChannelSecret   Secret[C] `json:"channel_secret"`
	ModelBearer     Secret[B] `json:"model_bearer,omitempty,omitzero"`
	ModelEndpoint   string    `json:"model_endpoint,omitempty"`
	ModelCertSHA256 string    `json:"model_cert_sha256,omitempty"`
}

func (Bootstrap[C, B]) String() string   { return "[private station bootstrap]" }
func (Bootstrap[C, B]) GoString() string { return "[private station bootstrap]" }
func Valid[C ~[]byte, B ~string](b Bootstrap[C, B]) bool {
	id, e := hex.DecodeString(b.BookingID)
	if e != nil || len(id) != 32 || hex.EncodeToString(id) != b.BookingID || (b.V != 1 && b.V != 2) || len(b.ChannelSecret.Reveal()) != 32 || !strings.HasPrefix(b.StationName, "id/") || len(b.StationName) > 255 || len(b.StationName) < 4 {
		return false
	}
	for _, c := range b.StationName[3:] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	if b.V == 1 {
		return b.ModelBearer.Reveal() == "" && b.ModelEndpoint == "" && b.ModelCertSHA256 == ""
	}
	return ValidCredential(string(b.ModelBearer.Reveal()), b.ModelEndpoint, b.ModelCertSHA256)
}
func Encode[C ~[]byte, B ~string](b Bootstrap[C, B]) (C, error) {
	if !Valid(b) {
		return nil, errors.New("PAYLOAD_BOOTSTRAP")
	}
	raw, e := json.Marshal(b)
	if e != nil || len(raw) > 4096 {
		return nil, errors.New("PAYLOAD_BOOTSTRAP")
	}
	return C(raw), nil
}
func Decode[C ~[]byte, B ~string](raw []byte) (Bootstrap[C, B], error) {
	var b Bootstrap[C, B]
	if len(raw) == 0 || len(raw) > 4096 {
		return b, errors.New("PAYLOAD_BOOTSTRAP")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || !Valid(b) {
		return Bootstrap[C, B]{}, errors.New("PAYLOAD_BOOTSTRAP")
	}
	encoded, e := json.Marshal(b)
	if e != nil || !bytes.Equal(raw, encoded) {
		return Bootstrap[C, B]{}, errors.New("PAYLOAD_BOOTSTRAP")
	}
	return b, nil
}

// ValidCredential matches the existing proxy credential contract, with no I/O.
func ValidCredential(bearer, endpoint, pin string) bool {
	b, e := base64.RawURLEncoding.DecodeString(bearer)
	p, pe := hex.DecodeString(pin)
	u, ue := url.Parse(endpoint)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == bearer && pe == nil && len(p) == 32 && hex.EncodeToString(p) == pin && ue == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && !strings.Contains(endpoint, "#") && u.Opaque == "" && u.Host == strings.ToLower(u.Host) && u.String() == endpoint && u.RawPath == "" && !strings.HasSuffix(endpoint, "/") && u.Path == ""
}
