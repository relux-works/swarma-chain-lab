package gatewaybind

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	proxy "relux.works/swarma-chain-lab/experiments/model-proxy"
	lifecycle "relux.works/swarma-chain-lab/experiments/station-lifecycle"
)

// PayloadBootstrap is private station input, not a manager credential or host
// policy. Payloads must use DecodeBootstrap before any stationlink handshake.
// The gateway address and TLS leaf pin are separate operator-pinned inputs.
type PayloadBootstrap struct {
	V               int              `json:"v"`
	BookingID       string           `json:"booking_id"`
	StationName     string           `json:"station_name"`
	ChannelSecret   lifecycle.Secret `json:"channel_secret"`
	ModelBearer     proxy.Secret     `json:"model_bearer,omitempty"`
	ModelEndpoint   string           `json:"model_endpoint,omitempty"`
	ModelCertSHA256 string           `json:"model_cert_sha256,omitempty"`
}

func (PayloadBootstrap) String() string   { return "[private station bootstrap]" }
func (PayloadBootstrap) GoString() string { return "[private station bootstrap]" }
func validBootstrap(b PayloadBootstrap) bool {
	id, e := hex.DecodeString(b.BookingID)
	if e != nil || len(id) != 32 || hex.EncodeToString(id) != b.BookingID || (b.V != 1 && b.V != 2) || len(b.ChannelSecret) != 32 || !strings.HasPrefix(b.StationName, "id/") || len(b.StationName) > 255 || len(b.StationName) < 4 {
		return false
	}
	for _, c := range b.StationName[3:] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	if b.V == 1 {
		return b.ModelBearer == "" && b.ModelEndpoint == "" && b.ModelCertSHA256 == ""
	}
	return (proxy.Credential{Bearer: b.ModelBearer, Endpoint: proxy.Endpoint{URL: b.ModelEndpoint, CertSHA256: b.ModelCertSHA256}}).Valid()
}
func EncodeBootstrap(b PayloadBootstrap) (lifecycle.Secret, error) {
	if !validBootstrap(b) {
		return nil, errors.New("PAYLOAD_BOOTSTRAP")
	}
	raw, e := json.Marshal(b)
	if e != nil || len(raw) > 4096 {
		return nil, errors.New("PAYLOAD_BOOTSTRAP")
	}
	return lifecycle.Secret(raw), nil
}
func DecodeBootstrap(raw []byte) (PayloadBootstrap, error) {
	var b PayloadBootstrap
	if len(raw) == 0 || len(raw) > 4096 {
		return b, errors.New("PAYLOAD_BOOTSTRAP")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || !validBootstrap(b) {
		return PayloadBootstrap{}, errors.New("PAYLOAD_BOOTSTRAP")
	}
	encoded, e := json.Marshal(b)
	if e != nil || !bytes.Equal(raw, encoded) {
		return PayloadBootstrap{}, errors.New("PAYLOAD_BOOTSTRAP")
	}
	return b, nil
}
