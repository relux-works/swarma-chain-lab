// Package payloadbootstrap validates the existing private station wire bytes
// and returns only public metadata. It does not establish custody or admission.
package payloadbootstrap

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
)

// Bootstrap deliberately has no channel secret, model bearer, slot or deadline.
// Slot/deadline bindings come from separately checked payloadlaunch receipts.
type Bootstrap struct {
	V               int    `json:"v"`
	BookingID       string `json:"booking_id"`
	StationName     string `json:"station_name"`
	ModelEndpoint   string `json:"model_endpoint,omitempty"`
	ModelCertSHA256 string `json:"model_cert_sha256,omitempty"`
	SHA256          string `json:"sha256"`
}

// DecodeBootstrap accepts the exact legacy v1/v2 canonical bytes. The digest
// covers every input byte, including validated credentials, without returning them.
func DecodeBootstrap(b []byte) (Bootstrap, error) {
	d, e := codec.Decode[[]byte, string](b)
	if e != nil {
		return Bootstrap{}, e
	}
	h := sha256.Sum256(b)
	return Bootstrap{V: d.V, BookingID: d.BookingID, StationName: d.StationName, ModelEndpoint: d.ModelEndpoint, ModelCertSHA256: d.ModelCertSHA256, SHA256: hex.EncodeToString(h[:])}, nil
}
