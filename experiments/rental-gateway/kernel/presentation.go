package kernel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// PresentationID checks v3 transport framing and returns the hash of the
// signed_grant bytes, excluding the issuance locator. This is not a grant
// validator: the real kernel must still verify the canonical grant schema,
// signatures, grantee, policy and chain before admitting anything. Keeping
// grant fields opaque here avoids a second authority implementation.
func PresentationID(raw []byte) (string, error) {
	malformed := errors.New("kernel: malformed v3 presentation")
	var p struct {
		SignedGrant struct {
			Grant     json.RawMessage `json:"grant"`
			Signature string          `json:"signature"`
		} `json:"signed_grant"`
		Issuance struct {
			TxID string `json:"txid"`
		} `json:"issuance"`
	}
	if len(raw) == 0 || len(raw) > 16384 {
		return "", malformed
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return "", malformed
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", malformed
	}
	var version struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(p.SignedGrant.Grant, &version) != nil || version.Version != 3 {
		return "", malformed
	}
	for value, size := range map[string]int{p.SignedGrant.Signature: 64, p.Issuance.TxID: 32} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != size || hex.EncodeToString(b) != value {
			return "", malformed
		}
	}
	signed, err := json.Marshal(p.SignedGrant)
	if err != nil {
		return "", malformed
	}
	sum := sha256.Sum256(signed)
	return hex.EncodeToString(sum[:]), nil
}
