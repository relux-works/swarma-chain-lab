package booking

import (
	"bytes"
	"encoding/json"
)

// ContractHandleV2 is an adapter view, not a signed-wire replacement or proof
// of a hold/payment. Exchange code can retain these exact bytes without knowing
// contract fields. Consent and provider authentication remain separate.
type ContractHandleV2 struct {
	BookingID      string          `json:"booking_id"`
	ContractSHA256 string          `json:"contract_sha256"`
	ContractJSON   json.RawMessage `json:"contract"`
}

func (c ContractV2) Handle() (ContractHandleV2, error) {
	if err := c.Validate(); err != nil {
		return ContractHandleV2{}, err
	}
	raw := c.Bytes()
	if len(raw) > 16384 {
		return ContractHandleV2{}, refuse("CONTRACT_HANDLE")
	}
	return ContractHandleV2{BookingID: c.BookingID, ContractSHA256: Hash(raw), ContractJSON: raw}, nil
}

// Validate checks only the static canonical/hash/booking binding. It never
// reserves a slot, authenticates signatures or establishes current payment.
func (h ContractHandleV2) Validate() error {
	var c ContractV2
	if len(h.ContractJSON) > 16384 || Strict(h.ContractJSON, &c) != nil || !bytes.Equal(h.ContractJSON, c.Bytes()) || c.Validate() != nil || h.BookingID != c.BookingID || h.ContractSHA256 != Hash(h.ContractJSON) {
		return refuse("CONTRACT_HANDLE")
	}
	return nil
}
