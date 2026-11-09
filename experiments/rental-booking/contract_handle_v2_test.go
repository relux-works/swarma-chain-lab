package booking

import (
	"bytes"
	"strings"
	"testing"
)

// Every frozen coin contract has an exact-byte handle. Altering its hash,
// booking ID, canonical encoding or inner version refuses; valid bytes remain
// detached from caller mutations. This is not signature/payment authentication.
func TestContractHandleV2(t *testing.T) {
	for _, coin := range []string{"nmc", "btc", "ltc"} {
		t.Run(coin, func(t *testing.T) {
			_, c := contractV2Fixture(t, coin)
			h, err := c.Handle()
			if err != nil || h.Validate() != nil || !bytes.Equal(h.ContractJSON, c.Bytes()) || h.ContractSHA256 != c.Hash() {
				t.Fatal("valid handle", err)
			}
			for _, mode := range []string{"hash", "booking", "whitespace", "version", "oversized"} {
				bad := h
				bad.ContractJSON = append([]byte(nil), h.ContractJSON...)
				switch mode {
				case "hash":
					bad.ContractSHA256 = strings.Repeat("0", 64)
				case "booking":
					bad.BookingID = strings.Repeat("0", 64)
				case "whitespace":
					bad.ContractJSON = append(bad.ContractJSON, '\n')
				case "version":
					old := c
					old.Version = 1
					bad.ContractJSON = old.Bytes()
					bad.ContractSHA256 = old.Hash()
				case "oversized":
					bad.ContractJSON = bytes.Repeat([]byte(" "), 16385)
				}
				if err := bad.Validate(); err == nil || err.Error() != "CONTRACT_HANDLE" {
					t.Fatal("invalid handle accepted", mode, err)
				}
				if h.Validate() != nil || !bytes.Equal(h.ContractJSON, c.Bytes()) {
					t.Fatal("valid neighbour changed")
				}
			}
			bad := c
			bad.Version = 1
			if handle, err := bad.Handle(); err == nil || err.Error() != "CONTRACT_IDENTITY" || handle.ContractJSON != nil || handle.BookingID != "" || handle.ContractSHA256 != "" {
				t.Fatal("invalid contract produced handle", err)
			}
		})
	}
}
