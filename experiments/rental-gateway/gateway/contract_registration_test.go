package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
)

// Registration retains only hash-bound bytes and exact replay preserves state.
// This fixture proves journaling, not the separate kernel signature admission.
func TestIssuedContractRegistration(t *testing.T) {
	for _, kind := range []string{"missing", "changed", "oversized", "existing-conflict", "legacy-replay"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			j, e := journal.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			raw := []byte(`{"fixture":"contract"}`)
			hash := sha256.Sum256(raw)
			cert := []byte(`{"signed_grant":{"grant":{"version":3},"signature":"` + strings.Repeat("0", 128) + `"},"issuance":{"txid":"` + strings.Repeat("0", 64) + `"}}`)
			id, e := kernel.PresentationID(cert)
			if e != nil {
				t.Fatal(e)
			}
			i := exchange.Issued{BookingID: strings.Repeat("b", 64), ContractSHA256: hex.EncodeToString(hash[:]), Contract: raw, Sender: strings.Repeat("c", 64), AgentName: "id/agent", StationName: "id/agent", GrantID: id, NotBefore: 100, NotAfter: 200, Presentation: cert}
			g := &Gateway{cfg: Config{Journal: j, AgentName: "id/agent"}}
			if kind == "existing-conflict" || kind == "legacy-replay" {
				old := &journal.Slot{ID: i.BookingID, BookingID: i.BookingID, RenterPubKey: i.Sender, ContractSHA256: i.ContractSHA256, CertificateB64: base64.StdEncoding.EncodeToString(cert), StationName: i.StationName, NotBefore: i.NotBefore, NotAfter: i.NotAfter, Ended: true}
				if kind == "existing-conflict" {
					old.ContractB64 = base64.StdEncoding.EncodeToString([]byte("changed"))
				}
				if e = j.Put(old); e != nil {
					t.Fatal(e)
				}
				before, _ := j.Get(i.BookingID)
				e = g.registerIssued(context.Background(), i)
				after, _ := j.Get(i.BookingID)
				if kind == "existing-conflict" && (e == nil || e.Error() != "issued slot conflict") {
					t.Fatal("persisted contract conflict accepted", e)
				}
				if kind == "legacy-replay" && e != nil {
					t.Fatal("legacy replay refused", e)
				}
				if after.ContractB64 != before.ContractB64 || !after.Ended {
					t.Fatal("replay rewrote existing state")
				}
				return
			}
			bad := i
			switch kind {
			case "missing":
				bad.Contract = nil
			case "changed":
				bad.Contract = []byte("changed")
			case "oversized":
				bad.Contract = make([]byte, 8193)
			}
			if e = g.registerIssued(context.Background(), bad); e == nil || e.Error() != "issued contract binding" {
				t.Fatal("wrong registration refusal", e)
			}
			if len(j.All()) != 0 {
				t.Fatal("refusal persisted slot")
			}
			if e = g.registerIssued(context.Background(), i); e != nil {
				t.Fatal("valid registration", e)
			}
			i.Contract[0] ^= 1
			reopened, e := journal.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			stored, _ := reopened.Get(i.BookingID)
			got, e := base64.StdEncoding.DecodeString(stored.ContractB64)
			if e != nil || !bytes.Equal(got, []byte(`{"fixture":"contract"}`)) {
				t.Fatal("journal lost original contract", e)
			}
		})
	}
}
