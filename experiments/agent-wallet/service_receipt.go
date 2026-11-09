package wallet

import (
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
)

type PeerIdentity struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}
type ActionReceipt struct {
	Version        int             `json:"v"`
	Service        string          `json:"service"`
	Grantee        string          `json:"grantee"`
	RequestHash    string          `json:"request_hash"`
	Verdict        string          `json:"verdict"`
	Reason         string          `json:"reason"`
	Effect         json.RawMessage `json:"effect"`
	Sequence       uint64          `json:"journal_seq"`
	ObservedHeight int64           `json:"observed_height"`
	Peer           PeerIdentity    `json:"peer"`
}
type SignedActionReceipt struct {
	Receipt   ActionReceipt `json:"receipt"`
	Signature string        `json:"signature"`
}

func receiptDigest(r ActionReceipt) string {
	return Hash(append([]byte("swarma-action-receipt-v1"), canonical(r)...))
}
func signActionReceipt(r ActionReceipt, key *btcec.PrivateKey) SignedActionReceipt {
	h, _ := hex.DecodeString(receiptDigest(r))
	s, e := schnorr.Sign(key, h)
	if e != nil {
		panic("receipt signing")
	}
	return SignedActionReceipt{r, hex.EncodeToString(s.Serialize())}
}

// ParseActionReceipt requires the locally pinned service key and exact request;
// an unsigned error or another request's valid receipt cannot become success.
func ParseActionReceipt(raw []byte, key, requestHash, grantee string) (SignedActionReceipt, error) {
	var s SignedActionReceipt
	if strict(raw, &s) != nil || s.Receipt.Version != 1 || s.Receipt.Service != WalletServiceID || s.Receipt.Grantee != grantee || s.Receipt.RequestHash != requestHash || s.Receipt.ObservedHeight < 0 || s.Receipt.Effect == nil || !hexN(s.Signature, 64) || !rental.VerifySignature(key, receiptDigest(s.Receipt), s.Signature) {
		return s, fail("SERVICE_RECEIPT")
	}
	switch s.Receipt.Verdict {
	case "executed", "pending", "refused", "uncertain":
	default:
		return s, fail("SERVICE_RECEIPT")
	}
	if !boundedCode(s.Receipt.Reason) {
		return s, fail("SERVICE_RECEIPT")
	}
	return s, nil
}
func boundedCode(s string) bool {
	if len(s) < 1 || len(s) > 96 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func safeCode(e error) string {
	if e != nil && boundedCode(e.Error()) {
		return e.Error()
	}
	return "SERVICE_FAILURE"
}
