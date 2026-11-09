package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
)

const MaxActionFrame = 65536
const WalletServiceID = "wallet.nmc"

type ActionGrant struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}
type SpendParams struct {
	To       string `json:"to"`
	Amount   int64  `json:"amount_sat"`
	FeeLimit int64  `json:"fee_limit_sat"`
}
type ActionRequest struct {
	Version   int             `json:"v"`
	Service   string          `json:"service"`
	Action    string          `json:"action"`
	Params    json.RawMessage `json:"params"`
	Grant     ActionGrant     `json:"grant"`
	Nonce     string          `json:"nonce"`
	CreatedAt int64           `json:"created_at"`
	Grantee   string          `json:"grantee"`
}
type ActionProof struct {
	UseTxID string `json:"use_txid"`
}
type ActionEnvelope struct {
	Request   ActionRequest `json:"request"`
	Signature string        `json:"signature"`
	Proof     *ActionProof  `json:"proof,omitempty"`
}
type VerifiedAction struct {
	Envelope     ActionEnvelope
	RequestBytes []byte
	Hash         string
	Spend        SpendParams
}

// ActionDigest commits the 32 binary hash bytes, not their ASCII hex spelling.
func ActionDigest(r ActionRequest) string {
	h, _ := hex.DecodeString(Hash(canonical(r)))
	return Hash(append([]byte("swarma-action-v1"), h...))
}
func actionFields(r ActionRequest, service string) (SpendParams, error) {
	var p SpendParams
	if r.Version != 1 || r.Service != service || service != WalletServiceID || !hexN(r.Nonce, 16) || r.CreatedAt <= 0 || !hexN(r.Grantee, 32) {
		return p, fail("ACTION_SCHEMA")
	}
	switch r.Action {
	case "spend":
		if strict(r.Params, &p) != nil || p.Amount < 1 || p.Amount > MaxMoney || p.FeeLimit < 1 || p.FeeLimit > MaxFee || p.Amount > MaxMoney-p.FeeLimit {
			return p, fail("ACTION_PARAMS")
		}
		if _, e := addressScript(p.To); e != nil {
			return p, e
		}
	case "balance", "receive", "history", "budget":
		if !bytes.Equal(r.Params, []byte(`{}`)) {
			return p, fail("ACTION_PARAMS")
		}
	default:
		return p, fail("ACTION_UNSUPPORTED")
	}
	if r.Action == "spend" || r.Action == "budget" {
		if (r.Grant.Kind != "standing" && r.Grant.Kind != "single-use") || !hexN(r.Grant.ID, 32) {
			return p, fail("ACTION_GRANT")
		}
	} else if r.Grant.Kind != "none" || r.Grant.ID != "" {
		return p, fail("ACTION_GRANT")
	}
	return p, nil
}
func ParseAction(raw []byte, service string) (VerifiedAction, error) {
	var v VerifiedAction
	if len(raw) > MaxActionFrame || strict(raw, &v.Envelope) != nil {
		return v, fail("ACTION_SCHEMA")
	}
	e := v.Envelope
	r := e.Request
	p, err := actionFields(r, service)
	if err != nil {
		return VerifiedAction{}, err
	}
	if e.Proof != nil && (r.Action != "spend" || r.Grant.Kind != "single-use" || !hexN(e.Proof.UseTxID, 32)) {
		return VerifiedAction{}, fail("ACTION_PROOF")
	}
	if !hexN(e.Signature, 64) || !rental.VerifySignature(r.Grantee, ActionDigest(r), e.Signature) {
		return VerifiedAction{}, fail("ACTION_SIGNATURE")
	}
	v.RequestBytes = canonical(r)
	v.Hash = Hash(v.RequestBytes)
	v.Spend = p
	return v, nil
}
func SignAction(r ActionRequest, key *btcec.PrivateKey, proof *ActionProof) ([]byte, error) {
	if key == nil || r.Grantee != hex.EncodeToString(schnorr.SerializePubKey(key.PubKey())) {
		return nil, fail("ACTION_KEY")
	}
	h, _ := hex.DecodeString(ActionDigest(r))
	sig, e := schnorr.Sign(key, h)
	if e != nil {
		return nil, fail("ACTION_SIGN")
	}
	raw := canonical(ActionEnvelope{r, hex.EncodeToString(sig.Serialize()), proof})
	if _, e = ParseAction(raw, r.Service); e != nil {
		return nil, e
	}
	return raw, nil
}

// The shared W1 journal requires a 32-byte nonce. Map the signed 16-byte LIP
// nonce into a separate domain; the service also retains the exact wire nonce.
func (v VerifiedAction) walletRequest() Request {
	r := v.Envelope.Request
	return Request{Version: 1, GrantID: r.Grant.ID, Action: "pay", Nonce: Hash([]byte("swarma-action-nonce-v1" + r.Grantee + r.Nonce)), Address: v.Spend.To, Amount: v.Spend.Amount, FeeLimit: v.Spend.FeeLimit}
}
