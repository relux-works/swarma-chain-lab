package wallet

import (
	"encoding/hex"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type ActionClientConfig struct {
	Version    int    `json:"version"`
	Service    string `json:"service"`
	Socket     string `json:"socket"`
	ServiceUID uint32 `json:"service_uid"`
	ReceiptKey string `json:"receipt_key"`
	KeyFile    string `json:"key_file"`
}

// Client pins contain no RPC, journal, wallet or service-configuration access.
func LoadActionClientConfig(path string) (ActionClientConfig, error) {
	var c ActionClientConfig
	b, e := su.PublicFile(path, 8192)
	if e != nil {
		return c, fail("CLIENT_CONFIG")
	}
	if su.StrictInput(b, &c) != nil || c.Version != 1 || c.Service != WalletServiceID || c.ServiceUID == 0 || !hexN(c.ReceiptKey, 32) {
		return c, fail("CLIENT_CONFIG")
	}
	for _, p := range []string{c.Socket, c.KeyFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, fail("CLIENT_CONFIG")
		}
	}
	k, _ := hex.DecodeString(c.ReceiptKey)
	if _, e = schnorr.ParsePubKey(k); e != nil {
		return c, fail("CLIENT_CONFIG")
	}
	return c, nil
}
func ParseActionRequest(raw []byte) (ActionRequest, error) {
	var r ActionRequest
	if strict(raw, &r) != nil {
		return r, fail("ACTION_SCHEMA")
	}
	_, e := actionFields(r, WalletServiceID)
	return r, e
}
func ActionErrorReason(e error) string { return safeCode(e) }
