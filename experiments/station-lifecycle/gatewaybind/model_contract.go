package gatewaybind

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
)

// Derive the original binding without consulting mutable operator config so
// revocation still targets the correct registry entry after a config change.
// The gateway's kernel owns signature and current chain admission; this checks
// that contract bytes are bound to that presentation, journal and slot window.
func boundModelBinding(s *journal.Slot) (proxy.Binding, error) {
	refuse := func() (proxy.Binding, error) { return proxy.Binding{}, errors.New("MODEL_CONTRACT") }
	if s == nil || len(s.ContractB64) == 0 || len(s.ContractB64) > 11000 {
		return refuse()
	}
	raw, e := base64.StdEncoding.DecodeString(s.ContractB64)
	var c booking.ContractV2
	if e != nil || len(raw) > 8192 || booking.Strict(raw, &c) != nil || !bytes.Equal(raw, c.Bytes()) || c.Validate() != nil || c.ModelCaps == nil || !c.ModelCaps.Valid() || c.Hash() != s.ContractSHA256 || c.BookingID != s.BookingID || c.RenterPubkey != s.RenterPubKey || c.StationName != s.StationName || c.NotBefore != s.NotBefore || c.NotAfter != s.NotAfter {
		return refuse()
	}
	presentation, e := base64.StdEncoding.DecodeString(s.CertificateB64)
	if e != nil {
		return refuse()
	}
	id, e := kernel.PresentationID(presentation)
	if e != nil {
		return refuse()
	}
	var p struct {
		SignedGrant struct {
			Grant struct {
				ContractSHA256 string `json:"contract_sha256"`
				GranteeKey     string `json:"grantee_key"`
				AgentName      string `json:"agent_name"`
				NotBefore      int64  `json:"not_before"`
				NotAfter       int64  `json:"not_after"`
			} `json:"grant"`
		} `json:"signed_grant"`
	}
	if json.Unmarshal(presentation, &p) != nil {
		return refuse()
	}
	g := p.SignedGrant.Grant
	if g.ContractSHA256 != c.Hash() || g.GranteeKey != c.RenterPubkey || g.AgentName != c.StationName || g.NotBefore != c.NotBefore || g.NotAfter != c.NotAfter {
		return refuse()
	}
	m := c.ModelCaps
	b := proxy.Binding{SlotID: s.BookingID, GrantID: id, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Caps: proxy.Caps{InputTokens: m.InputTokens, OutputTokens: m.OutputTokens, Requests: m.Requests, MaxTokens: m.MaxTokens, CostNanoUSD: m.CostNanoUSD, DefaultMaxOutputTokens: m.DefaultMaxOutputTokens}}
	if !b.Valid() {
		return refuse()
	}
	return b, nil
}
