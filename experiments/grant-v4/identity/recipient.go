package identity

import (
	"bytes"
	"errors"
)

// NostrMember states either a key string or the names map of the nostr member.
// It is not a parser for a name value. Only names["_"] yields the recipient key.
type NostrMember struct {
	Key   string
	Names map[string]string
}

func validSigningKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	_, err := ParsePin("02" + key)
	return err == nil
}

func (n NostrMember) channelKey() (string, bool) {
	if n.Key != "" && n.Names != nil {
		return "", false
	}
	key := n.Key
	if n.Names != nil {
		key = n.Names["_"]
	}
	return key, validSigningKey(key)
}

// NameRecipient is the signed name/owner choice, not a grant wire schema.
type NameRecipient struct {
	Name  []byte
	Owner Pin
}

// Recipient is a union: exactly one pointer must be present. By-key mode has
// no name (signed or unsigned); by-name mode has no request key or output pin.
type Recipient struct {
	RequestKey *string
	ByName     *NameRecipient
}

var (
	ErrRecipientUnion = errors.New("identity: select exactly one recipient mode")
	ErrRecipientKey   = errors.New("identity: invalid or mismatching request key")
	ErrChannel        = errors.New("identity: unsupported channel or missing channel key")
)

// ResolveRecipient returns the selected channel's key from the SAME stated
// output whose ownership passes. Only the Nostr channel is defined by the draft.
// By-key mode never reads state. This performs no signature authentication.
func ResolveRecipient(r Recipient, channel string, state *StatedName) (string, error) {
	if (r.RequestKey == nil) == (r.ByName == nil) {
		return "", ErrRecipientUnion
	}
	if channel != "nostr" {
		return "", ErrChannel
	}
	if r.RequestKey != nil {
		if !validSigningKey(*r.RequestKey) {
			return "", ErrRecipientKey
		}
		return *r.RequestKey, nil
	}
	if state == nil || !r.ByName.Owner.Valid() || !bytes.Equal(r.ByName.Name, state.Name) ||
		r.ByName.Owner.String() != state.Owner.String() {
		return "", RecipientNameUnavailable
	}
	d := CheckRecipientOwner(*state)
	if !d.Passes() {
		return "", d.refusals[0]
	}
	key, ok := state.Outputs[0].Nostr.channelKey()
	if !ok {
		return "", ErrChannel
	}
	return key, nil
}

// CheckRecipientKey compares a stated request signer to the resolved key. The
// caller still verifies the selected channel's signature and request binding.
func CheckRecipientKey(r Recipient, channel, signer string, state *StatedName) error {
	key, err := ResolveRecipient(r, channel, state)
	if err != nil {
		return err
	}
	if signer != key {
		return ErrRecipientKey
	}
	return nil
}

// CheckConsentKey adds W7.6 condition 5 to the historical evidence check. A
// later channel-key rotation does not change the consenting key at R. created_at
// is deliberately no input; its seconds checks belong to the consent pipeline.
func CheckConsentKey(s StatedName, recent Height, evidence, signer string) Decision {
	out, ok := consentOutput(s, recent, evidence)
	if !ok {
		return decide(ConsentEvidence)
	}
	key, ok := out.Nostr.channelKey()
	if !ok || signer != key {
		return decide(ConsentKey)
	}
	return decide()
}
