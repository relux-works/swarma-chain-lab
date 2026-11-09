package gateway

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// A renter presents one ["grant-cert", <grant_id>, <base64 presentation>]
// tag. The v3 presentation is {signed_grant, issuance:{txid}} in canonical
// JSON. grant_id hashes only the canonical signed grant; the locator is
// untrusted and checked by the kernel. At most 16384 decoded bytes are
// accepted. Only content reaches screening and the station.
const grantCertTag = "grant-cert"
const maxPresentationBytes = 16384

// Deterministic gateway notice texts for presentation refusals.
// These are fixed gateway strings, never model output.
const (
	noticePresentationRequired    = "presentation required: attach your v3 grant to your next message with one grant-cert tag [\"grant-cert\", <grant_id>, <base64 presentation>]."
	noticePresentationMalformed   = "presentation refused: malformed grant-cert tag; attach exactly one [\"grant-cert\", <grant_id>, <base64 presentation>] tag whose id is the SHA-256 of the canonical signed grant."
	noticePresentationUnsupported = "presentation refused: inline presentation is not enabled on this gateway."
)

var errPresentationMalformed = errors.New("malformed grant-cert tag")

type grantPresentation struct {
	id  string
	raw []byte
}

// parseGrantPresentation extracts the inline presentation from a
// rumor: (nil, nil) when absent, an error when malformed (more
// than one tag, wrong arity, bad id form, undecodable or oversize
// bytes, invalid v3 framing, or mismatched stable signed-grant id).
func parseGrantPresentation(rumor *nostr.Event) (*grantPresentation, error) {
	var found []string
	count := 0
	for _, tag := range rumor.Tags {
		if len(tag) > 0 && tag[0] == grantCertTag {
			count++
			found = tag
		}
	}
	if count == 0 {
		return nil, nil
	}
	if count > 1 || len(found) != 3 {
		return nil, errPresentationMalformed
	}
	id := found[1]
	if len(id) != 64 || !isLowerHex(id) {
		return nil, errPresentationMalformed
	}
	if len(found[2]) > base64.StdEncoding.EncodedLen(maxPresentationBytes) {
		return nil, errPresentationMalformed
	}
	raw, err := base64.StdEncoding.DecodeString(found[2])
	if err != nil || len(raw) == 0 || len(raw) > maxPresentationBytes {
		return nil, errPresentationMalformed
	}
	got, err := kernel.PresentationID(raw)
	if err != nil || got != id {
		return nil, errPresentationMalformed
	}
	return &grantPresentation{id: id, raw: raw}, nil
}

// GrantCertTag builds a v3 tag, refusing invalid transport framing. It does
// not attest authority; the recipient must call the real kernel Presenter.
func GrantCertTag(presentation []byte) ([]string, error) {
	id, err := kernel.PresentationID(presentation)
	if err != nil {
		return nil, err
	}
	return []string{grantCertTag, id, base64.StdEncoding.EncodeToString(presentation)}, nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// presentationNotice DMs one deterministic gateway text to the slot
// renter and marks the result when the publish succeeds.
func (g *Gateway) presentationNotice(ctx context.Context, slot *journal.Slot, res *Result, text string) {
	if err := g.dmRenter(ctx, slot, text); err == nil {
		res.WarningSent = true
	}
}
