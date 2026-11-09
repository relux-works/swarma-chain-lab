package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// Inline certificate presentation (detached grants, M2-04): the
// renter attaches ONE rumor tag
//
//	["grant-cert", <id>, <b64>]
//
// to its first NIP-17 message, where <b64> is base64-StdEncoding of
// the exact canonical detached-envelope JSON bytes (at most 16384
// raw bytes, the kernel Present bound) and <id> is the lowercase
// hex SHA-256 of those bytes. The gateway presents the bytes to the
// kernel (fresh Check; only live admits them into the kernel's
// bounded per-sender cache); later messages are Checked fresh
// against the cached bytes. The tag is stripped here: screening and
// station delivery only ever see the rumor content.
//
// parseGrantPresentation is the single place that knows this wire
// shape. A later grant format that changes what <id> commits to
// (K1: grant_id over the signed grant, locator outside the id)
// swaps this function only.
const grantCertTag = "grant-cert"
const maxPresentationBytes = 16384

// Deterministic gateway notice texts for presentation refusals.
// These are fixed gateway strings, never model output.
const (
	noticePresentationRequired    = "presentation required: attach your grant certificate to your next message with one grant-cert tag [\"grant-cert\", <sha256 hex id>, <base64 envelope>]."
	noticePresentationMalformed   = "presentation refused: malformed grant-cert tag; attach exactly one [\"grant-cert\", <sha256 hex id>, <base64 envelope>] tag whose id is the SHA-256 of the envelope bytes."
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
// bytes, or id not the SHA-256 of the bytes).
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
	raw, err := base64.StdEncoding.DecodeString(found[2])
	if err != nil || len(raw) == 0 || len(raw) > maxPresentationBytes {
		return nil, errPresentationMalformed
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != id {
		return nil, errPresentationMalformed
	}
	return &grantPresentation{id: id, raw: raw}, nil
}

// GrantCertTag builds the rumor tag carrying one inline
// presentation of the exact envelope bytes. It is the renter-side
// counterpart of parseGrantPresentation (clients and tests).
func GrantCertTag(envelopeBytes []byte) []string {
	sum := sha256.Sum256(envelopeBytes)
	return []string{grantCertTag, hex.EncodeToString(sum[:]),
		base64.StdEncoding.EncodeToString(envelopeBytes)}
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
