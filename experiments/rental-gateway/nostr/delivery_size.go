package nostr

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"unicode/utf8"
)

const DeliverySizeNotice = "reply exceeded deliverable size"

// ValidDeliveryEventLimit requires an explicit relay cap capable of carrying the
// fixed terminal notice. The upper bound is swarma-relay's supported maximum;
// operators must also keep this cap at or below the deployed relay's own cap.
func ValidDeliveryEventLimit(limit int) bool {
	n, ok := deliveryEventSize(DeliverySizeNotice)
	return ok && limit >= n && limit <= 131072
}

// BoundDeliveryReply preserves text only when the complete signed gift wrap
// fits the explicit relay cap and BOTH NIP-44 plaintext limits. Callers validate
// the cap before accepting work, so the immutable short notice always fits.
func BoundDeliveryReply(content string, relayMaxEventBytes int) string {
	n, ok := deliveryEventSize(content)
	if !ok || n > relayMaxEventBytes {
		return DeliverySizeNotice
	}
	return content
}

// The delivery shape has one e-tag and one p-tag, all IDs/keys are 64 hex bytes,
// and signatures are 128 hex bytes. MaxInt64 reserves the longest nonnegative
// timestamp, so station and gateway share a conservative bound without clocks,
// keys or encryption randomness. Base64 ciphertext has no JSON escapes.
func deliveryEventSize(content string) (int, bool) {
	if !utf8.ValidString(content) || len(content) > 32768 {
		return 0, false
	}
	hex64 := strings.Repeat("0", 64)
	rumor := Event{ID: hex64, PubKey: hex64, CreatedAt: math.MaxInt64, Kind: KindRumor, Tags: [][]string{{"e", hex64}, {"p", hex64}}, Content: content}
	raw, err := json.Marshal(rumor)
	if err != nil || len(raw) > nip44MaxPlaintext {
		return 0, false
	}
	// version + nonce + (length prefix + padded plaintext) + MAC, then base64.
	ciphertext := func(n int) string {
		return strings.Repeat("A", base64.StdEncoding.EncodedLen(1+32+2+nip44PaddedLen(n)+32))
	}
	seal := Event{ID: hex64, PubKey: hex64, CreatedAt: math.MaxInt64, Kind: KindSeal, Tags: [][]string{}, Content: ciphertext(len(raw)), Sig: strings.Repeat("0", 128)}
	raw, err = json.Marshal(seal)
	if err != nil || len(raw) > nip44MaxPlaintext {
		return 0, false
	}
	wrap := Event{ID: hex64, PubKey: hex64, CreatedAt: math.MaxInt64, Kind: KindGiftWrap, Tags: [][]string{{"p", hex64}}, Content: ciphertext(len(raw)), Sig: strings.Repeat("0", 128)}
	raw, err = json.Marshal(wrap)
	return len(raw), err == nil
}
