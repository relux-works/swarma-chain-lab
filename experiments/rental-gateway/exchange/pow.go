package exchange

import (
	"encoding/hex"
	"math/bits"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"strconv"
)

// CheckWork validates the recomputed rumor ID and one explicit NIP-13 target.
// NIP-17's signed seal binds the otherwise unsigned rumor to its sender.
func CheckWork(e *nostr.Event, difficulty int) bool {
	if e == nil || difficulty < 1 || difficulty > 32 || !e.CheckID() {
		return false
	}
	found := false
	for _, tag := range e.Tags {
		if len(tag) == 0 || tag[0] != "nonce" {
			continue
		}
		if found || len(tag) != 3 {
			return false
		}
		found = true
		nonce, err := strconv.ParseUint(tag[1], 10, 64)
		if err != nil || strconv.FormatUint(nonce, 10) != tag[1] {
			return false
		}
		target, err := strconv.Atoi(tag[2])
		if err != nil || strconv.Itoa(target) != tag[2] || target < difficulty || target > 256 {
			return false
		}
	}
	if !found {
		return false
	}
	raw, err := hex.DecodeString(e.ID)
	if err != nil || len(raw) != 32 {
		return false
	}
	n := 0
	for _, b := range raw {
		n += bits.LeadingZeros8(b)
		if b != 0 {
			break
		}
	}
	return n >= difficulty
}
