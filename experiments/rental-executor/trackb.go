package executor

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

type TokenRecord struct {
	Slot      string `json:"slot"`
	TokenHash string `json:"token_sha256"`
	Revoked   bool   `json:"revoked"`
}
type Audit struct {
	Time      int64  `json:"time"`
	Operation string `json:"operation"`
	Slot      string `json:"slot"`
	TokenHash string `json:"token_sha256"`
	Outcome   string `json:"outcome"`
}
type tokenState struct {
	Version int           `json:"version"`
	Binding string        `json:"binding"`
	Tokens  []TokenRecord `json:"tokens"`
	Audit   []Audit       `json:"audit"`
}
type TrackB struct {
	mu    sync.Mutex
	store *store
	state tokenState
	keys  map[string]string
	now   func() time.Time
}

// OpenTrackB accepts only local throwaway regtest private scalars. Configuration
// stays in private operator custody; state/audit retain key commitments only.
func OpenTrackB(root, network string, prizes map[string]string) (*TrackB, error) {
	if network != "regtest" || len(prizes) == 0 || len(prizes) > 256 {
		return nil, fail("TRACKB_CONFIG")
	}
	keys := map[string]string{}
	pins := map[string]string{}
	for slot, key := range prizes {
		if !hexN(slot, 32) || !hexN(key, 32) {
			return nil, fail("TRACKB_CONFIG")
		}
		raw, _ := hex.DecodeString(key)
		var scalar btcec.ModNScalar
		if scalar.SetByteSlice(raw) || scalar.IsZero() {
			return nil, fail("TRACKB_KEY")
		}
		keys[slot] = key
		pins[slot] = Hash(raw)
	}
	s, e := openStore(root)
	if e != nil {
		return nil, e
	}
	b := &TrackB{store: s, keys: keys, now: time.Now}
	binding := Hash(canonical(pins))
	raw, e := s.read("trackb.json")
	if e != nil {
		s.close()
		return nil, e
	}
	if raw == nil {
		b.state = tokenState{Version: 1, Binding: binding, Tokens: []TokenRecord{}, Audit: []Audit{}}
		if e = b.persist(); e != nil {
			s.close()
			return nil, e
		}
	} else {
		if Strict(raw, &b.state) != nil || b.state.Version != 1 || b.state.Binding != binding || len(b.state.Audit) > 10000 || len(b.state.Tokens) > len(keys) {
			s.close()
			return nil, fail("TRACKB_STATE")
		}
		seen := map[string]bool{}
		hashes := map[string]bool{}
		for _, r := range b.state.Tokens {
			if _, ok := keys[r.Slot]; !ok || seen[r.Slot] || !hexN(r.TokenHash, 32) || hashes[r.TokenHash] {
				s.close()
				return nil, fail("TRACKB_STATE")
			}
			seen[r.Slot] = true
			hashes[r.TokenHash] = true
		}
		for _, a := range b.state.Audit {
			if a.Time <= 0 || (a.Slot != "" && !hexN(a.Slot, 32)) || (a.TokenHash != "" && !hexN(a.TokenHash, 32)) || !ascii(a.Operation, 32) || !ascii(a.Outcome, 64) {
				s.close()
				return nil, fail("TRACKB_STATE")
			}
		}
	}
	return b, nil
}
func (b *TrackB) Close() { b.mu.Lock(); defer b.mu.Unlock(); b.store.close() }
func (b *TrackB) persist() error {
	if e := b.store.write("trackb.json", canonical(b.state)); e != nil {
		b.store.poison = true
		return e
	}
	return nil
}
func (b *TrackB) available() error {
	if b.store.poison || len(b.state.Audit) >= 10000 {
		return fail("TRACKB_UNAVAILABLE")
	}
	return nil
}
func (b *TrackB) audit(op, slot, hash, outcome string) error {
	if e := b.available(); e != nil {
		return e
	}
	if !hexN(slot, 32) {
		slot = ""
	}
	if !hexN(hash, 32) {
		hash = ""
	}
	at := b.now().Unix()
	if at <= 0 {
		return fail("CLOCK")
	}
	b.state.Audit = append(b.state.Audit, Audit{at, op, slot, hash, outcome})
	return b.persist()
}
func (b *TrackB) index(slot string) int {
	for i, r := range b.state.Tokens {
		if r.Slot == slot {
			return i
		}
	}
	return -1
}
func (b *TrackB) Mint(slot string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.available(); e != nil {
		return "", e
	}
	reason := "MINTED"
	if _, ok := b.keys[slot]; !ok {
		reason = "UNKNOWN_SLOT"
	} else if b.index(slot) >= 0 {
		reason = "TOKEN_EXISTS"
	}
	if reason != "MINTED" {
		if e := b.audit("mint", slot, "", reason); e != nil {
			return "", e
		}
		return "", fail(reason)
	}
	var raw [32]byte
	if _, e := rand.Read(raw[:]); e != nil {
		if ae := b.audit("mint", slot, "", "RANDOM_FAILED"); ae != nil {
			return "", ae
		}
		return "", fail("RANDOM_FAILED")
	}
	token := hex.EncodeToString(raw[:])
	hash := Hash([]byte(token))
	for _, r := range b.state.Tokens {
		if r.TokenHash == hash {
			if e := b.audit("mint", slot, hash, "TOKEN_COLLISION"); e != nil {
				return "", e
			}
			return "", fail("TOKEN_COLLISION")
		}
	}
	b.state.Tokens = append(b.state.Tokens, TokenRecord{Slot: slot, TokenHash: hash})
	if e := b.audit("mint", slot, hash, reason); e != nil {
		return "", e
	}
	return token, nil
}
func (b *TrackB) Revoke(slot string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.available(); e != nil {
		return e
	}
	i := b.index(slot)
	if i < 0 {
		if e := b.audit("revoke", slot, "", "UNKNOWN_SLOT"); e != nil {
			return e
		}
		return fail("UNKNOWN_SLOT")
	}
	b.state.Tokens[i].Revoked = true
	return b.audit("revoke", slot, b.state.Tokens[i].TokenHash, "REVOKED")
}
func (b *TrackB) List() ([]TokenRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.audit("list", "", "", "LISTED"); e != nil {
		return nil, e
	}
	v := append([]TokenRecord{}, b.state.Tokens...)
	sort.Slice(v, func(i, j int) bool { return v[i].Slot < v[j].Slot })
	return v, nil
}
func (b *TrackB) Claim(slot, token string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.available(); e != nil {
		return "", e
	}
	hash := ""
	if hexN(token, 32) {
		hash = Hash([]byte(token))
	}
	i := b.index(slot)
	reason := "TOKEN_REFUSED"
	if i >= 0 && hash != "" && !b.state.Tokens[i].Revoked && subtle.ConstantTimeCompare([]byte(hash), []byte(b.state.Tokens[i].TokenHash)) == 1 {
		reason = "KEY_RELEASED"
	}
	if e := b.audit("claim", slot, hash, reason); e != nil {
		return "", e
	}
	if reason != "KEY_RELEASED" {
		return "", fail(reason)
	}
	return b.keys[slot], nil
}

// Rejected records malformed/unknown endpoint calls without retaining body data.
func (b *TrackB) Rejected(operation string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.audit(operation, "", "", "MALFORMED")
}
