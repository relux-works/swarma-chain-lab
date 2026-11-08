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

const ClaimWindowSeconds int64 = 60
const ValidClaimsPerWindow = 32
const InvalidClaimsPerWindow = 8
const AuditPerSlot = 32
const AuditAdmin = 128

type ClaimWindow struct {
	Slot    string `json:"slot"`
	Since   int64  `json:"since"`
	Valid   int    `json:"valid"`
	Invalid int    `json:"invalid"`
}

type tokenState struct {
	Version      int           `json:"version"`
	Binding      string        `json:"binding"`
	Tokens       []TokenRecord `json:"tokens"`
	Audit        []Audit       `json:"audit"`
	Windows      []ClaimWindow `json:"claim_windows"`
	AuditDropped uint64        `json:"audit_dropped"`
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
		b.state = tokenState{Version: 1, Binding: binding, Tokens: []TokenRecord{}, Audit: []Audit{}, Windows: []ClaimWindow{}}
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
		windows := map[string]bool{}
		if len(b.state.Windows) > len(keys)+1 {
			s.close()
			return nil, fail("TRACKB_STATE")
		}
		for _, w := range b.state.Windows {
			_, known := keys[w.Slot]
			if (w.Slot != "" && !known) || windows[w.Slot] || w.Since < 1 || w.Valid < 0 || w.Valid > ValidClaimsPerWindow+1 || w.Invalid < 0 || w.Invalid > InvalidClaimsPerWindow+1 {
				s.close()
				return nil, fail("TRACKB_STATE")
			}
			windows[w.Slot] = true
		}
		if b.state.Windows == nil {
			b.state.Windows = []ClaimWindow{}
		}
		if b.compactAudit() {
			if e = b.persist(); e != nil {
				s.close()
				return nil, e
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
	if b.store.poison {
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
	b.compactAudit()
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
	if e := b.claimRate(slot, reason == "KEY_RELEASED"); e != nil {
		return "", e
	}
	if e := b.audit("claim", slot, hash, reason); e != nil {
		return "", e
	}
	if reason != "KEY_RELEASED" {
		return "", fail(reason)
	}
	return b.keys[slot], nil
}

// Rejected bounds and coalesces malformed/unknown calls without body data.
func (b *TrackB) Rejected(operation string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.available(); e != nil {
		return e
	}
	if e := b.claimRate("", false); e != nil {
		return e
	}
	return b.audit(operation, "", "", "MALFORMED")
}

// Unknown slots share one bounded bucket. A valid token has its own allowance
// so guessed tokens cannot consume its capacity; admin operations do not use it.
// The first over-limit call is durably coalesced; repeats do not write the disk.
func (b *TrackB) claimRate(slot string, valid bool) error {
	if _, ok := b.keys[slot]; !ok {
		slot = ""
		valid = false
	}
	now := b.now().Unix()
	if now < 1 {
		return fail("CLOCK")
	}
	i := -1
	for n, w := range b.state.Windows {
		if w.Slot == slot {
			i = n
			break
		}
	}
	if i < 0 {
		b.state.Windows = append(b.state.Windows, ClaimWindow{Slot: slot, Since: now})
		i = len(b.state.Windows) - 1
	}
	w := &b.state.Windows[i]
	if now >= w.Since && now-w.Since >= ClaimWindowSeconds {
		*w = ClaimWindow{Slot: slot, Since: now}
	}
	count, limit := &w.Invalid, InvalidClaimsPerWindow
	if valid {
		count, limit = &w.Valid, ValidClaimsPerWindow
	}
	if *count >= limit {
		if *count == limit {
			*count++
			if e := b.audit("claim", slot, "", "RATE_LIMITED"); e != nil {
				return e
			}
		}
		return fail("RATE_LIMITED")
	}
	*count++
	return nil
}

// Keep a separate bounded tail for every configured slot, admin calls, and
// malformed/unknown traffic. Rotation never changes tokens or revocation.
func (b *TrackB) compactAudit() bool {
	counts := map[string]int{}
	kept := make([]Audit, 0, len(b.state.Audit))
	dropped := uint64(0)
	for i := len(b.state.Audit) - 1; i >= 0; i-- {
		a := b.state.Audit[i]
		key := "admin"
		limit := AuditAdmin
		if a.Operation == "claim" || a.Operation == "http-rejected" {
			key = "unknown"
			limit = AuditPerSlot
			if _, ok := b.keys[a.Slot]; ok {
				key = a.Slot
			}
		}
		if counts[key] >= limit {
			dropped++
			continue
		}
		counts[key]++
		kept = append(kept, a)
	}
	if dropped == 0 {
		return false
	}
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	b.state.Audit = kept
	if ^uint64(0)-b.state.AuditDropped < dropped {
		b.state.AuditDropped = ^uint64(0)
	} else {
		b.state.AuditDropped += dropped
	}
	return true
}
