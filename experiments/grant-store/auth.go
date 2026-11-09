// Package grantstore provides a bounded Blossom grant store. Signed HTTP
// authorization identifies callers; it does not attest K1 grant authority.
package grantstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

const AuthBytes = 8192
const KindAuth = 24242

var errAuth = errors.New("invalid authorization")

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func digest(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func key(v string) bool { return digest(v) && nostr.ParseXOnlyPubKey(v) == nil }

type authorization struct {
	Event   *nostr.Event
	Expiry  int64
	Readers []string
}

// AuthHeader emits the current BUD-11 base64url encoding. A random nonce tag
// distinguishes two requests signed within the same second. The server scope
// is a lowercase hostname (no scheme/port); it is not inferred from a request.
func AuthHeader(signer *nostr.PrivKey, action, hash, server string, readers []string, now time.Time) (string, error) {
	if signer == nil {
		return "", errAuth
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return "", e
	}
	tags := [][]string{{"t", action}, {"expiration", strconv.FormatInt(now.Unix()+300, 10)}, {"nonce", hex.EncodeToString(nonce)}}
	if hash != "" {
		if !digest(hash) {
			return "", errAuth
		}
		tags = append(tags, []string{"x", hash})
	}
	if server != "" {
		tags = append(tags, []string{"server", server})
	}
	for _, reader := range readers {
		if !key(reader) {
			return "", errAuth
		}
		tags = append(tags, []string{"p", reader})
	}
	ev := &nostr.Event{CreatedAt: now.Unix(), Kind: KindAuth, Tags: tags, Content: "Authorize Blossom " + action}
	if e := signer.SignEvent(ev); e != nil {
		return "", e
	}
	raw, e := json.Marshal(ev)
	if e != nil || len(raw) > AuthBytes {
		return "", errAuth
	}
	return "Nostr " + base64.RawURLEncoding.EncodeToString(raw), nil
}
func parseAuth(header, action, hash, server string, now, skew int64) (authorization, error) {
	var a authorization
	if len(header) > 6+base64.StdEncoding.EncodedLen(AuthBytes) || !strings.HasPrefix(header, "Nostr ") {
		return a, errAuth
	}
	value := strings.TrimPrefix(header, "Nostr ")
	raw, e := base64.RawURLEncoding.Strict().DecodeString(value)
	if e != nil {
		raw, e = base64.StdEncoding.Strict().DecodeString(value)
	} // older Blossom clients
	if e != nil || len(raw) == 0 || len(raw) > AuthBytes {
		return a, errAuth
	}
	ev, e := nostr.ParseEvent(raw)
	if e != nil || !ev.CheckID() || nostr.VerifySignature(ev) != nil || ev.Kind != KindAuth || len(ev.Content) == 0 || len(ev.Content) > 512 || len(ev.Tags) > 80 {
		return a, errAuth
	}
	if ev.CreatedAt < 0 || ev.CreatedAt > now+skew {
		return a, errAuth
	}
	counts := map[string]int{}
	matchedHash := false
	serverCount := 0
	matchedServer := false
	readers := map[string]bool{}
	for _, tag := range ev.Tags {
		if len(tag) != 2 || len(tag[0]) > 32 || len(tag[1]) > 256 {
			return a, errAuth
		}
		counts[tag[0]]++
		switch tag[0] {
		case "t":
			if tag[1] != action || counts["t"] != 1 {
				return a, errAuth
			}
		case "expiration":
			exp, err := strconv.ParseInt(tag[1], 10, 64)
			if err != nil || strconv.FormatInt(exp, 10) != tag[1] || exp <= now || exp-now > 300 || exp <= ev.CreatedAt || exp-ev.CreatedAt > 300 || counts["expiration"] != 1 {
				return a, errAuth
			}
			a.Expiry = exp
		case "x":
			if !digest(tag[1]) {
				return a, errAuth
			}
			matchedHash = matchedHash || tag[1] == hash
		case "server":
			serverCount++
			if tag[1] == "" || tag[1] != strings.ToLower(tag[1]) || strings.ContainsAny(tag[1], "/@?# ") || (strings.Contains(tag[1], ":") && net.ParseIP(tag[1]) == nil) {
				return a, errAuth
			}
			matchedServer = matchedServer || tag[1] == server
		case "p":
			if action != "upload" || !key(tag[1]) || readers[tag[1]] {
				return a, errAuth
			}
			readers[tag[1]] = true
			a.Readers = append(a.Readers, tag[1])
		}
	}
	if counts["t"] != 1 || counts["expiration"] != 1 || (hash != "" && !matchedHash) || (action == "upload" && counts["x"] != 1) || (serverCount > 0 && !matchedServer) || len(a.Readers) > 64 {
		return a, errAuth
	}
	a.Event = ev
	return a, nil
}
