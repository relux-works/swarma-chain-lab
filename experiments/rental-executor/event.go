// Package executor implements a bounded regtest rental executor.
package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/bip340"
)

const RequestKind = 8183
const MaxMoney int64 = 21000000 * 100000000
const MaxFile = 1 << 20

type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}
type Request struct {
	Event                                 Event
	Action, Target, Slot, Nonce, Contract string
	Amount                                int64
}

func fail(s string) error  { return errors.New(s) }
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hexN(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func ascii(s string, limit int) bool {
	if len(s) > limit {
		return false
	}
	for _, c := range []byte(s) {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		panic("internal JSON encoding")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}

// Strict requires exact object fields and rejects duplicate names, aliases,
// nulls, unknown fields and trailing data. Typed decoding checks array shape.
func Strict(b []byte, out any) error {
	if len(b) == 0 || len(b) > 2<<20 || singleuse.StrictInput(b, out) != nil {
		return fail("JSON_SCHEMA")
	}
	var check func(any) bool
	check = func(v any) bool {
		switch x := v.(type) {
		case nil:
			return false
		case map[string]any:
			for _, v := range x {
				if !check(v) {
					return false
				}
			}
		case []any:
			for _, v := range x {
				if !check(v) {
					return false
				}
			}
		}
		return true
	}
	var tree any
	if json.Unmarshal(b, &tree) != nil || !check(tree) {
		return fail("JSON_SCHEMA")
	}
	var got, want map[string]json.RawMessage
	if json.Unmarshal(b, &got) != nil || json.Unmarshal(canonical(out), &want) != nil || len(got) != len(want) {
		return fail("JSON_SCHEMA")
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			return fail("JSON_SCHEMA")
		}
	}
	return nil
}
func (e Event) Digest() string {
	return Hash(canonical([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content}))
}
func ParseRequest(b []byte) (Request, error) {
	var e Event
	var r Request
	if len(b) > 8192 || Strict(b, &e) != nil || e.Kind != RequestKind || e.Content != "" || e.CreatedAt <= 0 || !hexN(e.ID, 32) || !hexN(e.Pubkey, 32) || !hexN(e.Sig, 64) {
		return r, fail("EVENT_SCHEMA")
	}
	if e.ID != e.Digest() {
		return r, fail("EVENT_ID")
	}
	pk, _ := hex.DecodeString(e.Pubkey)
	p, err := schnorr.ParsePubKey(pk)
	sb, _ := hex.DecodeString(e.Sig)
	sig, se := bip340.ParseBIP340Strict(sb)
	id, _ := hex.DecodeString(e.ID)
	if err != nil || se != nil || !sig.Verify(id, p) {
		return r, fail("EVENT_SIGNATURE")
	}
	tags := map[string]string{}
	for _, t := range e.Tags {
		if len(t) != 2 || !ascii(t[0], 16) || !ascii(t[1], 512) {
			return r, fail("REQUEST_TAGS")
		}
		if _, ok := tags[t[0]]; ok {
			return r, fail("REQUEST_TAGS")
		}
		switch t[0] {
		case "action", "amount", "target", "slot", "nonce", "contract":
		default:
			return r, fail("REQUEST_TAGS")
		}
		tags[t[0]] = t[1]
	}
	r = Request{Event: e, Action: tags["action"], Target: tags["target"], Slot: tags["slot"], Nonce: tags["nonce"], Contract: tags["contract"]}
	if !hexN(r.Slot, 32) || !hexN(r.Nonce, 32) || !hexN(r.Contract, 32) || r.Target == "" {
		return Request{}, fail("REQUEST_TAGS")
	}
	expected := 5
	switch r.Action {
	case "pay":
		expected = 6
		n, err := strconv.ParseInt(tags["amount"], 10, 64)
		if err != nil || n <= 0 || n > MaxMoney || strconv.FormatInt(n, 10) != tags["amount"] {
			return Request{}, fail("REQUEST_AMOUNT")
		}
		r.Amount = n
	case "deliver":
		if len(r.Target) != 71 || r.Target[:7] != "sha256:" || !hexN(r.Target[7:], 32) {
			return Request{}, fail("DELIVER_TARGET")
		}
	case "repository.push":
		u, err := url.Parse(r.Target)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
			return Request{}, fail("REPOSITORY_TARGET")
		}
	case "publish":
		if !ascii(r.Target, 128) {
			return Request{}, fail("PUBLISH_TARGET")
		}
	case "secret.release":
	default:
		return Request{}, fail("REQUEST_ACTION")
	}
	if len(tags) != expected || (r.Action != "pay" && tags["amount"] != "") {
		return Request{}, fail("REQUEST_TAGS")
	}
	return r, nil
}
