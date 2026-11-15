package notarycheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var integer = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var nameRE = regexp.MustCompile(`^id/[a-z0-9_.-]{1,252}$`)
var repoRE = regexp.MustCompile(`^https://[a-z0-9.-]+/[A-Za-z0-9_./-]+$`)

func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return nil
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func hash(b []byte) string                  { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func tagged(prefix string, b []byte) string { return hash(append([]byte(prefix), b...)) }
func ishex(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func key(s string) bool {
	if !ishex(s, 64) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}
func owner(s string) bool {
	if !ishex(s, 66) || (s[:2] != "02" && s[:2] != "03") {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := btcec.ParsePubKey(b)
	return e == nil
}
func signature(k, digest, sig string) bool {
	if !key(k) || !ishex(digest, 64) || !ishex(sig, 128) {
		return false
	}
	kb, _ := hex.DecodeString(k)
	db, _ := hex.DecodeString(digest)
	sb, _ := hex.DecodeString(sig)
	// Explicit BIP-340 bounds: library parsing alone historically accepted s >= n.
	p, _ := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	n, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	if bytes.Compare(sb[:32], p) >= 0 || bytes.Compare(sb[32:], n) >= 0 {
		return false
	}
	pk, e := schnorr.ParsePubKey(kb)
	if e != nil {
		return false
	}
	s, e := schnorr.ParseSignature(sb)
	return e == nil && s.Verify(db, pk)
}

// lexical enforces canonical spellings at every depth before semantic rules.
// Object order and duplicate members are preserved for typed shape comparison.
func lexical(raw []byte, limit int) bool {
	if len(raw) == 0 || len(raw) > limit {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out bytes.Buffer
	var value func() bool
	value = func() bool {
		t, e := d.Token()
		if e != nil {
			return false
		}
		switch v := t.(type) {
		case json.Delim:
			if v != '{' && v != '[' {
				return false
			}
			out.WriteByte(byte(v))
			first := true
			for d.More() {
				if !first {
					out.WriteByte(',')
				}
				first = false
				if v == '{' {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || !ascii(s) {
						return false
					}
					out.Write(canonical(s))
					out.WriteByte(':')
				}
				if !value() {
					return false
				}
			}
			close, e := d.Token()
			if e != nil || (v == '{' && close != json.Delim('}')) || (v == '[' && close != json.Delim(']')) {
				return false
			}
			out.WriteByte(byte(close.(json.Delim)))
		case string:
			if !ascii(v) {
				return false
			}
			out.Write(canonical(v))
		case json.Number:
			if !integer.MatchString(string(v)) {
				return false
			}
			if _, e := strconv.ParseInt(string(v), 10, 64); e != nil {
				return false
			}
			out.WriteString(string(v))
		default:
			return false
		}
		return true
	}
	if !value() {
		return false
	}
	_, e := d.Token()
	return e == io.EOF && bytes.Equal(out.Bytes(), raw)
}
func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}
func decode(raw []byte, out any, limit int) bool {
	if !lexical(raw, limit) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && bytes.Equal(canonical(out), raw)
}
func sorted(s []string) bool {
	if s == nil {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}
func contains(s []string, k string) bool {
	for _, v := range s {
		if v == k {
			return true
		}
	}
	return false
}
func subset(a, b []string) bool {
	for _, v := range a {
		if !contains(b, v) {
			return false
		}
	}
	return true
}
func repository(s string) bool {
	if len(s) > 200 || !repoRE.MatchString(s) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(s, "https://"), "/")
	labels := strings.Split(parts[0], ".")
	if len(labels) < 2 {
		return false
	}
	for _, v := range labels {
		if len(v) < 1 || len(v) > 63 || v[0] == '-' || v[len(v)-1] == '-' {
			return false
		}
	}
	for _, v := range parts[1:] {
		if v == "" || v == "." || v == ".." {
			return false
		}
	}
	return true
}
