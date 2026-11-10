package payloadjournal_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	codec "github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadjournal"
)

// The published SHA256("abc") vector is an independent digest/byte oracle, not
// an encoder-generated expectation. "abc" is not a valid payload bootstrap.
const goldenHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
const goldenBinding = "{\"v\":1,\"kind\":\"binding\",\"bootstrap_sha256\":\"" + goldenHash + "\"}\n"
const goldenLock = "{\"v\":1,\"kind\":\"lock\",\"bootstrap_sha256\":\"" + goldenHash + "\"}\n"

func present(b []byte) codec.File { return codec.File{Present: true, Bytes: b} }

// Proves the producer and consumer match the documented exact bytes and checked-
// in golden files, including the LF, filenames and version; not bootstrap validity.
func TestGoldenV1(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))
	if hex.EncodeToString(sum[:]) != goldenHash || codec.Version != 1 || codec.BindingName != "binding.json" || codec.LockName != "delivery.lock" || codec.MaxFileBytes != 256 {
		t.Fatal("published contract changed")
	}
	binding, lock, err := codec.Encode(goldenHash)
	if err != nil || !bytes.Equal(binding, []byte(goldenBinding)) || !bytes.Equal(lock, []byte(goldenLock)) {
		t.Fatal("encoder differs from independent golden bytes", err)
	}
	for path, want := range map[string]string{"testdata/binding-v1.json": goldenBinding, "testdata/lock-v1.json": goldenLock} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatal("golden fixture differs", path, err)
		}
	}
	if err := codec.Validate(present(binding), present(lock), goldenHash); err != nil {
		t.Fatal("valid golden pair refused", err)
	}
}

// Each refusal has the valid golden neighbor; the exact error and unchanged
// caller bytes are asserted. This checks byte admission, not file metadata/I/O.
func TestRefusals(t *testing.T) {
	other := strings.Repeat("0", 64)
	change := func(from, to string) string {
		s := strings.Replace(goldenBinding, from, to, 1)
		if s == goldenBinding {
			t.Fatal("mutation did not apply", from)
		}
		return s
	}
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"zero bytes", "", codec.ErrCorrupt},
		{"truncated", goldenBinding[:len(goldenBinding)-3], codec.ErrCorrupt},
		{"missing LF", strings.TrimSuffix(goldenBinding, "\n"), codec.ErrCorrupt},
		{"CRLF", strings.TrimSuffix(goldenBinding, "\n") + "\r\n", codec.ErrCorrupt},
		{"two LF", goldenBinding + "\n", codec.ErrCorrupt},
		{"space", " " + goldenBinding, codec.ErrCorrupt},
		{"BOM", "\xef\xbb\xbf" + goldenBinding, codec.ErrCorrupt},
		{"trailing record", goldenBinding + goldenBinding, codec.ErrCorrupt},
		{"null", "null\n", codec.ErrCorrupt},
		{"array", "[]\n", codec.ErrCorrupt},
		{"unknown field", change("{", "{\"extra\":1,"), codec.ErrCorrupt},
		{"duplicate version", change("{", "{\"v\":1,"), codec.ErrCorrupt},
		{"duplicate hash", change("{", "{\"bootstrap_sha256\":\""+other+"\","), codec.ErrCorrupt},
		{"field case", change("\"v\"", "\"V\""), codec.ErrCorrupt},
		{"field order", change("\"v\":1,\"kind\":\"binding\"", "\"kind\":\"binding\",\"v\":1"), codec.ErrCorrupt},
		{"missing version", change("\"v\":1,", ""), codec.ErrCorrupt},
		{"zero version", change("\"v\":1", "\"v\":0"), codec.ErrCorrupt},
		{"negative version", change("\"v\":1", "\"v\":-1"), codec.ErrCorrupt},
		{"string version", change("\"v\":1", "\"v\":\"1\""), codec.ErrCorrupt},
		{"float version", change("\"v\":1", "\"v\":1.0"), codec.ErrCorrupt},
		{"exponent version", change("\"v\":1", "\"v\":1e0"), codec.ErrCorrupt},
		{"null version", change("\"v\":1", "\"v\":null"), codec.ErrCorrupt},
		{"overflow version", change("\"v\":1", "\"v\":18446744073709551616"), codec.ErrCorrupt},
		{"unsupported version", change("\"v\":1", "\"v\":2"), codec.ErrUnsupported},
		{"max version", change("\"v\":1", "\"v\":18446744073709551615"), codec.ErrUnsupported},
		{"version plus corrupt", change("\"v\":1", "\"v\":2") + " ", codec.ErrCorrupt},
		{"wrong kind", change("binding", "lock"), codec.ErrCorrupt},
		{"missing kind", change("\"kind\":\"binding\",", ""), codec.ErrCorrupt},
		{"empty digest", change(goldenHash, ""), codec.ErrCorrupt},
		{"short digest", change(goldenHash, goldenHash[:63]), codec.ErrCorrupt},
		{"long digest", change(goldenHash, goldenHash+"0"), codec.ErrCorrupt},
		{"uppercase digest", change(goldenHash, strings.ToUpper(goldenHash)), codec.ErrCorrupt},
		{"nonhex digest", change(goldenHash, strings.Repeat("g", 64)), codec.ErrCorrupt},
		{"escaped digest", change("ba7816", "\\u0062a7816"), codec.ErrCorrupt},
		{"wrong digest", change(goldenHash, other), codec.ErrBinding},
		{"unsupported before mismatch", strings.Replace(change("\"v\":1", "\"v\":2"), goldenHash, other, 1), codec.ErrUnsupported},
		{"legacy DA1", "{\"hash\":\"" + goldenHash + "\"}", codec.ErrCorrupt},
		{"at size bound malformed", strings.Repeat(" ", codec.MaxFileBytes), codec.ErrCorrupt},
		{"over size bound", strings.Repeat(" ", codec.MaxFileBytes+1), codec.ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, target := range []string{"binding", "lock"} {
				binding, lock := []byte(goldenBinding), []byte(goldenLock)
				bad := []byte(tc.raw)
				if target == "binding" {
					binding = bad
				} else {
					// Apply the same encoding violation to the lock record. For the
					// wrong-kind case, explicitly use a binding record instead.
					lock = bytes.ReplaceAll(bad, []byte(`"kind":"binding"`), []byte(`"kind":"lock"`))
					if tc.name == "wrong kind" {
						lock = []byte(goldenBinding)
					}
				}
				beforeB, beforeL := bytes.Clone(binding), bytes.Clone(lock)
				if err := codec.Validate(present(binding), present(lock), goldenHash); err != tc.want {
					t.Fatalf("%s: got %v, want %v", target, err, tc.want)
				}
				if !bytes.Equal(binding, beforeB) || !bytes.Equal(lock, beforeL) {
					t.Fatal("refusal changed input bytes")
				}
				if err := codec.Validate(present([]byte(goldenBinding)), present([]byte(goldenLock)), goldenHash); err != nil {
					t.Fatal("valid neighbor refused", err)
				}
			}
		})
	}
}

// Consumers use these public codes across the provisioning/launch boundary;
// their exact strings carry no record bytes or underlying parser diagnostics.
func TestPublicCodes(t *testing.T) {
	for code, want := range map[codec.Code]string{
		codec.ErrMissing:     "PAYLOAD_JOURNAL_MISSING",
		codec.ErrUnsupported: "PAYLOAD_JOURNAL_UNSUPPORTED",
		codec.ErrCorrupt:     "PAYLOAD_JOURNAL_CORRUPT",
		codec.ErrBinding:     "PAYLOAD_JOURNAL_BINDING",
	} {
		if code.Error() != want {
			t.Fatalf("public code changed: got %s, want %s", code.Error(), want)
		}
	}
}

// Absence is explicit: an existing empty/nil byte slice is corruption, not a
// first-launch signal. Mixed errors follow the documented deterministic order.
func TestPresenceAndPrecedence(t *testing.T) {
	b, l := present([]byte(goldenBinding)), present([]byte(goldenLock))
	cases := []struct {
		name string
		b, l codec.File
		want error
	}{
		{"both missing", codec.File{}, codec.File{}, codec.ErrMissing},
		{"binding missing", codec.File{}, l, codec.ErrMissing},
		{"lock missing", b, codec.File{}, codec.ErrMissing},
		{"existing nil binding", present(nil), l, codec.ErrCorrupt},
		{"existing nil lock", b, present(nil), codec.ErrCorrupt},
		{"absent binding with bytes", codec.File{Bytes: b.Bytes}, l, codec.ErrCorrupt},
		{"absent lock with bytes", b, codec.File{Bytes: l.Bytes}, codec.ErrCorrupt},
		{"missing before corrupt", present(nil), codec.File{}, codec.ErrMissing},
		{"binding before lock", present([]byte(strings.Replace(goldenBinding, `"v":1`, `"v":2`, 1))), present(nil), codec.ErrUnsupported},
		{"swapped files", l, b, codec.ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			beforeB, beforeL := bytes.Clone(tc.b.Bytes), bytes.Clone(tc.l.Bytes)
			if err := codec.Validate(tc.b, tc.l, goldenHash); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if !bytes.Equal(beforeB, tc.b.Bytes) || !bytes.Equal(beforeL, tc.l.Bytes) {
				t.Fatal("input changed")
			}
			if err := codec.Validate(b, l, goldenHash); err != nil {
				t.Fatal("valid neighbor", err)
			}
		})
	}
}

// Invalid independent expectations cannot produce partial initialization bytes
// or authorize a pair; another valid expectation must match both files exactly.
func TestExpectedDigest(t *testing.T) {
	for _, bad := range []string{"", "x", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.ToUpper(goldenHash), strings.Repeat("g", 64), goldenHash + "\n"} {
		b, l, err := codec.Encode(bad)
		if err != codec.ErrCorrupt || b != nil || l != nil {
			t.Fatal("invalid digest produced bytes", err)
		}
		if err := codec.Validate(present([]byte(goldenBinding)), present([]byte(goldenLock)), bad); err != codec.ErrCorrupt {
			t.Fatal("invalid expectation", err)
		}
		if err := codec.Validate(codec.File{}, codec.File{}, bad); err != codec.ErrCorrupt {
			t.Fatal("expectation precedence", err)
		}
	}
	other := strings.Repeat("0", 64)
	b, l, err := codec.Encode(other)
	if err != nil || codec.Validate(present(b), present(l), other) != nil {
		t.Fatal("valid other binding refused", err)
	}
	if err := codec.Validate(present(b), present(l), goldenHash); err != codec.ErrBinding {
		t.Fatal("foreign pair accepted", err)
	}
	if err := codec.Validate(present([]byte(goldenBinding)), present([]byte(goldenLock)), other); err != codec.ErrBinding {
		t.Fatal("independent expectation ignored", err)
	}
	b[0] = '['
	freshB, freshL, err := codec.Encode(other)
	if err != nil || codec.Validate(present(freshB), present(freshL), other) != nil || bytes.Equal(b, freshB) {
		t.Fatal("encoder reused mutable output")
	}
}

// The oracle is the literal documented pair, not a second codec. Fuzzing checks
// exact-byte acceptance and unchanged inputs for a fixed independent binding.
func FuzzValidateExactPair(f *testing.F) {
	f.Add([]byte(goldenBinding), []byte(goldenLock), true, true)
	f.Add([]byte{}, []byte{}, false, false)
	f.Add([]byte(goldenLock), []byte(goldenBinding), true, true)
	f.Add([]byte(strings.Replace(goldenBinding, `"v":1`, `"v":2`, 1)), []byte(goldenLock), true, true)
	f.Fuzz(func(t *testing.T, b, l []byte, bp, lp bool) {
		beforeB, beforeL := bytes.Clone(b), bytes.Clone(l)
		err := codec.Validate(codec.File{Present: bp, Bytes: b}, codec.File{Present: lp, Bytes: l}, goldenHash)
		wantOK := bp && lp && string(b) == goldenBinding && string(l) == goldenLock
		if (err == nil) != wantOK {
			t.Fatal("acceptance differs from exact pair")
		}
		if !bytes.Equal(b, beforeB) || !bytes.Equal(l, beforeL) {
			t.Fatal("validation changed bytes")
		}
	})
}
