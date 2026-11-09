package rental

import (
	"encoding/json"
	"testing"
)

// Valid signatures cannot widen either frozen legacy decoder. The same action
// remains valid in a v3 grant; all five original actions remain valid in v1/v2.
func TestLegacyScopeIsolation(t *testing.T) {
	for _, version := range []int{1, 2} {
		name := "v1"
		if version == 2 {
			name = "v2"
		}
		t.Run(name, func(t *testing.T) {
			encode := func(scope []string) []byte {
				if version == 1 {
					c := testCertificate()
					c.Scope = scope
					b, _ := json.Marshal(c)
					raw, _ := json.Marshal(Envelope{c, signature(t, Hash(b), 1)})
					return raw
				}
				c := testDetached()
				c.Scope = scope
				b, _ := json.Marshal(c)
				raw, _ := json.Marshal(DetachedEnvelope{c, signature(t, Hash(b), 1)})
				return raw
			}
			parse := func(raw []byte) error {
				if version == 1 {
					_, e := ParseEnvelope(raw)
					return e
				}
				_, e := ParseDetachedEnvelope(raw)
				return e
			}
			want := "CERTIFICATE_SCOPE"
			if version == 2 {
				want = "DETACHED_SCOPE"
			}
			for _, scope := range [][]string{{"names.register"}, {"deliver", "names.register", "pay"}, {"deliver", "names.register", "pay", "publish", "repository.push", "secret.release"}} {
				if e := parse(encode(scope)); e == nil || e.Error() != want {
					t.Fatalf("legacy scope widened: want %s, got %v", want, e)
				}
				if e := parse(encode([]string{"deliver", "pay", "publish", "repository.push", "secret.release"})); e != nil {
					t.Fatal("legacy five-action neighbor", e)
				}
			}
		})
	}
	g := testGrant(t)
	g.Scope = []string{"deliver", "names.register", "pay", "publish", "repository.push", "secret.release"}
	if _, e := ParseSignedGrant(signGrantTest(t, g, 1)); e != nil {
		t.Fatal("v3 six-action neighbor", e)
	}
}

// A correctly signed untagged payload and neighbouring wrong-prefix signatures
// refuse with GRANT_SIGNATURE; exact fixed-prefix signing passes. ID remains
// the hash of SignedGrant bytes, independent of the signing-digest domain.
func TestGrantSignatureDomain(t *testing.T) {
	g := testGrant(t)
	payload, e := g.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	for _, prefix := range []string{"", "swarma-grant-v2", "swarma-grant-v3\x00"} {
		raw, _ := json.Marshal(SignedGrant{g, signature(t, Hash(append([]byte(prefix), payload...)), 1)})
		if _, e := ParseSignedGrant(raw); e == nil || e.Error() != "GRANT_SIGNATURE" {
			t.Fatalf("wrong signature domain accepted: prefix %q, error %v", prefix, e)
		}
	}
	want := Hash(append([]byte("swarma-grant-v3"), payload...))
	got, e := g.SigningHash()
	if e != nil || got != want || got == Hash(payload) {
		t.Fatal("signature domain bytes", e)
	}
	raw := signGrantTest(t, g, 1)
	signed, e := ParseSignedGrant(raw)
	if e != nil || signed.ID() != Hash(raw) {
		t.Fatal("tagged signature neighbor", e)
	}
}
