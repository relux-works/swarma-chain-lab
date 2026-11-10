package payloadbootstrap

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// Shared literal vectors pin existing wire acceptance, refusal codes, public
// projection and exact-byte digest. Rejected inputs return no partial data.
func TestGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Name, Raw, Error string
		Public           Bootstrap
	}
	if json.Unmarshal(raw, &cases) != nil {
		t.Fatal("fixture")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			b := []byte(c.Raw)
			before := bytes.Clone(b)
			got, e := DecodeBootstrap(b)
			code := ""
			if e != nil {
				code = e.Error()
			}
			if code != c.Error {
				t.Fatalf("bootstrap verdict %q want %q", code, c.Error)
			}
			if got != c.Public {
				t.Fatal("bootstrap public projection changed")
			}
			if !bytes.Equal(b, before) {
				t.Fatal("bootstrap input mutated")
			}
			public, _ := json.Marshal(got)
			for _, secret := range [][]byte{[]byte("channel_secret"), []byte("model_bearer")} {
				if bytes.Contains(public, secret) {
					t.Fatal("secret field in public projection")
				}
			}
		})
	}
}

// Only the six approved public fields may be returned, including when a future
// accidental credential field would happen to be empty in a particular fixture.
func TestPublicFields(t *testing.T) {
	typ := reflect.TypeOf(Bootstrap{})
	want := map[string]bool{"V": true, "BookingID": true, "StationName": true, "ModelEndpoint": true, "ModelCertSHA256": true, "SHA256": true}
	if typ.NumField() != len(want) {
		t.Fatal("public bootstrap field set changed")
	}
	for i := 0; i < typ.NumField(); i++ {
		if !want[typ.Field(i).Name] {
			t.Fatal("public bootstrap field set changed")
		}
	}
}
