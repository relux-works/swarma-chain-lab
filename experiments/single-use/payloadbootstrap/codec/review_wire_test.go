package codec_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	public "github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
	"reflect"
	"strings"
	"testing"
)

// Canonical v1/v2 bytes roundtrip exactly and every rejected variant clears the result.
func TestReviewWireDifferential(t *testing.T) {
	expectedFields := []string{"V", "BookingID", "StationName", "ModelEndpoint", "ModelCertSHA256", "SHA256"}
	schema := reflect.TypeOf(public.Bootstrap{})
	if schema.NumField() != len(expectedFields) {
		t.Fatal("public field count changed")
	}
	for index, name := range expectedFields {
		if schema.Field(index).Name != name {
			t.Fatal("public field list changed")
		}
	}
	accepted := 0
	refused := 0
	for version := 1; version <= 2; version++ {
		for sample := 0; sample < 32; sample++ {
			channel := make([]byte, 32)
			bearerBytes := make([]byte, 32)
			if _, err := rand.Read(channel); err != nil {
				t.Fatal("entropy unavailable")
			}
			if _, err := rand.Read(bearerBytes); err != nil {
				t.Fatal("entropy unavailable")
			}
			bearer := base64.RawURLEncoding.EncodeToString(bearerBytes)
			raw := []byte(fmt.Sprintf(`{"v":%d,"booking_id":"%s","station_name":"id/review","channel_secret":"%s"`, version, strings.Repeat("a", 64), base64.StdEncoding.EncodeToString(channel)))
			if version == 2 {
				raw = append(raw, []byte(fmt.Sprintf(`,"model_bearer":"%s","model_endpoint":"https://review.example","model_cert_sha256":"%s"`, bearer, strings.Repeat("b", 64)))...)
			}
			raw = append(raw, '}')
			document, err := codec.Decode[[]byte, string](raw)
			if err != nil {
				t.Fatal("valid canonical wire refused")
			}
			encoded, err := codec.Encode(document)
			if err != nil || !bytes.Equal(raw, encoded) {
				t.Fatal("wire roundtrip bytes changed")
			}
			accepted++
			projected, err := public.DecodeBootstrap(raw)
			digest := sha256.Sum256(raw)
			if err != nil || projected.V != version || projected.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("public projection mismatch")
			}
			for _, format := range []string{"%p", "%v", "%+v", "%#v"} {
				text := fmt.Sprintf(format, projected)
				if strings.Contains(text, bearer) || strings.Contains(text, base64.StdEncoding.EncodeToString(channel)) {
					t.Fatal("public projection leaked")
				}
			}
			variants := [][]byte{append(append([]byte(nil), raw...), ' '), append(append([]byte(nil), raw...), raw...), []byte(strings.Replace(string(raw), `"v":`, `"unknown":0,"v":`, 1)), []byte(strings.Replace(string(raw), `"v":`, `"v":0,"v":`, 1)), []byte(strings.Replace(string(raw), `"channel_secret":"`, `"channel_secret":"!`, 1)), []byte(strings.Replace(string(raw), `"booking_id":"`, `"booking_id":"A`, 1)), []byte(`{`), nil, bytes.Repeat([]byte("x"), 4097)}
			for _, invalid := range variants {
				got, err := codec.Decode[[]byte, string](invalid)
				if err == nil || err.Error() != "PAYLOAD_BOOTSTRAP" {
					t.Fatal("invalid wire rejection changed")
				}
				if !reflect.DeepEqual(got, codec.Bootstrap[[]byte, string]{}) {
					t.Fatal("refusal retained credential fields")
				}
				serialized, err := json.Marshal(got)
				if err != nil || bytes.Contains(serialized, []byte(bearer)) || bytes.Contains(serialized, []byte(base64.StdEncoding.EncodeToString(channel))) {
					t.Fatal("refusal serialization retained credentials")
				}
				refused++
			}
		}
	}
	t.Logf("valid-roundtrips=%d refusal-clearing-cases=%d public-fields=%d", accepted, refused, len(expectedFields))
}
