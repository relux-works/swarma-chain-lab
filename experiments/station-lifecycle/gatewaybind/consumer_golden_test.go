package gatewaybind

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// The legacy credential consumer must preserve every shared literal verdict and
// re-encode valid bytes exactly; it must not mutate input or return partial state.
func TestConsumerBootstrapGolden(t *testing.T) {
	raw, e := os.ReadFile("../../single-use/payloadbootstrap/testdata/golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct{ Name, Raw, Error string }
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
				t.Fatalf("consumer bootstrap verdict %q want %q", code, c.Error)
			}
			if e == nil {
				again, e := EncodeBootstrap(got)
				if e != nil || !bytes.Equal(again, b) {
					t.Fatal("consumer canonical bytes changed")
				}
			} else if got.BookingID != "" || len(got.ChannelSecret.Reveal()) != 0 || got.ModelBearer.Reveal() != "" {
				t.Fatal("partial credential on refusal")
			}
			if !bytes.Equal(b, before) {
				t.Fatal("consumer input mutated")
			}
		})
	}
}
