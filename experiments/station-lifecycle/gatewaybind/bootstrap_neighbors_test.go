package gatewaybind

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap"
)

// Opaque storage preserves usable HMAC/bearer credentials and exact wire bytes;
// its public neighbor retains pins, while every refusal returns empty wrappers.
func TestBootstrapCredentialNeighbors(t *testing.T) {
	const bearer = "eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXk"
	raw := []byte(`{"v":2,"booking_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","station_name":"id/fixture","channel_secret":"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=","model_bearer":"` + bearer + `","model_endpoint":"https://proxy.example","model_cert_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	document, err := DecodeBootstrap(raw)
	if err != nil {
		t.Fatal("valid neighbor refused")
	}
	encoded, err := EncodeBootstrap(document)
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("private wire bytes changed")
	}
	nonce := strings.Repeat("c", 64)
	response, err := stationlink.ComputeResponse(document.ChannelSecret.Reveal(), nonce, document.BookingID, document.StationName)
	if err != nil || !stationlink.VerifyResponse(bytes.Repeat([]byte("x"), 32), nonce, document.BookingID, document.StationName, response) {
		t.Fatal("decoded channel cannot authenticate")
	}
	request, err := http.NewRequest(http.MethodPost, document.ModelEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+string(document.ModelBearer.Reveal()))
	if request.Header.Get("Authorization") != "Bearer "+bearer {
		t.Fatal("decoded bearer cannot authorize")
	}
	public, err := payloadbootstrap.DecodeBootstrap(raw)
	if err != nil {
		t.Fatal("public neighbor refused")
	}
	output := fmt.Sprintf("%+v", public)
	if !strings.Contains(output, document.ModelEndpoint) || !strings.Contains(output, document.ModelCertSHA256) || strings.Contains(output, bearer[:8]) || strings.Contains(output, "xxxxxxxx") {
		t.Fatal("public projection lost pins or acquired credentials")
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":3`), 1), bytes.Replace(raw, []byte(bearer), []byte("short"), 1), bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":2,"unexpected":true`), 1)} {
		got, err := DecodeBootstrap(bad)
		if err == nil || err.Error() != "PAYLOAD_BOOTSTRAP" || got.BookingID != "" || !got.ChannelSecret.IsZero() || !got.ModelBearer.IsZero() || len(got.ChannelSecret.Reveal()) != 0 || got.ModelBearer.Reveal() != "" {
			t.Fatal("refusal retained data or credentials")
		}
	}
}

// The downstream station handle retains an opaque channel credential rather
// than copying it into a raw slice field that bad-verb diagnostics can inspect.
func TestStationHandleCredentialFormatting(t *testing.T) {
	const channel = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	handle := station.Station{ChannelSecret: station.NewChannelSecret([]byte(channel))}
	for _, value := range []any{handle, &handle, struct{ Handle station.Station }{handle}} {
		for _, format := range []string{"%p", "%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T"} {
			out := fmt.Sprintf(format, value)
			if strings.Contains(out, "xxxxxxxx") || strings.Contains(out, "120 120 ") || strings.Contains(out, "78787878") {
				t.Fatalf("station handle disclosed channel with %s", format)
			}
		}
	}
	// JSON encoding remains a private operation; the value returned by Reveal
	// can be changed without mutating the credential retained in the handle.
	before, err := json.Marshal(handle)
	if err != nil {
		t.Fatal(err)
	}
	handle.ChannelSecret.Reveal()[0] = 'y'
	after, err := json.Marshal(handle)
	if err != nil || !bytes.Equal(before, after) || string(handle.ChannelSecret.Reveal()) != channel {
		t.Fatal("station handle retained mutable accessor result")
	}
}
