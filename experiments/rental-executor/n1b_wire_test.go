package executor

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The dedicated private mint writer keeps the old JSON bytes. Decoding claims
// keeps credentials opaque without widening the previous strict input schema.
func TestN1bTrackBWireDifferential(t *testing.T) {
	for i := 0; i < 64; i++ {
		raw := Hash([]byte{byte(i)})
		token := NewTrackBToken(raw)
		w := httptest.NewRecorder()
		writeTrackBMintReply(w, token)
		var expected bytes.Buffer
		if json.NewEncoder(&expected).Encode(map[string]string{"status": "ok", "token": raw}) != nil || w.Body.String() != expected.String() {
			t.Fatal("private mint wire bytes changed")
		}
		body := canonical(map[string]string{"slot": strings.Repeat("1", 64), "token": raw})
		var claim trackBClaimRequest
		if decodeTrackBClaim(body, &claim) != nil || claim.Token.Reveal() != raw || claim.Slot != strings.Repeat("1", 64) {
			t.Fatal("private claim wire bytes changed")
		}
		generic, e := json.Marshal(claim)
		if e != nil || bytes.Contains(generic, []byte(raw)) {
			t.Fatal("claim credential entered generic JSON")
		}
	}
	for _, value := range []string{"null", "123", "[]", "{}"} {
		var claim trackBClaimRequest
		body := []byte(`{"slot":"` + strings.Repeat("1", 64) + `","token":` + value + `}`)
		if decodeTrackBClaim(body, &claim) == nil {
			t.Fatal("malformed private claim admitted")
		}
	}
	token := NewTrackBToken("copy-isolated-private-token")
	copy := token
	if json.Unmarshal([]byte(`123`), &token) == nil || !token.IsZero() || copy.Reveal() != "copy-isolated-private-token" {
		t.Fatal("failed token decode retained or mutated credentials")
	}
}
