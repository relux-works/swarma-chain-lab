package lifecycle

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
)

// The exact private DTO bytes retain all authority fields. Keep those bytes
// opaque so diagnostics cannot print the credential-bearing snapshot itself.
func authoritySnapshot(records map[string]brokerRecord) codec.Secret[[]byte] {
	return codec.NewSecret(privateCanonical(records))
}
func sameAuthority(left, right codec.Secret[[]byte]) bool {
	return subtle.ConstantTimeCompare(left.Reveal(), right.Reveal()) == 1
}

// Both secret-only mutations and ordinary metadata changes must change the
// snapshot; a value-preserving copy must compare equal and remain output-safe.
func TestAuthoritySnapshotCoverage(t *testing.T) {
	now := int64(100)
	broker, _ := brokerFixture(t, &now)
	key := hash([]byte("snapshot-coverage"))
	if _, err := broker.Allocate(key, hash([]byte("grant")), 90, 200); err != nil {
		t.Fatal("snapshot fixture refused")
	}
	before := authoritySnapshot(broker.state.Records)
	if !sameAuthority(before, authoritySnapshot(broker.state.Records)) {
		t.Fatal("unchanged authority snapshot differs")
	}
	original := broker.state.Records[key]
	for _, field := range []string{"credential", "bootstrap", "metadata"} {
		changed := original
		switch field {
		case "credential":
			raw := changed.Credential.Reveal()
			raw[0] ^= 1
			changed.Credential = NewPrivateBytes(raw)
		case "bootstrap":
			raw := changed.Slot.Bootstrap.Reveal()
			raw[0] ^= 1
			changed.Slot.Bootstrap = NewPrivateBytes(raw)
		case "metadata":
			changed.Desired = "stop"
		}
		broker.state.Records[key] = changed
		if sameAuthority(before, authoritySnapshot(broker.state.Records)) {
			t.Fatal("authority snapshot hides an authority mutation")
		}
	}
	broker.state.Records[key] = original
	raw := original.Credential.Reveal()
	needles := []string{base64.StdEncoding.EncodeToString(raw), strings.Trim(fmt.Sprint([]byte(raw)), "[]")}
	encoded, err := json.Marshal(before)
	if err != nil {
		t.Fatal("snapshot generic encoding refused")
	}
	for _, value := range []any{before, &before, struct{ Snapshot any }{before}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%p", "%d", "%O", "%s", "%q", "%x"} {
			output := fmt.Sprintf(format, value)
			for _, needle := range needles {
				if strings.Contains(output, needle) {
					t.Fatal("authority snapshot disclosed a credential")
				}
			}
		}
	}
	for _, needle := range needles {
		if bytes.Contains(encoded, []byte(needle)) {
			t.Fatal("authority snapshot JSON disclosed a credential")
		}
	}
}
