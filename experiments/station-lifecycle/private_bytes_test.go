package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Private representation preserves nil versus allocated-empty bytes and copy
// isolation, while generic encoders keep the same fixed redaction for either.
func TestPrivateBytesRepresentations(t *testing.T) {
	for _, raw := range []Secret{nil, {}, {0, 255, 1}} {
		value := NewPrivateBytes(raw)
		want, err := json.Marshal(raw)
		if err != nil {
			t.Fatal("private fixture encoding failed")
		}
		got, err := json.Marshal(value.Reveal())
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("private byte representation changed")
		}
		var decoded PrivateBytes
		if json.Unmarshal(want, &decoded) != nil {
			t.Fatal("private byte decode refused")
		}
		got, err = json.Marshal(decoded.Reveal())
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("decoded byte representation changed")
		}
		public, err := json.Marshal(decoded)
		if err != nil || string(public) != `"[private bootstrap credential]"` {
			t.Fatal("private byte JSON redaction changed")
		}
	}
	original := Secret{1, 2, 3}
	value := NewPrivateBytes(original)
	copied := value
	original[0] = 9
	value.Reveal()[1] = 9
	if !bytes.Equal(copied.Reveal(), []byte{1, 2, 3}) {
		t.Fatal("private bytes share caller storage")
	}
	if json.Unmarshal([]byte(`123`), &value) == nil || !value.IsZero() || value.Reveal() != nil {
		t.Fatal("invalid private byte decode retained data")
	}
	if !bytes.Equal(copied.Reveal(), []byte{1, 2, 3}) {
		t.Fatal("private byte reset mutated a copy")
	}
}

// Only the two former canonical erased forms are admitted, not alternate JSON
// representations of the same empty bytes or malformed values.
func TestPrivateBytesCanonicalBounds(t *testing.T) {
	original := privateCanonical(Slot{})
	for _, tc := range []struct {
		value    string
		accepted bool
	}{{"null", true}, {`""`, true}, {"[]", false}, {"[ ]", false}, {"{}", false}, {"123", false}, {`"`, false}, {`"!"`, false}, {`"" `, false}} {
		raw := bytes.Replace(original, []byte(`"bootstrap":null`), []byte(`"bootstrap":`+tc.value), 1)
		var decoded Slot
		err := strict(raw, &decoded)
		if (err == nil) != tc.accepted {
			t.Fatal("private empty-byte canonical bound changed")
		}
	}
}

// Erased forms must not revive or validate active authority. These public
// recovery calls reject canonical empty/null active records after a valid control.
func TestActiveRecoveryRejectsErasedBytes(t *testing.T) {
	for _, field := range []string{"credential", "bootstrap"} {
		for _, empty := range []Secret{nil, {}} {
			now := int64(100)
			broker, config := brokerFixture(t, &now)
			key := hash([]byte("active-erasure"))
			if _, err := broker.Allocate(key, hash([]byte("grant")), 90, 200); err != nil {
				t.Fatal("active broker fixture refused")
			}
			state := broker.state
			if broker.Close() != nil {
				t.Fatal("active broker close failed")
			}
			control, err := NewBroker(config)
			if err != nil {
				t.Fatal("valid active broker recovery refused")
			}
			control.Close()
			record := state.Records[key]
			if field == "credential" {
				record.Credential = NewPrivateBytes(empty)
			} else {
				record.Slot.Bootstrap = NewPrivateBytes(empty)
			}
			state.Records[key] = record
			if os.WriteFile(filepath.Join(config.StateDir, "broker.json"), privateCanonical(state), 0600) != nil {
				t.Fatal("active broker fixture write failed")
			}
			reopened, err := NewBroker(config)
			if err == nil {
				reopened.Close()
				t.Fatal("active broker accepted erased authority")
			}
			if err.Error() != "BROKER_STATE" {
				t.Fatal("active broker erasure refusal changed")
			}
		}
	}
	for _, empty := range []Secret{nil, {}} {
		manager, config, _, _, slot := managerFixture(t)
		if _, err := manager.Start(context.Background(), slot); err != nil {
			t.Fatal("active manager fixture refused")
		}
		state := manager.state
		manager.Close()
		record := state.Records[slot.ID]
		copied := *record.Slot
		copied.Bootstrap = NewPrivateBytes(empty)
		record.Slot = &copied
		state.Records[slot.ID] = record
		if os.WriteFile(filepath.Join(config.StateDir, "state.json"), privateCanonical(state), 0600) != nil {
			t.Fatal("active manager fixture write failed")
		}
		reopened, err := New(config)
		if err == nil {
			reopened.Close()
			t.Fatal("active manager accepted erased authority")
		}
		if err.Error() != "STATE_RECORD" {
			t.Fatal("active manager erasure refusal changed")
		}
	}
}
