package codec

import "testing"

// Every automatically discovered encoding method returns the same fixed
// redaction for populated and empty wrappers; none is a private-wire encoder.
func TestSecretOutputEncodings(t *testing.T) {
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{NewSecret("synthetic-private-marker"), NewSecret([]byte("synthetic-private-marker")), Secret[string]{}, Secret[[]byte]{}} {
		raw, err := value.MarshalJSON()
		if err != nil || string(raw) != `"[private bootstrap credential]"` {
			t.Fatal("generic JSON redaction changed")
		}
		raw, err = value.MarshalText()
		if err != nil || string(raw) != "[private bootstrap credential]" {
			t.Fatal("generic text redaction changed")
		}
	}
}
