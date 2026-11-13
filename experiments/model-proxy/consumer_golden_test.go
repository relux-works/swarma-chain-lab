package modelproxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The installed loader retains DK5 custody and shares the pure parser's
// canonical table. Empty/oversized files refuse at custody before decoding;
// pairing failures are valid loader inputs, not proxy-startup assertions.
func TestConsumerConfigGolden(t *testing.T) {
	raw, e := os.ReadFile("../single-use/modelprofile/testdata/golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct{ Name, Raw, Error string }
	if json.Unmarshal(raw, &cases) != nil {
		t.Fatal("fixture")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "public.json")
			writeInstalled(t, p, []byte(c.Raw))
			got, e := LoadConfig(p)
			code := ""
			if e != nil {
				code = e.Error()
			}
			want := c.Error
			if want == "PAYLOAD_CONFIG" {
				want = ""
			}
			// Installed custody rejects file size before the public parser.
			if len(c.Raw) == 0 || len(c.Raw) > MaxBody {
				want = "DK5_FILE_SIZE"
			}
			if code != want {
				t.Fatalf("consumer config verdict %q want %q", code, want)
			}
			if e == nil && !bytes.Equal(privateCanonical(got), bytes.TrimSpace([]byte(c.Raw))) {
				t.Fatal("consumer config bytes changed")
			}
			after, e := os.ReadFile(p)
			if e != nil || string(after) != c.Raw {
				t.Fatal("consumer file mutated")
			}
		})
	}
}
