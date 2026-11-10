package payload

import (
	"encoding/json"
	"os"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

// The actual public parser + payload pairing preserves every shared literal verdict;
// valid configurations are positive controls for each refusal family.
func TestConsumerModelGolden(t *testing.T) {
	raw, e := os.ReadFile("../single-use/modelprofile/testdata/golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Name, Raw, Error string
		Want             ModelSelection
	}
	if json.Unmarshal(raw, &cases) != nil {
		t.Fatal("fixture")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			input := []byte(c.Raw)
			cfg, e := proxy.ParseConfig(input)
			if e == nil {
				e = CheckModelPair(c.Want, cfg)
			}
			code := ""
			if e != nil {
				code = e.Error()
			}
			if code != c.Error {
				t.Fatalf("consumer model verdict %q want %q", code, c.Error)
			}
			if string(input) != c.Raw {
				t.Fatal("consumer input mutated")
			}
		})
	}
}
