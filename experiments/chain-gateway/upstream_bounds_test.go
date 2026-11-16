package chaingateway_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

type countingReader struct{ remaining, read int }

func (r *countingReader) Read(p []byte) (int, error) {
	n := min(len(p), r.remaining)
	for i := 0; i < n; i++ {
		p[i] = ' '
		if r.read+i == 0 {
			p[i] = '{'
		}
		if r.read+i == 1 {
			p[i] = '}'
		}
	}
	r.remaining -= n
	r.read += n
	return n, nil
}

// Claim: every upstream method stops at cap+1 and rejects excessive depth before projection, beside exact-bound controls.
func TestUpstreamBounds(t *testing.T) {
	for method, b := range upstreamBounds {
		t.Run(method, func(t *testing.T) {
			// Claim: a cap-byte body is read completely, but an overflowing stream consumes only cap+1 bytes.
			if raw, e := upstreamRead(strings.NewReader("{}"+strings.Repeat(" ", b.bytes-2)), b.bytes); e != nil || len(raw) != b.bytes {
				t.Fatalf("exact cap: %v", e)
			}
			r := &countingReader{remaining: b.bytes * 4}
			if _, e := upstreamRead(r, b.bytes); e == nil || r.read != b.bytes+1 {
				t.Fatalf("cap+1 stop: read=%d error=%v", r.read, e)
			}
			// Claim: method-specific container depth admits the exact boundary and rejects one more container.
			nested := func(depth int) []byte {
				return []byte(`{"x":` + strings.Repeat(`[`, depth-1) + `0` + strings.Repeat(`]`, depth-1) + `}`)
			}
			if _, e := upstreamParse(nested(b.depth), b.depth); e != nil {
				t.Fatal(e)
			}
			if _, e := upstreamParse(nested(b.depth+1), b.depth); e == nil || e.Error() != "upstream depth" {
				t.Fatalf("depth guard: %v", e)
			}
		})
	}
}

// Claim: complete credential/base64/header and secret-component values refuse, while fragments and embedded values do not.
func TestReflectionRepresentations(t *testing.T) {
	for _, mode := range []string{"verifier", "cookie"} {
		t.Run(mode, func(t *testing.T) {
			// Public test-only markers are not credentials and are never printed by assertions.
			r := reflectionInput{Mode: mode, User: "public-user", Secret: "public-test-marker", Value: "ordinary value"}
			if reflectionOracle(r) != "ok" {
				t.Fatal("ordinary positive control")
			}
			raw := r.User + ":" + r.Secret
			b64 := base64.StdEncoding.EncodeToString([]byte(raw))
			for i, value := range []string{raw, b64, "Basic " + b64, r.Secret} {
				r.Value = value
				if reflectionOracle(r) != "unavailable" {
					t.Fatal(fmt.Sprintf("whole-value refusal %d", i))
				}
			}
			for _, value := range []string{"public-test", "prefix-" + r.Secret + "-suffix"} {
				r.Value = value
				if reflectionOracle(r) != "ok" {
					t.Fatal("no substring heuristic")
				}
			}
		})
	}
}
