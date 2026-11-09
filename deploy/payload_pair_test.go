package deploy

import "testing"

// Deploy admission requires explicit pinned mode; missing
// inputs, either direction of dialect mismatch, unknown models and wrong public
// endpoint/pin cannot be hidden behind a valid release descriptor. Existing
// main-network descriptor rejection remains unchanged in TestNewServicePolicies.
func TestPayloadPairing(t *testing.T) {
	for _, dialect := range []string{"messages", "responses"} {
		for _, kind := range []string{"legacy", "dialect", "model", "endpoint", "pin", "limit", "missing-config", "extra", "unknown"} {
			t.Run(dialect+"/"+kind, func(t *testing.T) {
				c := modelFixture()
				if dialect == "responses" {
					c.Upstream = "https://upstream.invalid/v1/responses"
					c.ModelProfiles = map[string]modelProfileSpec{"fixture-model": {"openai-responses-functions-default-v1", c.Upstream}}
				}
				q := payloadPair{dialect, "fixture-model", 10, c.Endpoint.URL, c.Endpoint.CertSHA256}
				p := newPolicy("payload")
				if e := ValidateServiceInputs(p, [][]byte{encoded(t, q), encoded(t, c)}); e != nil {
					t.Fatal("payload pairing neighbor refused", e)
				}
				inputs := [][]byte{encoded(t, q), encoded(t, c)}
				switch kind {
				case "legacy":
					q.Dialect = ""
				case "dialect":
					if dialect == "messages" {
						q.Dialect = "responses"
					} else {
						q.Dialect = "messages"
					}
				case "model":
					q.Model = "absent"
				case "endpoint":
					q.Endpoint = "https://other.invalid"
				case "pin":
					q.CertSHA256 = ""
				case "limit":
					q.MaxTokens = 0
				case "missing-config":
					inputs = nil
				case "extra":
					inputs = append(inputs, []byte(`{}`))
				case "unknown":
					q.Dialect = "unknown"
				}
				if len(inputs) > 0 {
					inputs[0] = encoded(t, q)
				}
				if e := ValidateServiceInputs(p, inputs); e != ErrPolicy {
					t.Fatal("unpinned payload deployment accepted", e)
				}
			})
		}
	}
}
