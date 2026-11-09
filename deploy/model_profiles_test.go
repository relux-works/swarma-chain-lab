package deploy

import "testing"

// The public config validator admits the native Responses profile but refuses
// unknown models/profiles and unpinned endpoints. It opens no credential files.
func TestModelResponsesProfiles(t *testing.T) {
	for _, kind := range []string{"profile", "model", "http", "query", "path", "partial", "mismatch"} {
		t.Run(kind, func(t *testing.T) {
			c := modelFixture()
			c.Upstream = "https://upstream.invalid/v1/responses"
			c.ModelProfiles = map[string]modelProfileSpec{"fixture-model": {"openai-responses-functions-default-v1", c.Upstream}}
			p := newPolicy("model")
			if e := ValidateServiceInputs(p, [][]byte{encoded(t, c)}); e != nil {
				t.Fatal("Responses public config positive refused", e)
			}
			profile := c.ModelProfiles["fixture-model"]
			switch kind {
			case "profile":
				profile.Profile = "unknown"
			case "model":
				delete(c.ModelProfiles, "fixture-model")
				c.ModelProfiles["unknown"] = profile
			case "http":
				profile.Upstream = "http://upstream.invalid/v1/responses"
			case "query":
				profile.Upstream += "?tier=priority"
			case "path":
				profile.Upstream = "https://upstream.invalid/v1/messages"
			case "partial":
				c.Models["legacy-model"] = c.Models["fixture-model"]
			case "mismatch":
				c.Upstream = "https://upstream.invalid/v1/messages"
			}
			if kind != "model" {
				c.ModelProfiles["fixture-model"] = profile
			}
			if e := ValidateServiceInputs(p, [][]byte{encoded(t, c)}); e != ErrPolicy {
				t.Fatal("Responses public config guard missing", e)
			}
		})
	}
}
