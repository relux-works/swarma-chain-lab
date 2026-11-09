package deploy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func modelTermsFixture(t *testing.T) (map[string]any, []byte, map[string]any, modelConfig, payloadPair) {
	t.Helper()
	caps := modelCaps{1000, 100, 10, 10, 10000, 5}
	profile := []byte("public signed model terms fixture\n")
	tmpl := bookingTemplate{Version: 2, ID: "model", ProfileID: "fixture", ProfileVersion: "v2", ProfileSHA256: digest(profile), Allowed: []string{"deliver"}, Forbidden: []string{"pay", "publish", "repository.push", "secret.release"}, BudgetSat: 1000, ModelCaps: &caps}
	templateHash := digest(encoded(t, tmpl))
	b := map[string]any{"service_version": 2, "config": map[string]any{"template": tmpl, "template_sha256": templateHash, "model_caps": caps}}
	g := modelPublic()
	m := modelFixture()
	m.Endpoint.CertSHA256 = g["model_proxy"].(map[string]any)["cert_sha256"].(string)
	g["model_proxy"].(map[string]any)["origin"] = m.Endpoint.URL
	g["model_proxy"].(map[string]any)["cert_sha256"] = m.Endpoint.CertSHA256
	g["exchange"] = map[string]any{"booking_version": 2, "payment_coins": []string{"nmc"}, "template_sha256": templateHash, "profile_sha256": tmpl.ProfileSHA256}
	return b, profile, g, m, payloadPair{"messages", "fixture-model", 10, m.Endpoint.URL, m.Endpoint.CertSHA256}
}

// Cross-document equality is checked for all six caps in both directions, next
// to valid terms. Profile/template pins, missing defaults and payload/endpoint
// mismatches fail as policy; this does not claim complete native startup checks.
func TestModelTerms(t *testing.T) {
	for i := 0; i < reflect.TypeOf(modelCaps{}).NumField(); i++ {
		for _, delta := range []int64{-1, 1} {
			t.Run(fmt.Sprintf("%s/%d", reflect.TypeOf(modelCaps{}).Field(i).Name, delta), func(t *testing.T) {
				b, p, g, m, q := modelTermsFixture(t)
				check := func() error { return CompareModelTerms(encoded(t, b), p, encoded(t, g), encoded(t, m), encoded(t, q)) }
				if e := check(); e != nil {
					t.Fatal("valid neighbor", e)
				}
				caps := g["model_proxy"].(map[string]any)["caps"].(map[string]any)
				name := reflect.TypeOf(modelCaps{}).Field(i).Tag.Get("json")
				n := caps[name].(int)
				caps[name] = int64(n) + delta
				if e := check(); e != ErrPolicy {
					t.Fatal("mismatched gateway cap accepted", e)
				}
			})
		}
	}
	for _, kind := range []string{"profile", "template-pin", "template-cap", "booking-cap", "missing-default", "payload-cap", "endpoint", "null-template-caps"} {
		t.Run(kind, func(t *testing.T) {
			b, p, g, m, q := modelTermsFixture(t)
			bc := b["config"].(map[string]any)
			check := func() error { return CompareModelTerms(encoded(t, b), p, encoded(t, g), encoded(t, m), encoded(t, q)) }
			if e := check(); e != nil {
				t.Fatal("valid neighbor", e)
			}
			switch kind {
			case "profile":
				p = append(p, 'x')
			case "template-pin":
				bc["template_sha256"] = digest([]byte("wrong"))
			case "template-cap":
				v := bc["template"].(bookingTemplate)
				c := *v.ModelCaps
				c.Requests++
				v.ModelCaps = &c
				bc["template"] = v
			case "booking-cap":
				c := bc["model_caps"].(modelCaps)
				c.InputTokens--
				bc["model_caps"] = c
			case "missing-default":
				c := bc["model_caps"].(modelCaps)
				c.DefaultMaxOutputTokens = 0
				bc["model_caps"] = c
			case "payload-cap":
				q.MaxTokens = 11
			case "endpoint":
				g["model_proxy"].(map[string]any)["origin"] = "https://other.invalid"
			case "null-template-caps":
				v := bc["template"].(bookingTemplate)
				v.ModelCaps = nil
				bc["template"] = v
			}
			if e := check(); e != ErrPolicy {
				t.Fatal("mismatch accepted", e)
			}
		})
	}
}

// Explicit model templates validate structurally on main; both config/template
// caps are required and exact. A legacy non-model template still omits both.
func TestMainBookingModelCaps(t *testing.T) {
	var b mainBooking
	if e := json.Unmarshal(resolvedMain(t, "booking"), &b); e != nil {
		t.Fatal(e)
	}
	if b.Config.Template.Version != 2 || validateMainBooking(encoded(t, b)) != nil {
		t.Fatal("model template neighbor")
	}
	b.Config.ModelCaps.Requests++
	if e := validateMainBooking(encoded(t, b)); e != ErrPolicy {
		t.Fatal("booking mismatch", e)
	}
	b.Config.Template.Version = 1
	b.Config.Template.ModelCaps = nil
	b.Config.ModelCaps = nil
	if e := validateMainBooking(encoded(t, b)); e != nil {
		t.Fatal("legacy neighbor", e)
	}
}

// Real CLI checks the supplied public file set. A known mismatched cap must
// fail at the policy check beside MODEL_TERMS_MATCH, with no input writes.
func TestModelTermsCLI(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "deploy-kit")
	build := exec.Command("go", "build", "-o", binary, "./cmd/deploy-kit")
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("CLI build: %v %s", e, out)
	}
	b, p, g, m, q := modelTermsFixture(t)
	inputs := [][]byte{encoded(t, b), p, encoded(t, g), encoded(t, m), encoded(t, q)}
	names := []string{"booking", "profile", "gateway", "model", "payload"}
	args := []string{"check-model-terms"}
	for i, name := range names {
		path := filepath.Join(root, name)
		if e := os.WriteFile(path, inputs[i], 0600); e != nil {
			t.Fatal(e)
		}
		args = append(args, "-"+name, path)
	}
	if out, e := exec.Command(binary, args...).CombinedOutput(); e != nil || string(out) != "MODEL_TERMS_MATCH\n" {
		t.Fatalf("valid CLI: %v %s", e, out)
	}
	g["model_proxy"].(map[string]any)["caps"].(map[string]any)["requests"] = 11
	inputs[2] = encoded(t, g)
	if e := os.WriteFile(filepath.Join(root, "gateway"), inputs[2], 0600); e != nil {
		t.Fatal(e)
	}
	out, e := exec.Command(binary, args...).CombinedOutput()
	code, ok := e.(*exec.ExitError)
	if !ok || code.ExitCode() != 1 || strings.TrimSpace(string(out)) != ErrPolicy.Error() {
		t.Fatalf("wrong CLI refusal: %v %s", e, out)
	}
	for i, name := range names {
		raw, e := os.ReadFile(filepath.Join(root, name))
		if e != nil || string(raw) != string(inputs[i]) {
			t.Fatal("CLI changed input", name, e)
		}
	}
}
