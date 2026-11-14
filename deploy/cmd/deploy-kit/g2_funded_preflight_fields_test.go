package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

// Claim: all five neighboring malformed strings from the repeated review
// finding refuse with their own member, no success output, and ErrPolicy.
func TestG2FundedPreflightParserSemanticFields(t *testing.T) {
	cases := []struct{ name, path, value string }{
		{"zero-grantee", "grantee", strings.Repeat("0", 64)},
		{"empty-receipt", "receipt_pubkey", ""},
		{"change-me-canary", "g2.canary.outpoint.txid", "CHANGE_ME"},
		{"token-canary", "g2.canary.outpoint.txid", "@TXID@"},
		{"short-canary", "g2.canary.outpoint.txid", strings.Repeat("1", 63)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := fundedParams()
			setG2String(t, &p, tc.path, tc.value)
			out, err := runFundedPreflight(t, p)
			if out != "" || !errors.Is(err, deploy.ErrPolicy) || err.Error() != deploy.ErrPolicy.Error()+": "+tc.path {
				t.Fatalf("want clean named refusal for %s, got %q %v", tc.path, out, err)
			}
			if out, err := runFundedPreflight(t, fundedParams()); err != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
				t.Fatal("valid neighbor", out, err)
			}
		})
	}
}

func setG2String(t *testing.T, p *deploy.G2PayParameters, path, value string) {
	t.Helper()
	v := reflect.ValueOf(p).Elem()
	for _, part := range strings.Split(path, ".") {
		typ := v.Type()
		found := false
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).Tag.Get("json") == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			t.Fatal("unknown fixture field", path)
		}
	}
	v.SetString(value)
}

// Claim: every declared string member has malformed contents (not merely
// wrong JSON types) rejected under its own path, with an accepted neighbor.
// Reflection pins coverage to the schema: adding a string requires fixtures.
func TestG2FundedPreflightStringMemberSweep(t *testing.T) {
	cases := map[string]struct {
		valid string
		bad   []string
	}{
		"network":                 {"main", []string{"", "CHANGE_ME", "@NETWORK@", "MAIN", "test"}},
		"genesis":                 {fundedParams().Genesis, []string{"", "CHANGE_ME", "@GENESIS@", strings.Repeat("0", 64), strings.Repeat("1", 63)}},
		"agent_user":              {"agent_2", []string{"", "1agent", "root", "nobody", "swarma-wallet-other", "a.b", strings.Repeat("a", 32), "a\nPRIVATE_MARKER"}},
		"agent_key_file":          {"/srv/agent/next.key", []string{"", "relative", "/", "/srv/../key", "/srv/key ", "/srv/\nPRIVATE_MARKER", "/" + strings.Repeat("a", 4095)}},
		"node_datadir":            {"/srv/node", []string{"", "relative", "/", "/srv/node/", "/run/node", "/etc/swarma/node", "/var/lib/swarma-wallet", "/" + strings.Repeat("a", 1024)}},
		"grantee":                 {hashKey("sweep-grantee"), []string{"", "CHANGE_ME", "@KEY@", strings.Repeat("0", 64), strings.Repeat("1", 63), strings.Repeat("f", 64), strings.Repeat("0", 63) + "5", strings.ToUpper(hashKey("grantee"))}},
		"receipt_pubkey":          {hashKey("sweep-receipt"), []string{"", "CHANGE_ME", "@KEY@", strings.Repeat("0", 64), strings.Repeat("1", 63), strings.Repeat("f", 64), strings.Repeat("0", 63) + "5", strings.ToUpper(hashKey("receipt"))}},
		"hot_wallet_name":         {"wallet-2", []string{"", ".hidden", "-option", "UPPER", "../wallet", "a/b", strings.Repeat("a", 65)}},
		"g2.canary.outpoint.txid": {strings.Repeat("abcd", 16), []string{"", "CHANGE_ME", "@TXID@", strings.Repeat("0", 64), strings.Repeat("1", 63), strings.Repeat("a", 65), strings.Repeat("g", 64), strings.Repeat("AB", 32)}},
	}
	var walk func(reflect.Type, string)
	seen := 0
	walk = func(typ reflect.Type, prefix string) {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			path := prefix + field.Tag.Get("json")
			if field.Type.Kind() == reflect.Struct {
				walk(field.Type, path+".")
				continue
			}
			if field.Type.Kind() != reflect.String {
				continue
			}
			seen++
			tc, ok := cases[path]
			if !ok || len(tc.bad) == 0 {
				t.Fatalf("string member lacks malformed-content fixtures: %s", path)
			}
			t.Run(path, func(t *testing.T) {
				p := fundedParams()
				setG2String(t, &p, path, tc.valid)
				if out, err := runFundedPreflight(t, p); err != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
					t.Fatal("valid member neighbor", out, err)
				}
				for i, value := range tc.bad {
					p := fundedParams()
					setG2String(t, &p, path, value)
					out, err := runFundedPreflight(t, p)
					cause := deploy.ErrPolicy
					if path == "network" || path == "genesis" {
						cause = deploy.ErrNetwork
					}
					if out != "" || !errors.Is(err, cause) || err.Error() != cause.Error()+": "+path {
						t.Fatalf("variant %d: want %s, got %q %v", i, path, out, err)
					}
					raw, err := json.Marshal(p)
					if err != nil {
						t.Fatal(err)
					}
					parsed, err := deploy.ParseG2PayParameters(raw)
					var fieldError *deploy.FieldError
					if !errors.As(err, &fieldError) || fieldError.Path != path || !errors.Is(err, cause) || parsed != (deploy.G2PayParameters{}) {
						t.Fatalf("canonical parser lost path/sentinel or returned partial parameters: %v", err)
					}
				}
			})
		}
	}
	walk(reflect.TypeFor[deploy.G2PayParameters](), "")
	if seen != len(cases) {
		t.Fatal("fixture/schema drift", seen, len(cases))
	}
}
