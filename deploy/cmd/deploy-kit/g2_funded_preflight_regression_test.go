package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

func runFundedRaw(t *testing.T, raw []byte) (string, error) {
	t.Helper()
	_, path := writeG2Params(t, fundedParams())
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := g2FundedPreflight([]string{"-params", path}, &out)
	if err != nil && out.Len() != 0 {
		t.Fatalf("success output on refusal: %q", out.String())
	}
	return out.String(), err
}

// Claim: the independently pinned public key shared by BIP-340 rows 15-18
// refuses in either field; a complete nontrivial neighbour still succeeds.
func TestG2FundedPreflightPublishedBIP340Rows15To18(t *testing.T) {
	if out, err := runFundedPreflight(t, fundedParams()); err != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
		t.Fatal("valid neighbour", out, err)
	}
	// Public key column, bitcoin/bips 200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb.
	const published = "778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117"
	for _, field := range []string{"grantee", "receipt_pubkey"} {
		t.Run(field, func(t *testing.T) {
			p := fundedParams()
			if field == "grantee" {
				p.Grantee = published
			} else {
				p.ReceiptPubkey = published
			}
			_, err := runFundedPreflight(t, p)
			wantFundedRefusal(t, field, err, "BIP340_VECTOR_KEY "+field+" vector=15-18")
		})
	}
}

// requiredG2Members enumerates the frozen JSON type independently of the
// command's diagnostic walker, including intermediate object members.
func requiredG2Members(typ reflect.Type, prefix string) []string {
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := prefix + f.Tag.Get("json")
		out = append(out, name)
		if f.Type.Kind() == reflect.Struct {
			out = append(out, requiredG2Members(f.Type, name+".")...)
		}
	}
	return out
}

// omitG2Member preserves the canonical member order and bytes for every
// remaining field. A map re-encoding would test ordering rather than omission.
func omitG2Member(t *testing.T, raw []byte, path []string) []byte {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	value, ok := members[path[0]]
	if !ok {
		t.Fatal("missing omission fixture", path)
	}
	if len(path) > 1 {
		changed := omitG2Member(t, value, path[1:])
		return bytes.Replace(raw, value, changed, 1)
	}
	fragment := append([]byte(`"`+path[0]+`":`), value...)
	if bytes.Contains(raw, append(append([]byte{}, fragment...), ',')) {
		fragment = append(fragment, ',')
	} else {
		fragment = append([]byte{','}, fragment...)
	}
	changed := bytes.Replace(raw, fragment, nil, 1)
	if bytes.Equal(changed, raw) {
		t.Fatal("omission fixture did not apply", path)
	}
	return changed
}

// Claim: every required member, including false booleans and zero vout /
// low_float_sat, is required by the command and named on refusal. The complete
// zero/false-valued neighbour passes. No silent-default acceptance is allowed.
func TestG2FundedPreflightRequiredMembers(t *testing.T) {
	p := fundedParams()
	p.G2.Canary.Outpoint.Vout = 0
	p.G2.LowFloatSat = 0
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runFundedRaw(t, raw); err != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
		t.Fatal("complete false/zero neighbour", out, err)
	}
	for _, field := range requiredG2Members(reflect.TypeFor[deploy.G2PayParameters](), "") {
		t.Run(field, func(t *testing.T) {
			_, err := runFundedRaw(t, omitG2Member(t, raw, strings.Split(field, ".")))
			if !errors.Is(err, deploy.ErrPolicy) || !strings.Contains(err.Error(), ": "+field) {
				t.Fatalf("omission must refuse and name %s: %v", field, err)
			}
		})
	}
}

// Claim: parse-layer missing, null, mistyped and placeholder values name safe
// schema fields; zero canary and equal keys do too. Sentinels are preserved and
// neither supplied key values nor attacker-supplied member names are printed.
func TestG2FundedPreflightParserFieldDiagnostics(t *testing.T) {
	p := fundedParams()
	good, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, field string
		raw         []byte
		cause       error
	}{
		{"missing-grantee", "grantee", omitG2Member(t, good, []string{"grantee"}), deploy.ErrPolicy},
		{"null-grantee", "grantee", bytes.Replace(good, []byte(`"`+p.Grantee+`"`), []byte("null"), 1), deploy.ErrPolicy},
		{"mistyped-grantee", "grantee", bytes.Replace(good, []byte(`"`+p.Grantee+`"`), []byte("123"), 1), deploy.ErrPolicy},
		{"zero-canary", "g2.canary.outpoint.txid", bytes.Replace(good, []byte(p.G2.Canary.Outpoint.TxID), []byte(strings.Repeat("0", 64)), 1), deploy.ErrPolicy},
		{"placeholder-canary", "g2.canary.outpoint.txid", bytes.Replace(good, []byte(p.G2.Canary.Outpoint.TxID), []byte("PLACEHOLDER_CANARY"), 1), deploy.ErrPlaceholder},
		{"placeholder-key", "receipt_pubkey", bytes.Replace(good, []byte(p.ReceiptPubkey), []byte("PLACEHOLDER_RECEIPT"), 1), deploy.ErrPlaceholder},
		{"equal-keys", "grantee, receipt_pubkey", bytes.Replace(good, []byte(p.ReceiptPubkey), []byte(p.Grantee), 1), deploy.ErrPolicy},
		{"unknown-member", "parameters", append([]byte(`{"PRIVATE_MARKER":1,`), good[1:]...), deploy.ErrPolicy},
		{"malformed", "parameters", good[:len(good)-1], deploy.ErrPolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runFundedRaw(t, tc.raw)
			if !errors.Is(err, tc.cause) || err.Error() != tc.cause.Error()+": "+tc.field {
				t.Fatalf("got %v, want preserved sentinel and field %s", err, tc.field)
			}
			for _, forbidden := range []string{p.Grantee, p.ReceiptPubkey, "PRIVATE_MARKER", "PLACEHOLDER_RECEIPT", "PLACEHOLDER_CANARY"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatal("diagnostic echoed supplied data")
				}
			}
		})
	}
	if out, err := runFundedRaw(t, good); err != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
		t.Fatal("valid neighbour", out, err)
	}
}

// Claim: each documented small scalar is covered in both fields, including
// interior points (not only the endpoints); 1025/1026 remain outside the bound.
func TestG2FundedPreflightAllSmallScalars(t *testing.T) {
	for k := uint32(1); k <= 1024; k++ {
		for _, field := range []string{"grantee", "receipt_pubkey"} {
			p := fundedParams()
			if field == "grantee" {
				p.Grantee = scalarKey(k)
			} else {
				p.ReceiptPubkey = scalarKey(k)
			}
			_, err := runFundedPreflight(t, p)
			if err == nil || !strings.Contains(err.Error(), "SMALL_SCALAR_KEY "+field+" ") {
				t.Fatalf("scalar %d in %s not refused: %v", k, field, err)
			}
		}
	}
	p := fundedParams()
	p.Grantee, p.ReceiptPubkey = scalarKey(1025), scalarKey(1026)
	if _, err := runFundedPreflight(t, p); err != nil {
		t.Fatal("outside-bound neighbour", err)
	}
}
