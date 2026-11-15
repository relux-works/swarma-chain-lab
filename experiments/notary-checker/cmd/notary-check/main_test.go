package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The real CLI path reads exact positive fixtures and reports the expected
// digest; invalid invocations exit nonzero and print only named refusals.
func TestCLI(t *testing.T) {
	var args []string
	for _, n := range []string{"parent", "child", "parent-contract", "child-contract", "request", "policy", "notary-value", "statement"} {
		args = append(args, "-"+n, "../../testdata/positive/"+n+".json")
	}
	args = append(args, "-at", "1700000100")
	var out, errs bytes.Buffer
	if code := run(args, &out, &errs); code != 0 || !strings.HasPrefix(out.String(), "ATTEST ") || len(out.String()) != 72 {
		t.Fatalf("%d %s %s", code, out.String(), errs.String())
	}
	for _, c := range []struct {
		args []string
		code string
	}{
		{nil, "INPUT_REQUIRED"},
		{[]string{"-unknown"}, "ARGUMENTS"},
		{append(append([]string{}, args...), "extra"), "ARGUMENTS"},
		{append(append([]string{}, args...), "-at", "0"), "AT_TIME"},
		{[]string{"-parent", "nonexistent"}, "INPUT_READ"},
	} {
		out.Reset()
		errs.Reset()
		if run(c.args, &out, &errs) == 0 || out.String() != "REFUSED "+c.code+"\n" {
			t.Fatalf("%v: %s %s", c.args, out.String(), errs.String())
		}
	}
}

// The CLI accepts both bounded neighbors but prints only the named refusal,
// with no signing digest, when a fitting statement composes to 8193 bytes.
func TestCLIAttestationOutputSize(t *testing.T) {
	raw, e := os.ReadFile("../../testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Vectors []struct {
			Name, Statement, Expected string
			Result                    struct{ Digest string }
		}
	}
	if e = json.Unmarshal(raw, &corpus); e != nil {
		t.Fatal(e)
	}
	seen := 0
	for _, v := range corpus.Vectors {
		if !strings.Contains(v.Name, "attestation-819") {
			continue
		}
		seen++
		t.Run(v.Name, func(t *testing.T) {
			statement := filepath.Join(t.TempDir(), "statement.json")
			if e := os.WriteFile(statement, []byte(v.Statement), 0600); e != nil {
				t.Fatal(e)
			}
			var args []string
			for _, n := range []string{"parent", "child", "parent-contract", "child-contract", "request", "policy", "notary-value"} {
				args = append(args, "-"+n, "../../testdata/positive/"+n+".json")
			}
			args = append(args, "-statement", statement, "-at", "1700000100")
			var out, errs bytes.Buffer
			wantCode, want := 0, "ATTEST "+v.Result.Digest+"\n"
			if v.Expected != "ATTEST" {
				wantCode, want = 1, "REFUSED ATTESTATION_TOO_LARGE\n"
			}
			if code := run(args, &out, &errs); code != wantCode || out.String() != want || errs.Len() != 0 {
				t.Fatalf("got %d %q %q; want %d %q", code, out.String(), errs.String(), wantCode, want)
			}
		})
	}
	if seen != 3 {
		t.Fatal("missing CLI boundary vectors")
	}
}
