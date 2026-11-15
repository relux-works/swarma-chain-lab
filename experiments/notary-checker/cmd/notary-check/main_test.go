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

// Every MVP vector also crosses the real file/flag boundary. Offline positives
// carry both a LAB banner and marker; refusals return no digest. Omitting the
// explicit fixture flag refuses even for otherwise valid two-owner approvals.
func TestCLIMVPNameFixtures(t *testing.T) {
	raw, e := os.ReadFile("../../testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Vectors []map[string]json.RawMessage `json:"vectors"`
	}
	if e = json.Unmarshal(raw, &corpus); e != nil {
		t.Fatal(e)
	}
	for _, v := range corpus.Vectors {
		var name, want string
		json.Unmarshal(v["name"], &name)
		json.Unmarshal(v["expected"], &want)
		if !strings.Contains(name, "mvp") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var args []string
			for _, field := range []string{"parent", "child", "parent_contract", "child_contract", "request", "policy", "notary_value", "statement"} {
				var value string
				if e := json.Unmarshal(v[field], &value); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(dir, field+".json")
				if e := os.WriteFile(path, []byte(value), 0600); e != nil {
					t.Fatal(e)
				}
				args = append(args, "-"+strings.ReplaceAll(field, "_", "-"), path)
			}
			args = append(args, "-at", "1700000100")
			var out, errs bytes.Buffer
			if name == "positive-mvp-issuer-owner" {
				if code := run(args, &out, &errs); code != 1 || out.String() != "REFUSED MVP_CHAIN_READ_REQUIRED\n" || errs.Len() != 0 {
					t.Fatalf("running: %d %s %s", code, &out, &errs)
				}
				out.Reset()
				errs.Reset()
			}
			offline := v["names"] != nil
			if offline {
				path := filepath.Join(dir, "names.json")
				if e := os.WriteFile(path, v["names"], 0600); e != nil {
					t.Fatal(e)
				}
				args = append(args, "-offline-name-fixture", path)
			}
			code := run(args, &out, &errs)
			if want == "ATTEST" {
				if code != 0 || !strings.HasPrefix(out.String(), "ATTEST ") || !strings.HasSuffix(out.String(), " offline-fixture\n") {
					t.Fatalf("%d %s %s", code, &out, &errs)
				}
			} else if code != 1 || out.String() != "REFUSED "+want+"\n" {
				t.Fatalf("%d %s %s; want %s", code, &out, &errs, want)
			}
			if offline && !strings.Contains(errs.String(), "LAB/OFFLINE") {
				t.Fatal("missing offline banner")
			}
			if !offline && errs.Len() != 0 {
				t.Fatal("unexpected banner without offline flag")
			}
		})
	}
}
