package main

import (
	"bytes"
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
