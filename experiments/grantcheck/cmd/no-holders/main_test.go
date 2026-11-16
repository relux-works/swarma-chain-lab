package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Claim: valid legacy values pass as raw JSON and name_show.value strings;
// every holders presence refuses, and malformed/foreign inputs fail closed.
// This is a format gate only: it proves no key custody or current-chain state.
func TestNoHolders(t *testing.T) {
	key := "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	legacy := `{"swarma":{"landlord":{"grant":"` + key + `"}}}`
	for _, tc := range []struct{ name, raw, want string }{{"legacy", legacy, "LEGACY-OK"}, {"empty", strings.Replace(legacy, `"grant":`, `"holders":[],"grant":`, 1), "REFUSE HOLDERS_PRESENT"}, {"populated", strings.Replace(legacy, `"grant":`, `"holders":["02`+key+`"],"grant":`, 1), "REFUSE HOLDERS_PRESENT"}, {"null", strings.Replace(legacy, `"grant":`, `"holders":null,"grant":`, 1), "REFUSE HOLDERS_PRESENT"}, {"malformed", "{", "REFUSE INVALID_VALUE"}, {"empty-object", "{}", "REFUSE INVALID_LEGACY_VALUE"}, {"duplicate", strings.Replace(legacy, `"grant":`, `"grant":"`+key+`","grant":`, 1), "REFUSE INVALID_LEGACY_VALUE"}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, quoted := range []bool{false, true} {
				raw := tc.raw
				if quoted {
					b, _ := json.Marshal(raw)
					raw = string(b)
				}
				var out bytes.Buffer
				code := run(strings.NewReader(raw), &out)
				if out.String() != tc.want+"\n" || (code == 0) != (tc.want == "LEGACY-OK") {
					t.Fatalf("result=%q exit=%d", out.String(), code)
				}
			}
		})
	}
	var out bytes.Buffer
	if run(strings.NewReader(strings.Repeat(" ", 1048577)), &out) != 1 || out.String() != "REFUSE INPUT\n" {
		t.Fatal("oversize admitted")
	}
}
