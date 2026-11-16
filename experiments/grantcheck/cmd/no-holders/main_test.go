package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// ceremonyCases reads the exported landlord VALUE bytes, never a name_show
// envelope. Every rejection is paired with the same exported legacy control.
func ceremonyCases(t *testing.T) []struct {
	name, raw, want string
	exit            int
} {
	t.Helper()
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "identity-interop", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	legacy := read("landlord-legacy.json")
	return []struct {
		name, raw, want string
		exit            int
	}{
		{"legacy", legacy, "LEGACY-OK\n", 0},
		{"holders-empty", read("landlord-holders-empty.json"), "REFUSE HOLDERS_PRESENT\n", 1},
		{"holders-populated", read("landlord-holders-populated.json"), "REFUSE HOLDERS_PRESENT\n", 1},
		{"foreign-landlord", strings.Replace(legacy, `"grant":`, `"foreign":true,"grant":`, 1), "REFUSE INVALID_LEGACY_VALUE\n", 1},
		{"foreign-swarma", strings.Replace(legacy, `"landlord":`, `"foreign":true,"landlord":`, 1), "REFUSE INVALID_LEGACY_VALUE\n", 1},
		{"case-variant", strings.Replace(legacy, `"landlord":`, `"Landlord":`, 1), "REFUSE INVALID_LEGACY_VALUE\n", 1},
	}
}

// Claim: the command entry consumes the three exported VALUES, raw and as
// name_show.value strings, with exact exits/messages; foreign members refuse.
func TestNoHoldersCorpus(t *testing.T) {
	for _, tc := range ceremonyCases(t) {
		for _, quoted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/quoted=%v", tc.name, quoted), func(t *testing.T) {
				raw := tc.raw
				if quoted {
					b, err := json.Marshal(raw)
					if err != nil {
						t.Fatal(err)
					}
					raw = string(b)
				}
				var out bytes.Buffer
				code := run(strings.NewReader(raw), &out)
				if code != tc.exit || out.String() != tc.want {
					t.Fatalf("exit=%d output=%q", code, out.String())
				}
				t.Logf("exported VALUE exit=%d output=%q", code, out.String())
			})
		}
	}
}

// Claim: a freshly built binary executes main(), stdin/stdout and os.Exit on
// the exported VALUES and foreign-field controls, including JSON string forms.
// No node or real operator value is involved; build is a setup-time operation.
func TestNoHoldersCommand(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "no-holders")
	build := exec.Command("go", "build", "-mod=readonly", "-p", "1", "-buildvcs=false", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for _, tc := range ceremonyCases(t) {
		for _, quoted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/quoted=%v", tc.name, quoted), func(t *testing.T) {
				raw := tc.raw
				if quoted {
					b, err := json.Marshal(raw)
					if err != nil {
						t.Fatal(err)
					}
					raw = string(b)
				}
				command := exec.Command(binary)
				command.Stdin = strings.NewReader(raw)
				var stdout, stderr bytes.Buffer
				command.Stdout, command.Stderr = &stdout, &stderr
				err := command.Run()
				exit := 0
				if err != nil {
					var status *exec.ExitError
					if !errors.As(err, &status) {
						t.Fatal(err)
					}
					exit = status.ExitCode()
				}
				if exit != tc.exit || stdout.String() != tc.want || stderr.Len() != 0 {
					t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
				}
				t.Logf("binary main exit=%d stdout=%q stderr=empty", exit, stdout.String())
			})
		}
	}
}
