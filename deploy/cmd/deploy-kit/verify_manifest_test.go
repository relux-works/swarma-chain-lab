package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

func manifestFixture(t *testing.T) []byte {
	t.Helper()
	raw, e := os.ReadFile("../../g2ledger/testdata/release-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func manifestEdit(t *testing.T, raw []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var root map[string]any
	if e := json.Unmarshal(raw, &root); e != nil {
		t.Fatal(e)
	}
	edit(root)
	result, e := json.Marshal(root)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func manifestRow(root map[string]any, inventory string, i int) map[string]any {
	return root[inventory].([]any)[i].(map[string]any)
}

func manifestModule(root map[string]any) map[string]any {
	return manifestRow(root, "linkage", 0)["modules"].([]any)[0].(map[string]any)
}

func checkManifestFile(t *testing.T, raw []byte, commit, refusal string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if e := os.WriteFile(path, raw, 0400); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	e := verifyManifest([]string{"-manifest", path, "-commit", commit}, &out)
	if refusal != "" {
		if e == nil || e.Error() != refusal || out.Len() != 0 {
			t.Fatalf("want %s and empty stdout; got %v %q", refusal, e, out.String())
		}
	} else {
		m, err := deploy.ValidateManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("verified manifest commit=%s binaries=%d strict=%s\n", commit, len(m.Linkage), deploy.StrictParseCommit)
		if e != nil || out.String() != want {
			t.Fatalf("want summary %q; got %v %q", want, e, out.String())
		}
	}
	// Claim: acceptance and refusal preserve input bytes/mode and create no sibling files.
	after, e := os.ReadFile(path)
	st, statErr := os.Stat(path)
	entries, dirErr := os.ReadDir(dir)
	if e != nil || !bytes.Equal(after, raw) || statErr != nil || st.Mode().Perm() != 0400 || dirErr != nil || len(entries) != 1 {
		t.Fatal("manifest verification changed the input directory")
	}
}

// Claim: the ledger fixture accepts only its exact commit pin; a different valid pin refuses without output or writes.
func TestVerifyManifestCommitPin(t *testing.T) {
	raw := manifestFixture(t)
	m, e := deploy.ValidateManifest(raw)
	if e != nil {
		t.Fatal(e)
	}
	checkManifestFile(t, raw, m.Commit, "")
	checkManifestFile(t, raw, strings.Repeat("b", 40), "VERIFY_MANIFEST_COMMIT")
}

// Claim: fixture mutations exercise both refusal and acceptance parity with the shipped validator, independently of commit-pin checks.
func TestVerifyManifestParity(t *testing.T) {
	checkManifestParity(t, manifestFixture(t))
}

func checkManifestParity(t *testing.T, raw []byte) {
	t.Helper()
	m, e := deploy.ValidateManifest(raw)
	if e != nil {
		t.Fatal(e)
	}
	checkManifestFile(t, raw, m.Commit, "")
	reject := map[string]func(map[string]any){
		"unknown-root":         func(r map[string]any) { r["unexpected"] = "private-marker" },
		"unknown-artifact":     func(r map[string]any) { manifestRow(r, "artifacts", 0)["unexpected"] = true },
		"unknown-tool":         func(r map[string]any) { manifestRow(r, "tools", 0)["unexpected"] = true },
		"wrong-os":             func(r map[string]any) { r["goos"] = "darwin" },
		"wrong-arch":           func(r map[string]any) { r["goarch"] = "arm64" },
		"wrong-cgo":            func(r map[string]any) { r["cgo_enabled"] = "1" },
		"wrong-flags":          func(r map[string]any) { r["build_flags"] = []string{"-trimpath"} },
		"wrong-artifact-hash":  func(r map[string]any) { manifestRow(r, "artifacts", 0)["sha256"] = "bad" },
		"wrong-tool-hash":      func(r map[string]any) { manifestRow(r, "tools", 0)["sha256"] = strings.Repeat("A", 64) },
		"missing-artifact":     func(r map[string]any) { r["artifacts"] = r["artifacts"].([]any)[1:] },
		"missing-tool":         func(r map[string]any) { r["tools"] = r["tools"].([]any)[1:] },
		"reordered-artifacts":  func(r map[string]any) { rows := r["artifacts"].([]any); rows[0], rows[1] = rows[1], rows[0] },
		"reordered-tools":      func(r map[string]any) { rows := r["tools"].([]any); rows[0], rows[1] = rows[1], rows[0] },
		"reordered-linkage":    func(r map[string]any) { rows := r["linkage"].([]any); rows[0], rows[1] = rows[1], rows[0] },
		"missing-linkage-row":  func(r map[string]any) { r["linkage"] = r["linkage"].([]any)[1:] },
		"missing-module-row":   func(r map[string]any) { manifestRow(r, "linkage", 0)["modules"] = []any{} },
		"non-contains-verdict": func(r map[string]any) { manifestModule(r)["verdict"] = "not-contains " + deploy.StrictParseCommit },
		"wrong-strict-commit":  func(r map[string]any) { manifestModule(r)["verdict"] = "contains " + strings.Repeat("b", 40) },
	}
	for name, edit := range reject {
		t.Run(name, func(t *testing.T) {
			candidate := manifestEdit(t, raw, edit)
			if _, e := deploy.ValidateManifest(candidate); e == nil {
				t.Fatal("negative control unexpectedly accepted by ValidateManifest")
			}
			checkManifestFile(t, candidate, m.Commit, "VERIFY_MANIFEST_INVALID")
		})
	}
	malformed := map[string][]byte{
		"duplicate-json-keys": bytes.Replace(raw, []byte(`"commit":`), []byte(`"commit":"`+m.Commit+`","commit":`), 1),
		"trailing-data":       append(append([]byte(nil), raw...), []byte(` {}`)...),
		"truncated-file":      raw[:len(raw)/2],
	}
	for name, candidate := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, e := deploy.ValidateManifest(candidate); e == nil {
				t.Fatal("malformed control unexpectedly accepted by ValidateManifest")
			}
			checkManifestFile(t, candidate, m.Commit, "VERIFY_MANIFEST_INVALID")
		})
	}
	// Claim: optional null/empty fields and alternate internal-module forms accepted by ValidateManifest remain valid consumer inputs.
	accept := map[string]func(map[string]any){
		"published-empty-replace":   func(r map[string]any) { row := manifestModule(r); row["replace"] = ""; row["version"] = "v0.3.1" },
		"published-null-replace":    func(r map[string]any) { row := manifestModule(r); row["replace"] = nil; row["version"] = "v0.3.1" },
		"local-null-version":        func(r map[string]any) { manifestModule(r)["version"] = nil },
		"local-replace-and-version": func(r map[string]any) { manifestModule(r)["version"] = "v0.3.1" },
		"root-internal-module": func(r map[string]any) {
			row := map[string]any{"module": "github.com/relux-works/swarma-chain-lab", "version": "v0.3.1", "commit": m.Commit, "verdict": "contains " + deploy.StrictParseCommit}
			binary := manifestRow(r, "linkage", 0)
			binary["modules"] = append([]any{row}, binary["modules"].([]any)...)
		},
	}
	for name, edit := range accept {
		t.Run(name, func(t *testing.T) {
			candidate := manifestEdit(t, raw, edit)
			if _, e := deploy.ValidateManifest(candidate); e != nil {
				t.Fatalf("positive control refused by ValidateManifest: %v", e)
			}
			checkManifestFile(t, candidate, m.Commit, "")
		})
	}
}

// Claim: each of the plan's 15 negative release-check mutations is refused
// by both the command handler and the executable, with a named reason, empty
// stdout and no input changes. POS-R1 is the nearby accepting control.
func TestVerifyManifestReleaseCheckCases(t *testing.T) {
	checkManifestReleaseCases(t, manifestFixture(t))
}

func checkManifestReleaseCases(t *testing.T, raw []byte) {
	t.Helper()
	m, e := deploy.ValidateManifest(raw)
	if e != nil {
		t.Fatal(e)
	}
	// The minimal ledger fixture has only one local module per binary. Add a
	// valid published dependency to make missing-version, missing-main and
	// descending-order mutations meaningful. Real releases already have both
	// local and published gateway modules and are used without this addition.
	var root map[string]any
	if e := json.Unmarshal(raw, &root); e != nil {
		t.Fatal(e)
	}
	modules := manifestRow(root, "linkage", 0)["modules"].([]any)
	published := false
	for _, item := range modules {
		if item.(map[string]any)["replace"] == nil || item.(map[string]any)["replace"] == "" {
			published = true
		}
	}
	if !published {
		raw = manifestEdit(t, raw, func(r map[string]any) {
			row := manifestRow(r, "linkage", 0)
			dependency := map[string]any{
				"module":  "github.com/relux-works/swarma-chain-lab/experiments/rental",
				"version": "v0.3.1", "commit": m.Commit,
				"verdict": "contains " + deploy.StrictParseCommit,
			}
			row["modules"] = append([]any{dependency}, row["modules"].([]any)...)
		})
	}
	if _, e := deploy.ValidateManifest(raw); e != nil {
		t.Fatalf("release-check positive baseline: %v", e)
	}
	module := func(r map[string]any, local bool) map[string]any {
		for _, item := range manifestRow(r, "linkage", 0)["modules"].([]any) {
			row := item.(map[string]any)
			replace, _ := row["replace"].(string)
			if (replace != "") == local {
				return row
			}
		}
		t.Fatal("baseline lacks the required local or published gateway module")
		return nil
	}
	cases := []struct {
		name    string
		edit    func(map[string]any)
		rawEdit func([]byte) []byte
		pin     string
		reason  string
	}{
		{name: "POS-R1-release-of-h-with-full-linkage"},
		{
			name: "NEG-R1-01-release-of-another-commit",
			edit: func(r map[string]any) { r["commit"] = strings.Repeat("2", 40) },
			// The unchanged in-tree module commits now disagree with the
			// mutated release commit, so shared validation refuses first.
			reason: "VERIFY_MANIFEST_INVALID",
		},
		{name: "NEG-R1-02-manifest-without-linkage", edit: func(r map[string]any) { delete(r, "linkage") }, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-03-foreign-strict-commit", edit: func(r map[string]any) { module(r, false)["verdict"] = "contains " + strings.Repeat("f", 40) }, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-04-abbreviated-verdict", edit: func(r map[string]any) { module(r, false)["verdict"] = "contains " + deploy.StrictParseCommit[:8] }, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-05-binary-without-linkage-row", edit: func(r map[string]any) {
			rows := r["linkage"].([]any)
			r["linkage"] = append(rows[:8], rows[9:]...)
		}, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-06-rows-out-of-release-order", edit: func(r map[string]any) {
			rows := r["linkage"].([]any)
			rows[0], rows[1] = rows[1], rows[0]
		}, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-07-in-tree-module-not-at-h", edit: func(r map[string]any) { module(r, true)["commit"] = strings.Repeat("3", 40) }, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-08-replace-outside-checkout", edit: func(r map[string]any) { module(r, true)["replace"] = "../elsewhere" }, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-09-published-module-without-version", edit: func(r map[string]any) { delete(module(r, false), "version") }, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-10-row-without-main-module", edit: func(r map[string]any) {
			row := manifestRow(r, "linkage", 0)
			own := "github.com/relux-works/swarma-chain-lab/" + manifestRow(r, "artifacts", 0)["module"].(string)
			var keep []any
			for _, item := range row["modules"].([]any) {
				if item.(map[string]any)["module"] != own {
					keep = append(keep, item)
				}
			}
			row["modules"] = keep
		}, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-11-external-module", edit: func(r map[string]any) {
			row := manifestRow(r, "linkage", 0)
			// Keep ascending order so external identity is the only defect.
			row["modules"] = append([]any{map[string]any{
				"module": "github.com/other/mod", "version": "v1.0.0",
				"commit": strings.Repeat("4", 40), "verdict": "contains " + deploy.StrictParseCommit,
			}}, row["modules"].([]any)...)
		}, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-12-modules-not-ascending", edit: func(r map[string]any) {
			rows := manifestRow(r, "linkage", 0)["modules"].([]any)
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-13-unknown-module-key", edit: func(r map[string]any) { manifestModule(r)["note"] = "x" }, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-14-duplicate-verdict-key", rawEdit: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"verdict":`), []byte(`"verdict":"contains `+strings.Repeat("f", 40)+`","verdict":`), 1)
		}, reason: "VERIFY_MANIFEST_INVALID"},
		{name: "NEG-R1-15-abbreviated-h", pin: m.Commit[:8], reason: "VERIFY_MANIFEST_INPUT"},
	}
	binary := filepath.Join(t.TempDir(), "deploy-kit")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build CLI: %v %s", e, output)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := raw
			if tc.edit != nil {
				candidate = manifestEdit(t, raw, tc.edit)
			}
			if tc.rawEdit != nil {
				candidate = tc.rawEdit(raw)
				if bytes.Equal(candidate, raw) {
					t.Fatal("raw mutation was not applied")
				}
			}
			pin := m.Commit
			if tc.pin != "" {
				pin = tc.pin
			}
			checkManifestFile(t, candidate, pin, tc.reason)
			dir := t.TempDir()
			path := filepath.Join(dir, "manifest.json")
			if e := os.WriteFile(path, candidate, 0400); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(binary, "verify-manifest", "-manifest", path, "-commit", pin)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=" + filepath.Join(dir, "no-executables")}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			e := cmd.Run()
			if tc.reason != "" {
				if exit, ok := e.(*exec.ExitError); !ok || exit.ExitCode() != 1 || stdout.Len() != 0 || stderr.String() != tc.reason+"\n" {
					t.Fatalf("want exit 1, empty stdout and %s; got %v %q %q", tc.reason, e, stdout.String(), stderr.String())
				}
			} else {
				want := fmt.Sprintf("verified manifest commit=%s binaries=%d strict=%s\n", pin, len(m.Linkage), deploy.StrictParseCommit)
				if e != nil || stdout.String() != want || stderr.Len() != 0 {
					t.Fatalf("want accepting summary %q; got %v %q %q", want, e, stdout.String(), stderr.String())
				}
			}
			after, readErr := os.ReadFile(path)
			st, statErr := os.Stat(path)
			entries, dirErr := os.ReadDir(dir)
			if readErr != nil || !bytes.Equal(after, candidate) || statErr != nil || st.Mode().Perm() != 0400 || dirErr != nil || len(entries) != 1 {
				t.Fatal("CLI changed the input directory")
			}
		})
	}
}

// Claim: a manifest produced by the real double build passes the same positive and negative parity controls; this test requires an explicit release path.
func TestVerifyManifestRealRelease(t *testing.T) {
	path := os.Getenv("DK1_VERIFY_MANIFEST")
	if path == "" {
		t.Skip("set DK1_VERIFY_MANIFEST to the real double-build manifest")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	checkManifestParity(t, raw)
	t.Run("release-check", func(t *testing.T) { checkManifestReleaseCases(t, raw) })
}

// Claim: malformed flags, invalid pins and unreadable files return only named refusals and no stdout.
func TestVerifyManifestInput(t *testing.T) {
	for _, args := range [][]string{
		nil, {"-manifest", "missing"}, {"-manifest", "missing", "-commit", "bad"},
		{"-manifest", "missing", "-commit", strings.Repeat("z", 40)},
		{"-unexpected", "private-marker"}, {"-help"},
		{"-manifest", "missing", "-commit", strings.Repeat("a", 40), "extra"},
	} {
		var out bytes.Buffer
		if e := verifyManifest(args, &out); e == nil || e.Error() != "VERIFY_MANIFEST_INPUT" || out.Len() != 0 {
			t.Fatalf("invalid input: %v %q", e, out.String())
		}
	}
	var out bytes.Buffer
	if e := verifyManifest([]string{"-manifest", filepath.Join(t.TempDir(), "missing"), "-commit", strings.Repeat("a", 40)}, &out); e == nil || e.Error() != "VERIFY_MANIFEST_READ" || out.Len() != 0 {
		t.Fatalf("missing file: %v %q", e, out.String())
	}
}

// Claim: the real CLI dispatch accepts a read-only fixture with no executables on PATH and refuses a mismatched commit with exit 1 and only the refusal name.
func TestVerifyManifestCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "deploy-kit")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build CLI: %v %s", e, output)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if e := os.WriteFile(path, manifestFixture(t), 0400); e != nil {
		t.Fatal(e)
	}
	for _, commit := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
		cmd := exec.Command(binary, "verify-manifest", "-manifest", path, "-commit", commit)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + filepath.Join(dir, "no-executables")}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		e := cmd.Run()
		if commit[0] == 'a' {
			if e != nil || !strings.HasPrefix(stdout.String(), "verified manifest commit="+commit+" ") || strings.Count(stdout.String(), "\n") != 1 || stderr.Len() != 0 {
				t.Fatalf("valid CLI: %v %q %q", e, stdout.String(), stderr.String())
			}
		} else if exit, ok := e.(*exec.ExitError); !ok || exit.ExitCode() != 1 || stdout.Len() != 0 || stderr.String() != "VERIFY_MANIFEST_COMMIT\n" {
			t.Fatalf("refusal CLI: %v %q %q", e, stdout.String(), stderr.String())
		}
	}
}
