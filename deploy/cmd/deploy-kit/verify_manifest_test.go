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
