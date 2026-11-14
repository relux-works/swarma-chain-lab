//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the built CLI preserves exit codes 0/1/2/3, executes its audited
// exclusive keygen in a real child, protects a pre-existing key, and reports a
// crashed intent without touching its orphan or older entries. No root commands.
func TestLedgerCLIRealExclusiveCreatorAndExitCodes(t *testing.T) {
	root := t.TempDir()
	kit := filepath.Join(root, "deploy-kit")
	build := exec.Command("go", "build", "-o", kit, ".")
	if raw, e := build.CombinedOutput(); e != nil {
		t.Fatalf("CLI build: %v %s", e, raw)
	}
	base := filepath.Join(root, "baseline")
	if e := os.Mkdir(base, 0700); e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string][]byte{"taken-at.txt": []byte("captured\n"), "errors.txt": nil} {
		if e := os.WriteFile(filepath.Join(base, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	manifest := filepath.Join(root, "manifest.json")
	raw, e := os.ReadFile("../../g2ledger/testdata/release-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(manifest, raw, 0600); e != nil {
		t.Fatal(e)
	}
	invoke := func(want int, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(kit, args...)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		e := cmd.Run()
		got := 0
		if e != nil {
			status, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatal(e)
			}
			got = status.ExitCode()
		}
		if got != want {
			t.Fatalf("command %s exit=%d want=%d stderr=%s", args[0], got, want, stderr.Bytes())
		}
		if want != 0 && stderr.Len() == 0 {
			t.Fatal("missing named stderr")
		}
		return out.Bytes()
	}
	outputs := filepath.Join(root, "outputs")
	if e = os.Mkdir(outputs, 0700); e != nil {
		t.Fatal(e)
	}
	scopeFile := filepath.Join(root, "scope.json")
	scopeRaw, e := json.Marshal(map[string]any{"paths": []map[string]string{{"path": filepath.Join(outputs, "key"), "kind": "secret"}, {"path": filepath.Join(outputs, "closed-key"), "kind": "secret"}, {"path": filepath.Join(outputs, "rehearsal-key"), "kind": "secret"}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(scopeFile, scopeRaw, 0600); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "ledger")
	invoke(0, "g2-ledger", "init", "-dir", dir, "-manifest", manifest, "-baseline", base, "-scope", scopeFile, "-purpose", "station")
	invoke(1, "g2-ledger", "init", "-dir", dir, "-manifest", manifest, "-baseline", base, "-scope", scopeFile, "-purpose", "station")
	invoke(2, "g2-ledger", "create-file", "-dir", dir)
	key := filepath.Join(outputs, "key")
	out := invoke(0, "g2-ledger", "exec-create", "-dir", dir, "-kind", "secret", "-ret", "d6", "-path", key, "--", kit, "g2-keygen", "-out", key)
	if !strings.HasPrefix(string(out), "G2_KEY_XONLY ") {
		t.Fatal("public output missing")
	}
	before, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(before)
	invoke(1, "g2-ledger", "exec-create", "-dir", dir, "-kind", "secret", "-ret", "d6", "-path", key, "--", kit, "g2-keygen", "-out", key)
	invoke(1, "g2-ledger", "replay", "-dir", dir, "-mode", "rehearsal")
	invoke(0, "g2-ledger", "verify", "-dir", dir)
	compareOut := invoke(0, "g2-ledger", "replay", "-dir", dir, "-mode", "station")
	if !bytes.Contains(compareOut, []byte(`"type":"retained"`)) || !bytes.Contains(compareOut, []byte(`"rule":"retain-d6"`)) {
		t.Fatal("missing machine-readable retention")
	}
	rehearsalDir := filepath.Join(root, "rehearsal-ledger")
	invoke(0, "g2-ledger", "init", "-dir", rehearsalDir, "-manifest", manifest, "-baseline", base, "-scope", scopeFile, "-purpose", "rehearsal")
	rehearsalKey := filepath.Join(outputs, "rehearsal-key")
	invoke(0, "g2-ledger", "exec-create", "-dir", rehearsalDir, "-kind", "secret", "-ret", "rehearsal", "-path", rehearsalKey, "--", kit, "g2-keygen", "-out", rehearsalKey)
	invoke(1, "g2-ledger", "replay", "-dir", rehearsalDir, "-mode", "station")
	invoke(0, "g2-ledger", "replay", "-dir", rehearsalDir, "-mode", "rehearsal")
	if _, e = os.Lstat(rehearsalKey); !os.IsNotExist(e) {
		t.Fatal("rehearsal CLI key retained")
	}
	invoke(1, "g2-ledger", "exec-create", "-dir", dir, "-kind", "secret", "-ret", "rehearsal", "-path", rehearsalKey, "--", kit, "g2-keygen", "-out", rehearsalKey)
	after, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("retained key changed")
	}
	// A closed public-output pipe returns the ledger's named failure, while
	// its already-committed secret remains tracked and preserved.
	closedKey := filepath.Join(outputs, "closed-key")
	closedDir := filepath.Join(root, "closed-ledger")
	invoke(0, "g2-ledger", "init", "-dir", closedDir, "-manifest", manifest, "-baseline", base, "-scope", scopeFile, "-purpose", "station")
	pipeR, pipeW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	pipeR.Close()
	closed := exec.Command(kit, "g2-ledger", "exec-create", "-dir", closedDir, "-kind", "secret", "-ret", "d6", "-path", closedKey, "--", kit, "g2-keygen", "-out", closedKey)
	var closedErr bytes.Buffer
	closed.Stdout = pipeW
	closed.Stderr = &closedErr
	result := closed.Run()
	pipeW.Close()
	status, ok := result.(*exec.ExitError)
	if !ok || status.ExitCode() != 1 || !strings.Contains(closedErr.String(), "EXEC_PUBLIC_OUTPUT") {
		t.Fatal("closed stdout did not return named exit 1")
	}
	invoke(0, "g2-ledger", "verify", "-dir", closedDir)
	// Simulate a process stopping immediately after its durable intent: retain
	// that valid prefix, update its HEAD to the observed intent, and keep the key.
	records := filepath.Join(dir, "records.jsonl")
	raw, e = os.ReadFile(records)
	if e != nil {
		t.Fatal(e)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatal("unexpected record shape")
	}
	var intent struct {
		Hash string `json:"hash"`
	}
	if e = json.Unmarshal(lines[1], &intent); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(records, append(bytes.Join(lines[:2], []byte{'\n'}), '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	head, e := json.Marshal(struct {
		Count uint64 `json:"count"`
		Hash  string `json:"hash"`
	}{2, intent.Hash})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "HEAD"), head, 0600); e != nil {
		t.Fatal(e)
	}
	invoke(3, "g2-ledger", "verify", "-dir", dir)
	invoke(3, "g2-ledger", "replay", "-dir", dir, "-mode", "station")
	if _, e = os.Stat(key); e != nil {
		t.Fatal("orphan removed")
	}
	// Claim: the real CLI rejects removed/unknown modes with exit 2 before
	// reading even an orphaned ledger, preserving journal, HEAD and key bytes.
	// Valid station and rehearsal subprocess neighbours are exercised above.
	t.Run("unknown-replay-modes-before-ledger-read", func(t *testing.T) {
		paths := []string{records, filepath.Join(dir, "HEAD"), key}
		before := make(map[string][]byte)
		stats := make(map[string]os.FileInfo)
		for _, path := range paths {
			var err error
			before[path], err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before[path])
			stats[path], err = os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, mode := range []string{"station-remove", "unknown", ""} {
			cmd := exec.Command(kit, "g2-ledger", "replay", "-dir", dir, "-mode", mode)
			var out, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &stderr
			result := cmd.Run()
			status, ok := result.(*exec.ExitError)
			if !ok || status.ExitCode() != 2 || strings.TrimSpace(stderr.String()) != "g2-ledger: USAGE_REPLAY" || out.Len() != 0 {
				t.Fatalf("mode %q: missing named usage exit 2: %v stderr=%s", mode, result, stderr.String())
			}
		}
		for _, path := range paths {
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(after)
			stat, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before[path], after) || !os.SameFile(stats[path], stat) || stats[path].Mode() != stat.Mode() || !stats[path].ModTime().Equal(stat.ModTime()) {
				t.Fatal("usage refusal changed ledger or key")
			}
		}
	})
}
