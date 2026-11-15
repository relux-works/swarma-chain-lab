//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy/g2ledger"
)

// Claim: the public executable dispatches rollback with exit 0/1/2/3, uses an initialized rehearsal ledger, and never invokes node controls in these offline cases.
func TestRollbackCLIContract(t *testing.T) {
	root := t.TempDir()
	kit := filepath.Join(root, "deploy-kit")
	build := exec.Command("go", "build", "-o", kit, ".")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	invoke := func(want int, reason string, args ...string) {
		t.Helper()
		cmd := exec.Command(kit, args...)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		e := cmd.Run()
		got := 0
		if e != nil {
			exit, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatal(e)
			}
			got = exit.ExitCode()
		}
		if got != want || !strings.Contains(stderr.String(), reason) {
			t.Fatalf("exit=%d want=%d stderr=%s", got, want, stderr.String())
		}
		if want != 0 && out.Len() != 0 {
			t.Fatal("refusal emitted success output")
		}
	}
	invoke(2, "USAGE_ROLLBACK", "g2-rollback")
	invoke(2, "USAGE_ROLLBACK", "g2-rollback", "-dir", root, "-mode", "station-remove")
	invoke(1, "phase=validate", "g2-rollback", "-dir", filepath.Join(root, "missing"), "-mode", "station")
	baseline := filepath.Join(root, "baseline")
	if e := os.Mkdir(baseline, 0700); e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{"taken-at.txt": []byte("captured\n"), "errors.txt": nil} {
		if e := os.WriteFile(filepath.Join(baseline, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	manifest := filepath.Join(root, "manifest.json")
	b, e := os.ReadFile("../../g2ledger/testdata/release-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(manifest, b, 0600); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "ledger")
	scope := g2ledger.Scope{Reused: []string{}}
	if e = g2ledger.Init(dir, manifest, baseline, g2ledger.InitOptions{Purpose: "rehearsal", Scope: scope}); e != nil {
		t.Fatal(e)
	}
	invoke(0, "", "g2-rollback", "-dir", dir, "-mode", "rehearsal")
	invoke(1, "MODE_PURPOSE_MISMATCH", "g2-rollback", "-dir", dir, "-mode", "station")
	// A canonical fixture represents an unresolved, sealed intent; the ledger
	// tests separately execute the physical modification before interruption.
	scope.Reused = []string{root}
	scope.Paths = []g2ledger.ScopePath{{Path: filepath.Join(root, "orphan"), Kind: "file"}}
	orphanDir := filepath.Join(root, "orphan-ledger")
	if e = g2ledger.Init(orphanDir, manifest, baseline, g2ledger.InitOptions{Purpose: "station", Scope: scope}); e != nil {
		t.Fatal(e)
	}
	records := filepath.Join(orphanDir, "records.jsonl")
	raw, e := os.ReadFile(records)
	if e != nil {
		t.Fatal(e)
	}
	var genesis g2ledger.Record
	if e = json.Unmarshal(bytes.TrimSpace(raw), &genesis); e != nil {
		t.Fatal(e)
	}
	intent := g2ledger.Record{Seq: 1, Prev: genesis.Hash, Body: g2ledger.Body{Op: "intent", Action: &g2ledger.Action{Kind: "file", Ret: "remove", Paths: []string{filepath.Join(root, "orphan")}, Mode: 0600, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}}
	unsigned, _ := json.Marshal(struct {
		Seq  uint64        `json:"seq"`
		Prev string        `json:"prev"`
		Body g2ledger.Body `json:"body"`
	}{intent.Seq, intent.Prev, intent.Body})
	h := sha256.Sum256(unsigned)
	intent.Hash = hex.EncodeToString(h[:])
	line, _ := json.Marshal(intent)
	if e = os.WriteFile(records, append(raw, append(line, '\n')...), 0600); e != nil {
		t.Fatal(e)
	}
	head, _ := json.Marshal(struct {
		Count uint64 `json:"count"`
		Hash  string `json:"hash"`
	}{2, intent.Hash})
	if e = os.WriteFile(filepath.Join(orphanDir, "HEAD"), head, 0600); e != nil {
		t.Fatal(e)
	}
	invoke(3, "cause=ORPHAN", "g2-rollback", "-dir", orphanDir, "-mode", "station")
}
