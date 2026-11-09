package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental/discovery"
)

// CLI emits exact fixture values, reports drift as exit1, and rejects malformed
// inventory without echoing paths/input. Files and stdout are local public data.
func TestCLI(t *testing.T) {
	raw, e := os.ReadFile("../../testdata/n1-values/inventory.json")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.json")
	if e = os.WriteFile(inv, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if code := run([]string{"-inventory", inv}, &out); code != 0 {
		t.Fatal("build", code, out.String())
	}
	expected, e := os.ReadFile("../../testdata/n1-values/record.json")
	if e != nil || !bytes.Equal(out.Bytes(), append(expected, '\n')) {
		t.Fatal("exact publisher fixture", e)
	}
	var rec discovery.Record
	if json.Unmarshal(out.Bytes(), &rec) != nil {
		t.Fatal("record output")
	}
	path := filepath.Join(dir, "record.json")
	os.WriteFile(path, out.Bytes(), 0600)
	out.Reset()
	if code := run([]string{"-inventory", inv, "-record", path}, &out); code != 0 || !strings.Contains(out.String(), `"ok":true`) {
		t.Fatal("check", code, out.String())
	}
	rec.Value = strings.Replace(rec.Value, `"cedar":`, `"birch":`, 1)
	b, _ := json.Marshal(rec)
	os.WriteFile(path, b, 0600)
	out.Reset()
	if code := run([]string{"-inventory", inv, "-record", path}, &out); code != 1 || !strings.Contains(out.String(), `"ok":false`) {
		t.Fatal("drift", code, out.String())
	}
	os.WriteFile(inv, []byte(`{"landlord":null}`), 0600)
	out.Reset()
	if code := run([]string{"-inventory", inv}, &out); code != 2 || out.String() != "{\"error\":\"INPUT\"}\n" {
		t.Fatal("invalid input output", code, out.String())
	}
}
