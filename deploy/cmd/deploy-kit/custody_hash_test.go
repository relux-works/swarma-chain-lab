package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

// cliR4Spec is the r4 launch custody spec of the T18 real-host report, and
// cliR4SpecSHA the spec_sha256 its stored valid report carries in the header.
const (
	cliR4Spec    = "../../testdata/t18-real-host-r4/custody-spec.json"
	cliR4Report  = "../../testdata/t18-real-host-r4/valid-real.txt"
	cliR4SpecSHA = "cd88fe1a0c42dcb137d77f456a674fc57fb0b325a2a01fddbe153ed225563077"
)

// cliSha is the hex SHA-256 of b: the shell's hash of a file's bytes.
func cliSha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// cliPassingReport is a custody report for spec whose every probe passes,
// bound to the given spec hash, as the agent UID.
func cliPassingReport(spec deploy.CustodySpecV1, sha string) []byte {
	r := deploy.CustodyReportV1{Version: 1, SpecSHA256: sha, UID: spec.AgentUID, GID: spec.AgentUID, Pass: true}
	for _, p := range spec.DeniedReads {
		r.Probes = append(r.Probes, deploy.CustodyProbeV1{Kind: "read", Target: p, Expect: "denied", Observed: "EACCES", Pass: true})
	}
	for _, p := range spec.DeniedRPC {
		r.Probes = append(r.Probes, deploy.CustodyProbeV1{Kind: "rpc", Target: p, Expect: "denied", Observed: "HTTP_401", Pass: true})
	}
	r.Probes = append(r.Probes, deploy.CustodyProbeV1{Kind: "socket", Target: spec.AllowedSocket, Expect: "allowed", Observed: "CONNECTED", Pass: true})
	b, _ := json.Marshal(r)
	return append(b, '\n')
}

// Claim: on the r4 launch spec and on its two whitespace variants that the
// shared reader accepts (a leading space; a trailing space before the
// newline), g2-custody-hash prints exactly one line, T18_CUSTODY_SPEC_SHA256
// cd88fe1a..., the spec_sha256 of the stored r4 valid report, and
// g2-custody-verify (default launch layout) verifies a passing report bound to
// that printed hash against the same file and prints the same hex. The
// variants are the shell-hash witness: SHA-256 of the file bytes minus the
// trailing newline differs from the canonical hash for both, so a command
// hashing bytes instead of the parsed spec fails here. Valid neighbours: the
// canonical file and the file without its newline print the same line, and a
// report bound to an all-zero hash is refused by verify.
func TestG2CustodyHashR4Spec(t *testing.T) {
	raw, e := os.ReadFile(cliR4Spec)
	if e != nil {
		t.Fatal("G2_CLI_CUSTODY_HASH setup", e)
	}
	stored, e := os.ReadFile(cliR4Report)
	if e != nil || !strings.Contains(strings.SplitN(string(stored), "\n", 2)[0], " spec_sha256="+cliR4SpecSHA+" ") {
		t.Fatal("G2_CLI_CUSTODY_HASH setup: r4 report header does not carry the r4 hash", e)
	}
	body := bytes.TrimSuffix(raw, []byte("\n"))
	spec, e := deploy.ParseCustodySpec(body)
	if e != nil || deploy.ValidateG2CustodyLaunchSpec(spec) != nil {
		t.Fatal("G2_CLI_CUSTODY_HASH setup: r4 spec", e)
	}
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	if e := os.WriteFile(report, cliPassingReport(spec, cliR4SpecSHA), 0600); e != nil {
		t.Fatal(e)
	}
	want := "T18_CUSTODY_SPEC_SHA256 " + cliR4SpecSHA + "\n"
	for _, c := range []struct {
		name      string
		b         []byte
		shellSame bool // the shell's hash happens to agree for this file
	}{
		{"canonical", raw, true},
		{"no-newline", body, true},
		{"lead-space", append([]byte(" "), raw...), false},
		{"trail-space", append(append(append([]byte{}, body...), ' '), '\n'), false},
	} {
		path := filepath.Join(dir, c.name+".json")
		if e := os.WriteFile(path, c.b, 0600); e != nil {
			t.Fatal(e)
		}
		var out bytes.Buffer
		if e := g2CustodyHash([]string{"-spec", path}, &out); e != nil || out.String() != want {
			t.Fatalf("G2_CLI_CUSTODY_HASH %s: %v %q want %q", c.name, e, out.String(), want)
		}
		if shell := cliSha(bytes.TrimSuffix(c.b, []byte("\n"))); (shell == cliR4SpecSHA) != c.shellSame {
			t.Fatalf("G2_CLI_CUSTODY_HASH setup: %s shell hash %s", c.name, shell)
		}
		out.Reset()
		if e := g2CustodyVerify([]string{"-spec", path, "-report", report}, &out); e != nil || out.String() != "T18_CUSTODY_VERIFIED "+cliR4SpecSHA+"\n" {
			t.Fatalf("G2_CLI_CUSTODY_HASH verify %s: %v %q", c.name, e, out.String())
		}
	}
	zero := filepath.Join(dir, "zero.json")
	os.WriteFile(zero, cliPassingReport(spec, strings.Repeat("0", 64)), 0600)
	if e := g2CustodyVerify([]string{"-spec", cliR4Spec, "-report", zero}, io.Discard); e != deploy.ErrCustody {
		t.Fatal("G2_CLI_CUSTODY_HASH verify accepted another hash", e)
	}
}

// Claim: a spec file the shared reader refuses (missing, over 64 KiB,
// non-canonical JSON, an unknown member, an unresolved placeholder, a
// reserved agent UID) is refused by g2-custody-hash with exactly the error
// g2-custody-probe and g2-custody-verify (with and without -launch=false)
// return for the same file, a named error, never nil, and nothing is printed.
// A malformed command line (an extra argument, an unknown flag) is ErrInput
// with no output; a missing -spec reads no file and is refused like a missing
// file. Valid neighbour: another valid spec prints its own hash, not r4's.
// Limit: verify's -launch layout check is not applied by g2-custody-hash (nor
// by probe); a valid non-launch spec prints its hash.
func TestG2CustodyHashRefusals(t *testing.T) {
	raw, e := os.ReadFile(cliR4Spec)
	if e != nil {
		t.Fatal("G2_CLI_CUSTODY_HASH setup", e)
	}
	body := string(bytes.TrimSuffix(raw, []byte("\n")))
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	report := write("report.json", `{"v":1}`+"\n")
	for _, c := range []struct {
		name, path string
		want       error
	}{
		{"missing-file", filepath.Join(dir, "absent.json"), deploy.ErrPolicy},
		{"oversize", write("big.json", body+strings.Repeat(" ", 1<<16)), deploy.ErrPolicy},
		{"non-canonical", write("nc.json", strings.Replace(body, `"v":1,`, `"v": 1,`, 1)+"\n"), deploy.ErrPolicy},
		{"unknown-member", write("um.json", strings.Replace(body, `{"v":1,`, `{"v":1,"x":1,`, 1)+"\n"), deploy.ErrPolicy},
		{"placeholder", write("ph.json", strings.Replace(body, "wallet.sock", "PLACEHOLDER.sock", 1)+"\n"), deploy.ErrPlaceholder},
		{"reserved-uid", write("ru.json", strings.Replace(body, `"agent_uid":1201`, `"agent_uid":65534`, 1)+"\n"), deploy.ErrPolicy},
	} {
		var out bytes.Buffer
		got := g2CustodyHash([]string{"-spec", c.path}, &out)
		probe := g2CustodyProbe([]string{"-spec", c.path}, io.Discard)
		verify := g2CustodyVerify([]string{"-spec", c.path, "-report", report}, io.Discard)
		verifyNoLaunch := g2CustodyVerify([]string{"-spec", c.path, "-report", report, "-launch=false"}, io.Discard)
		if got == nil || got != c.want || got != probe || got != verify || got != verifyNoLaunch || out.Len() != 0 {
			t.Fatalf("G2_CLI_CUSTODY_HASH refusal %s: hash=%v probe=%v verify=%v verify-no-launch=%v want=%v out=%q", c.name, got, probe, verify, verifyNoLaunch, c.want, out.String())
		}
	}
	for name, args := range map[string][]string{
		"extra-arg":    {"-spec", cliR4Spec, "x"},
		"unknown-flag": {"-spec", cliR4Spec, "-launch=false"},
	} {
		var out bytes.Buffer
		if e := g2CustodyHash(args, &out); e != deploy.ErrInput || out.Len() != 0 {
			t.Fatalf("G2_CLI_CUSTODY_HASH %s: %v %q", name, e, out.String())
		}
	}
	var out bytes.Buffer
	if e := g2CustodyHash(nil, &out); e != deploy.ErrPolicy || out.Len() != 0 {
		t.Fatalf("G2_CLI_CUSTODY_HASH no -spec: %v %q", e, out.String())
	}
	other := deploy.CustodySpecV1{Version: 1, AgentUID: 210001, ServiceUID: 210201, DeniedReads: []string{"/etc/swarma/wallet/wallet.json"}, DeniedRPC: []string{"127.0.0.1:8336"}, AllowedSocket: "/run/swarma-wallet/wallet.sock"}
	b, _ := json.Marshal(other)
	if deploy.ValidateG2CustodyLaunchSpec(other) == nil {
		t.Fatal("G2_CLI_CUSTODY_HASH setup: neighbour must be a non-launch spec")
	}
	if e := g2CustodyHash([]string{"-spec", write("other.json", string(b)+"\n")}, &out); e != nil || out.String() != "T18_CUSTODY_SPEC_SHA256 "+cliSha(b)+"\n" || strings.Contains(out.String(), cliR4SpecSHA) {
		t.Fatalf("G2_CLI_CUSTODY_HASH valid neighbour: %v %q", e, out.String())
	}
}

// Claim: the subcommand is reachable by name through run and listed in the
// usage line; an unknown name stays refused.
func TestG2CustodyHashDispatch(t *testing.T) {
	if e := run(nil); e == nil || !strings.Contains(e.Error(), "|g2-custody-hash ") {
		t.Fatal("G2_CLI_CUSTODY_HASH usage", e)
	}
	if e := run([]string{"g2-custody-hash", "-spec", filepath.Join(t.TempDir(), "absent")}); e != deploy.ErrPolicy {
		t.Fatal("G2_CLI_CUSTODY_HASH dispatch", e)
	}
	if e := run([]string{"g2-custody-hashx"}); e == nil || e == deploy.ErrPolicy {
		t.Fatal("G2_CLI_CUSTODY_HASH unknown name accepted", e)
	}
}
