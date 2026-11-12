package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Public deterministic test scalars, never wallet keys.
func cliKey(n byte) (*btcec.PrivateKey, string) {
	b := make([]byte, 32)
	b[31] = n
	k, p := btcec.PrivKeyFromBytes(b)
	return k, hex.EncodeToString(schnorr.SerializePubKey(p))
}

func cliRun(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	var out bytes.Buffer
	code := run(args, &out)
	var m map[string]any
	if e := json.Unmarshal(out.Bytes(), &m); e != nil {
		t.Fatalf("output is not one JSON object: %q", out.String())
	}
	return code, m
}

func cliInput(t *testing.T) rental.PayGrantV2Input {
	t.Helper()
	golden, e := os.ReadFile("../../testdata/px1/terms-v2-allow.json")
	if e != nil {
		t.Fatal(e)
	}
	var terms rental.PayTermsV2
	if e := json.Unmarshal(golden, &terms); e != nil {
		t.Fatal(e)
	}
	_, issuer := cliKey(1)
	_, grantee := cliKey(2)
	return rental.PayGrantV2Input{Network: "main", Genesis: su.MainGenesis, AgentName: "id/ivanopcode-cedar", LandlordName: "id/ivanopcode", IssuerKey: issuer, GranteeKey: grantee, NotBefore: 1794000000, NotAfter: 1794000000 + 30*86400, Seal: rental.Point{TxID: strings.Repeat("b", 64), Vout: 1}, BudgetSat: 500000, Terms: terms, ConsentCreatedAt: 1794000060, PrivacyNoticeSHA256: rental.Hash([]byte("g2-privacy-notice"))}
}

func cliWrite(t *testing.T, dir, name string, v any) string {
	t.Helper()
	b, ok := v.([]byte)
	if !ok {
		b, _ = json.Marshal(v)
	}
	path := filepath.Join(dir, name)
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	return path
}

// Claim: "terms" prints the frozen contract hash for the golden fixture and
// writes <contract_sha256>.json once; a second write refuses instead of
// overwriting; invalid caps and an unknown member refuse with exit 1.
func TestCLITerms(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	golden, _ := os.ReadFile("../../testdata/px1/terms-v2-allow.json")
	path := cliWrite(t, dir, "terms.json", golden)
	code, m := cliRun(t, "terms", "-terms", path, "-out-dir", out)
	const sha = "8fd808bf05a15ce5bc3d2be0a3086f1d8ccd64c6b4224b66def6e10b22fa28d0"
	if code != 0 || m["contract_sha256"] != sha {
		t.Fatal("terms", code, m)
	}
	if b, e := os.ReadFile(filepath.Join(out, sha+".json")); e != nil || !bytes.Equal(b, golden) {
		t.Fatal("terms file")
	}
	if code, m := cliRun(t, "terms", "-terms", path, "-out-dir", out); code != 1 || m["reason"] != "OUTPUT_EXISTS_OR_UNWRITABLE" {
		t.Fatal("overwrite", code, m)
	}
	bad := cliWrite(t, dir, "bad.json", bytes.Replace(golden, []byte(`"transfer_cap_sat":100000`), []byte(`"transfer_cap_sat":0`), 1))
	if code, m := cliRun(t, "terms", "-terms", bad); code != 1 || m["reason"] != "CONTRACT_BUDGET" {
		t.Fatal("invalid caps", code, m)
	}
	unknown := cliWrite(t, dir, "unknown.json", bytes.Replace(golden, []byte(`{"version":2`), []byte(`{"extra":1,"version":2`), 1))
	if code, m := cliRun(t, "terms", "-terms", unknown); code != 1 || m["reason"] != "TERMS_INPUT" {
		t.Fatal("unknown member", code, m)
	}
}

// Claim: "issue" completes the ceremony through the file exchange when the
// remote side gates every signature on "check-request" (exit 0), and writes
// the terms, signed grant and result; "present" then yields a presentation
// that ParseGrantPresentation accepts. "check-request" refuses a tampered
// digest, and "issue" refuses invalid input before writing any request.
func TestCLIIssueCeremony(t *testing.T) {
	dir, outbox, inbox, out := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	in := cliInput(t)
	inPath := cliWrite(t, dir, "input.json", in)
	keys := map[string]byte{in.IssuerKey: 1, in.GranteeKey: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	checked := make(chan string, 8)
	go func() {
		seen := map[string]bool{}
		for ctx.Err() == nil {
			entries, _ := os.ReadDir(outbox)
			for _, en := range entries {
				name := en.Name()
				if !strings.HasSuffix(name, ".request.json") || seen[name] {
					continue
				}
				seen[name] = true
				reqPath := filepath.Join(outbox, name)
				var buf bytes.Buffer
				if run([]string{"check-request", "-request", reqPath}, &buf) != 0 {
					checked <- "refused " + name
					continue
				}
				checked <- "ok"
				raw, _ := os.ReadFile(reqPath)
				var req rental.PayGrantSigningRequest
				_ = json.Unmarshal(raw, &req)
				priv, _ := cliKey(keys[req.SignerKey])
				s, _ := schnorr.Sign(priv, mustHex(req.Digest))
				b, _ := json.Marshal(rental.PayGrantSignature{Version: 1, Purpose: req.Purpose, SignerKey: req.SignerKey, Digest: req.Digest, Signature: hex.EncodeToString(s.Serialize())})
				target := filepath.Join(inbox, strings.TrimSuffix(name, ".request.json")+".signature.json")
				_ = os.WriteFile(target+".part", b, 0600)
				_ = os.Rename(target+".part", target)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	code, m := cliRun(t, "issue", "-input", inPath, "-outbox", outbox, "-inbox", inbox, "-out-dir", out, "-poll", "1ms", "-timeout", "15s")
	if code != 0 || m["verdict"] != "issued" {
		t.Fatal("issue", code, m)
	}
	for i := 0; i < 3; i++ {
		if v := <-checked; v != "ok" {
			t.Fatal(v)
		}
	}
	grantPath := filepath.Join(out, "signed-grant.json")
	raw, e := os.ReadFile(grantPath)
	if e != nil {
		t.Fatal(e)
	}
	s, e := rental.ParseSignedGrant(raw)
	if e != nil || s.ID() != m["grant_id"] {
		t.Fatal("signed grant", e)
	}
	if _, e := os.Stat(filepath.Join(out, m["contract_sha256"].(string)+".json")); e != nil {
		t.Fatal("terms artifact", e)
	}
	presentation := filepath.Join(out, s.ID()+".json")
	if code, pm := cliRun(t, "present", "-grant", grantPath, "-txid", strings.Repeat("c", 64), "-out", presentation); code != 0 || pm["grant_id"] != s.ID() {
		t.Fatal("present", code, pm)
	}
	if b, _ := os.ReadFile(presentation); func() error { _, e := rental.ParseGrantPresentation(b); return e }() != nil {
		t.Fatal("presentation")
	}
	if code, pm := cliRun(t, "present", "-grant", grantPath, "-txid", "c", "-out", filepath.Join(out, "x.json")); code != 1 || pm["reason"] != "ISSUANCE_LOCATOR" {
		t.Fatal("bad txid", code, pm)
	}

	// Tampered digest: the conforming check refuses.
	entries, _ := os.ReadDir(outbox)
	rawReq, _ := os.ReadFile(filepath.Join(outbox, entries[0].Name()))
	var req rental.PayGrantSigningRequest
	_ = json.Unmarshal(rawReq, &req)
	req.Digest = strings.Repeat("a", 64)
	tampered := cliWrite(t, dir, "tampered.json", req)
	if code, tm := cliRun(t, "check-request", "-request", tampered); code != 1 || tm["reason"] != "SIGNING_REQUEST_DIGEST" {
		t.Fatal("tampered digest", code, tm)
	}

	// Invalid input: no request leaves the helper.
	in.BudgetSat = 1
	badIn := cliWrite(t, dir, "bad-input.json", in)
	emptyBox := t.TempDir()
	if code, bm := cliRun(t, "issue", "-input", badIn, "-outbox", emptyBox, "-inbox", inbox, "-out-dir", t.TempDir()); code != 1 || bm["reason"] != "CONTRACT_BUDGET" {
		t.Fatal("invalid input", code, bm)
	}
	if left, _ := os.ReadDir(emptyBox); len(left) != 0 {
		t.Fatal("invalid input wrote a request")
	}
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }
