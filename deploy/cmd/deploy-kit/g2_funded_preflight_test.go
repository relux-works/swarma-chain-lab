package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/relux-works/swarma-chain-lab/deploy"
)

// BIP-340 test vectors #0-#3, "public key" column of rows index 0..3 of
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
// (lowercased). The product derives these from the "secret key" column.
var bip340PublishedKeys = [4]string{
	"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
	"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
	"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
}

func scalarKey(k uint32) string {
	var s secp256k1.ModNScalar
	return g2XOnly(s.SetInt(k))
}

// hashKey is x(k*G) for the scalar k = SHA-256(label): a key with no known
// small or published private scalar.
func hashKey(label string) string {
	sum := sha256.Sum256([]byte("g2-funded-preflight test " + label))
	var s secp256k1.ModNScalar
	if s.SetBytes(&sum) != 0 || s.IsZero() {
		panic("hash scalar out of range")
	}
	return g2XOnly(&s)
}

// fundedParams is the rehearsal cliParams with two hash-derived keys and a
// hash-derived canary txid: the valid neighbour of every refusal below.
func fundedParams() deploy.G2PayParameters {
	p := cliParams()
	p.Grantee, p.ReceiptPubkey = hashKey("grantee"), hashKey("receipt")
	sum := sha256.Sum256([]byte("g2-funded-preflight test canary"))
	p.G2.Canary.Outpoint.TxID = hex.EncodeToString(sum[:])
	return p
}

func writeG2Params(t *testing.T, p deploy.G2PayParameters) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "params.json")
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, append(raw, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	return dir, path
}

// runFundedPreflight runs the command on p and also checks it is read-only:
// the parameters directory holds only the parameters file afterwards, and
// nothing is printed on a refusal.
func runFundedPreflight(t *testing.T, p deploy.G2PayParameters) (string, error) {
	t.Helper()
	dir, path := writeG2Params(t, p)
	var out bytes.Buffer
	e := g2FundedPreflight([]string{"-params", path}, &out)
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatal("preflight wrote into the parameters directory", entries)
	}
	if e != nil && out.Len() != 0 {
		t.Fatalf("output on refusal: %q", out.String())
	}
	return out.String(), e
}

func wantFundedRefusal(t *testing.T, name string, e error, want ...string) {
	t.Helper()
	var rs g2FundedRefusals
	if !errors.As(e, &rs) {
		t.Fatalf("%s: not a funded refusal: %v", name, e)
	}
	for i := range want {
		want[i] = "G2_FUNDED_PREFLIGHT_REFUSED " + want[i]
	}
	if got := strings.Split(e.Error(), "\n"); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: refusal lines\n got %q\nwant %q", name, got, want)
	}
}

// Claim: parameters whose two keys are hash-derived (no small or published
// scalar) and whose canary txid has mixed bytes pass with exactly
// G2_FUNDED_PREFLIGHT_OK on stdout and no write.
func TestG2FundedPreflightAcceptsNonTrivial(t *testing.T) {
	out, e := runFundedPreflight(t, fundedParams())
	if e != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
		t.Fatalf("non-trivial parameters refused: %q %v", out, e)
	}
}

// Claim: the rehearsal parameters (deploy g2KeyG/g2Key2G keys, all-0xcc
// canary) are refused with every reason named, and each rehearsal key alone,
// as grantee and as receipt_pubkey, is refused as a small scalar and a fixture
// key while the other member and the canary are valid. The deploy-kit
// dispatch (run) lists the command and returns the same refusal.
func TestG2FundedPreflightRehearsalKeys(t *testing.T) {
	if e := run(nil); e == nil || !strings.Contains(e.Error(), "|g2-funded-preflight|") {
		t.Fatal("usage does not list g2-funded-preflight", e)
	}
	_, e := runFundedPreflight(t, cliParams())
	wantFundedRefusal(t, "rehearsal", e,
		"SMALL_SCALAR_KEY grantee k=1", "FIXTURE_TEST_KEY grantee fixture=deploy-g2KeyG",
		"SMALL_SCALAR_KEY receipt_pubkey k=2", "FIXTURE_TEST_KEY receipt_pubkey fixture=deploy-g2Key2G",
		"DUMMY_CANARY_TXID g2.canary.outpoint.txid byte=cc")
	_, path := writeG2Params(t, cliParams())
	if e2 := run([]string{"g2-funded-preflight", "-params", path}); e2 == nil || e2.Error() != e.Error() {
		t.Fatal("dispatch did not refuse the rehearsal parameters", e2)
	}
	cases := []struct {
		name, field, key string
		want             []string
	}{
		{"grantee-G", "grantee", cliKeyG, []string{"SMALL_SCALAR_KEY grantee k=1", "FIXTURE_TEST_KEY grantee fixture=deploy-g2KeyG"}},
		{"grantee-2G", "grantee", cliKey2G, []string{"SMALL_SCALAR_KEY grantee k=2", "FIXTURE_TEST_KEY grantee fixture=deploy-g2Key2G"}},
		{"receipt-G", "receipt_pubkey", cliKeyG, []string{"SMALL_SCALAR_KEY receipt_pubkey k=1", "FIXTURE_TEST_KEY receipt_pubkey fixture=deploy-g2KeyG"}},
		{"receipt-2G", "receipt_pubkey", cliKey2G, []string{"SMALL_SCALAR_KEY receipt_pubkey k=2", "FIXTURE_TEST_KEY receipt_pubkey fixture=deploy-g2Key2G"}},
	}
	for _, c := range cases {
		p := fundedParams()
		if c.field == "grantee" {
			p.Grantee = c.key
		} else {
			p.ReceiptPubkey = c.key
		}
		_, e := runFundedPreflight(t, p)
		wantFundedRefusal(t, c.name, e, c.want...)
	}
}

// Claim: the product's BIP-340 vector keys #0-#3, derived from the published
// secret keys, equal the published public keys, and each is refused as
// grantee and as receipt_pubkey (#0, secret 3, also as k=3).
func TestG2FundedPreflightBIP340Vectors(t *testing.T) {
	for i, published := range bip340PublishedKeys {
		b, _ := hex.DecodeString(g2BIP340VectorSecrets[i])
		var s secp256k1.ModNScalar
		if s.SetByteSlice(b) || g2XOnly(&s) != published {
			t.Fatalf("vector %d: derived key differs from the published key", i)
		}
		for _, field := range []string{"grantee", "receipt_pubkey"} {
			p := fundedParams()
			if field == "grantee" {
				p.Grantee = published
			} else {
				p.ReceiptPubkey = published
			}
			want := []string{"BIP340_VECTOR_KEY " + field + " vector=" + strconv.Itoa(i)}
			if i == 0 {
				want = append([]string{"SMALL_SCALAR_KEY " + field + " k=3"}, want...)
			}
			_, e := runFundedPreflight(t, p)
			wantFundedRefusal(t, field, e, want...)
		}
	}
}

// Claim: the small-scalar range is exactly 1..1024: x(1024*G) is refused as
// grantee and as receipt_pubkey; x(1025*G) passes (the bound, not a gap);
// x((n-5)*G) is refused as k=5 because an x-only key drops the sign of y.
func TestG2FundedPreflightSmallScalarBound(t *testing.T) {
	p := fundedParams()
	p.Grantee = scalarKey(1024)
	_, e := runFundedPreflight(t, p)
	wantFundedRefusal(t, "grantee-1024", e, "SMALL_SCALAR_KEY grantee k=1024")
	p = fundedParams()
	p.ReceiptPubkey = scalarKey(1024)
	_, e = runFundedPreflight(t, p)
	wantFundedRefusal(t, "receipt-1024", e, "SMALL_SCALAR_KEY receipt_pubkey k=1024")
	p = fundedParams()
	p.Grantee, p.ReceiptPubkey = scalarKey(1025), scalarKey(1026)
	if out, e := runFundedPreflight(t, p); e != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
		t.Fatal("k=1025/1026 refused", out, e)
	}
	var minus5 secp256k1.ModNScalar
	minus5.SetInt(5).Negate()
	p = fundedParams()
	p.ReceiptPubkey = g2XOnly(&minus5)
	_, e = runFundedPreflight(t, p)
	wantFundedRefusal(t, "receipt-minus-5", e, "SMALL_SCALAR_KEY receipt_pubkey k=5")
}

// Claim: a canary txid of 32 equal bytes is refused with its byte named
// (0x11, 0xff through the command; all-zero is already the parser's ErrPolicy
// and the funded check names it too); a txid differing in one byte passes.
func TestG2FundedPreflightCanary(t *testing.T) {
	for _, b := range []string{"11", "ff"} {
		p := fundedParams()
		p.G2.Canary.Outpoint.TxID = strings.Repeat(b, 32)
		_, e := runFundedPreflight(t, p)
		wantFundedRefusal(t, "canary-"+b, e, "DUMMY_CANARY_TXID g2.canary.outpoint.txid byte="+b)
	}
	p := fundedParams()
	p.G2.Canary.Outpoint.TxID = strings.Repeat("00", 32)
	if _, e := runFundedPreflight(t, p); e != deploy.ErrPolicy {
		t.Fatal("all-zero canary not the parser's refusal", e)
	}
	wantFundedRefusal(t, "canary-00-check", g2FundedCheck(p), "DUMMY_CANARY_TXID g2.canary.outpoint.txid byte=00")
	p = fundedParams()
	p.G2.Canary.Outpoint.TxID = strings.Repeat("11", 31) + "12"
	if out, e := runFundedPreflight(t, p); e != nil || out != "G2_FUNDED_PREFLIGHT_OK\n" {
		t.Fatal("mixed-byte canary refused", out, e)
	}
}

// Claim: input the g2-render parser refuses is refused with that parser's
// sentinel and no funded refusal: malformed JSON, an unknown member, a
// PLACEHOLDER, a test network, grantee == receipt_pubkey (rule 5 is the
// parser's), a missing file and an extra argument.
func TestG2FundedPreflightParserRefusals(t *testing.T) {
	good, _ := json.Marshal(fundedParams())
	same := fundedParams()
	same.ReceiptPubkey = same.Grantee
	sameRaw, _ := json.Marshal(same)
	testnet := fundedParams()
	testnet.Network = "test"
	testnetRaw, _ := json.Marshal(testnet)
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"truncated", good[:len(good)-1], deploy.ErrPolicy},
		{"unknown-member", append([]byte(`{"extra":1,`), good[1:]...), deploy.ErrPolicy},
		{"placeholder", bytes.Replace(good, []byte(`"cedar"`), []byte(`"PLACEHOLDER"`), 1), deploy.ErrPlaceholder},
		{"testnet", testnetRaw, deploy.ErrNetwork},
		{"grantee-is-receipt", sameRaw, deploy.ErrPolicy},
	}
	for _, c := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "params.json")
		os.WriteFile(path, c.raw, 0600)
		var out bytes.Buffer
		e := g2FundedPreflight([]string{"-params", path}, &out)
		var rs g2FundedRefusals
		if e != c.want || errors.As(e, &rs) || out.Len() != 0 {
			t.Fatalf("%s: got %v %q, want the parser's %v", c.name, e, out.String(), c.want)
		}
	}
	if e := g2FundedPreflight([]string{"-params", filepath.Join(t.TempDir(), "absent.json")}, &bytes.Buffer{}); e != deploy.ErrPolicy {
		t.Fatal("missing file", e)
	}
	_, path := writeG2Params(t, fundedParams())
	if e := g2FundedPreflight([]string{"-params", path, "extra"}, &bytes.Buffer{}); e != deploy.ErrInput {
		t.Fatal("extra argument", e)
	}
}

// Claim: every listed fixture key is x(k*G) of its documented scalar (G, 2G,
// 7G, 9G), the deploy-kit rehearsal keys are listed, and a fixture key as
// grantee is refused with both its small-scalar and its fixture reason.
func TestG2FundedPreflightFixtureKeys(t *testing.T) {
	scalars := map[string]uint32{"deploy-g2KeyG": 1, "deploy-g2Key2G": 2, "agent-wallet-service-v1-receipt": 7, "agent-wallet-px1ExecutorKey": 9}
	listed := map[string]bool{}
	for _, f := range g2FixtureKeys {
		k, ok := scalars[f.Source]
		if !ok || scalarKey(k) != f.Key {
			t.Fatalf("fixture %s is not x(%d*G)", f.Source, k)
		}
		listed[f.Key] = true
		p := fundedParams()
		p.Grantee = f.Key
		_, e := runFundedPreflight(t, p)
		wantFundedRefusal(t, f.Source, e, "SMALL_SCALAR_KEY grantee k="+strconv.FormatUint(uint64(k), 10), "FIXTURE_TEST_KEY grantee fixture="+f.Source)
	}
	if len(g2FixtureKeys) != len(scalars) || !listed[cliKeyG] || !listed[cliKey2G] {
		t.Fatal("deploy rehearsal keys missing from the fixture list")
	}
}
