package main

// g2-funded-preflight: the read-only guard a FUNDED G2 station runs before any
// install step. Rehearsal parameters legitimately carry public test keys and
// a placeholder canary, so this is a separate command: g2-render,
// g2-host-flow and deploy.ValidateG2PayParameters are unchanged.

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/relux-works/swarma-chain-lab/deploy"
)

// Funded-preflight refusal reasons. Every refusal line on stderr names one.
const (
	g2FundedSmallScalar = "SMALL_SCALAR_KEY"  // x(k*G) for 1 <= k <= g2FundedSmallScalarMax
	g2FundedBIP340      = "BIP340_VECTOR_KEY" // a BIP-340 test-vector public key #0-#3
	g2FundedFixture     = "FIXTURE_TEST_KEY"  // an x-only key of this repository's G2 test fixtures
	g2FundedCanary      = "DUMMY_CANARY_TXID" // a canary txid whose 32 bytes are all one value
)

// g2FundedSmallScalarMax is the largest private scalar k whose key x(k*G) is
// refused. An x-only key does not carry the sign of y, so x(k*G) is also
// x((n-k)*G): both k and n-k are refused.
const g2FundedSmallScalarMax = 1024

// g2BIP340VectorSecrets are the secret keys of BIP-340 test vectors #0-#3,
// the "secret key" column of rows index 0..3 of
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
// The public keys are DERIVED from them (g2FundedKnownKeys), never typed;
// TestG2FundedPreflightBIP340Vectors checks the derivation against that
// file's "public key" column.
var g2BIP340VectorSecrets = [4]string{
	"0000000000000000000000000000000000000000000000000000000000000003",
	"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
	"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
	"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
}

// g2FixtureKeys are the x-only keys that appear as literals in this
// repository's G2 test fixtures (deploy and experiments/agent-wallet tests
// and testdata), with their source. Each one is also a small scalar
// (agent-wallet testKey(n) is the scalar n <= 255);
// TestG2FundedPreflightFixtureKeys checks every listed key against its scalar.
var g2FixtureKeys = []struct{ Key, Source string }{
	{"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "deploy-g2KeyG"},                   // x(G): deploy g2KeyG, deploy-kit cliKeyG
	{"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "deploy-g2Key2G"},                  // x(2G): deploy g2Key2G, deploy-kit cliKey2G, service-v1 grantee
	{"5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc", "agent-wallet-service-v1-receipt"}, // x(7G)
	{"acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe", "agent-wallet-px1ExecutorKey"},     // x(9G): testKey(9)
}

// g2FundedRefusal is one named refusal: reason, refused member, detail.
type g2FundedRefusal struct{ Reason, Field, Detail string }

func (r g2FundedRefusal) Error() string {
	return "G2_FUNDED_PREFLIGHT_REFUSED " + r.Reason + " " + r.Field + " " + r.Detail
}

// g2FundedRefusals is every refusal of one parameters file, one per line.
type g2FundedRefusals []g2FundedRefusal

func (rs g2FundedRefusals) Error() string {
	lines := make([]string, len(rs))
	for i, r := range rs {
		lines[i] = r.Error()
	}
	return strings.Join(lines, "\n")
}

// g2XOnly returns the lowercase-hex x-only public key x(k*G).
func g2XOnly(k *secp256k1.ModNScalar) string {
	var p secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &p)
	p.ToAffine()
	return hex.EncodeToString(p.X.Bytes()[:])
}

type g2KeyMatch struct{ Reason, Detail string }

// g2FundedKnownKeys maps every refused x-only key to its reasons, in the fixed
// order small scalar, BIP-340 vector, fixture.
var g2FundedKnownKeys = sync.OnceValue(func() map[string][]g2KeyMatch {
	known := make(map[string][]g2KeyMatch, g2FundedSmallScalarMax+len(g2BIP340VectorSecrets)+len(g2FixtureKeys))
	var k secp256k1.ModNScalar
	for i := uint32(1); i <= g2FundedSmallScalarMax; i++ {
		x := g2XOnly(k.SetInt(i))
		known[x] = append(known[x], g2KeyMatch{g2FundedSmallScalar, "k=" + strconv.FormatUint(uint64(i), 10)})
	}
	for i, s := range g2BIP340VectorSecrets {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 32 || k.SetByteSlice(b) || k.IsZero() {
			panic("g2-funded-preflight: invalid BIP-340 vector secret " + strconv.Itoa(i))
		}
		x := g2XOnly(&k)
		known[x] = append(known[x], g2KeyMatch{g2FundedBIP340, "vector=" + strconv.Itoa(i)})
	}
	for _, f := range g2FixtureKeys {
		known[f.Key] = append(known[f.Key], g2KeyMatch{g2FundedFixture, "fixture=" + f.Source})
	}
	return known
})

// g2FundedCheck returns every funded-station refusal of parameters that
// deploy.ParseG2PayParameters already accepted (lowercase-hex keys and txid;
// grantee != receipt_pubkey and a non-zero txid are the parser's refusals).
func g2FundedCheck(p deploy.G2PayParameters) g2FundedRefusals {
	var out g2FundedRefusals
	known := g2FundedKnownKeys()
	for _, f := range []struct{ name, key string }{{"grantee", p.Grantee}, {"receipt_pubkey", p.ReceiptPubkey}} {
		for _, m := range known[f.key] {
			out = append(out, g2FundedRefusal{m.Reason, f.name, m.Detail})
		}
	}
	txid := p.G2.Canary.Outpoint.TxID
	if b, e := hex.DecodeString(txid); e != nil || len(b) != 32 {
		out = append(out, g2FundedRefusal{g2FundedCanary, "g2.canary.outpoint.txid", "malformed"})
	} else if bytes.Count(b, b[:1]) == len(b) {
		out = append(out, g2FundedRefusal{g2FundedCanary, "g2.canary.outpoint.txid", fmt.Sprintf("byte=%02x", b[0])})
	}
	return out
}

// g2FundedPreflight is the funded-station guard. It reads the parameters file
// through the g2-render parser (deploy.ParseG2PayParameters) and returns that
// parser's refusal unchanged; it then refuses a grantee or receipt_pubkey that
// is a small-scalar key, a BIP-340 test-vector key or a G2 fixture key, and a
// canary txid of 32 equal bytes, one named line per refusal. Only when nothing
// is refused it prints G2_FUNDED_PREFLIGHT_OK. It is read-only: no network,
// no write, no account database; it judges nothing else.
//
//	deploy-kit g2-funded-preflight -params PARAMS
func g2FundedPreflight(args []string, out io.Writer) error {
	f := flag.NewFlagSet("g2-funded-preflight", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	params := f.String("params", "", "canonical G2PayParameters JSON")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return deploy.ErrInput
	}
	raw, e := readBounded(*params, 1<<16)
	if e != nil {
		return e
	}
	p, e := deploy.ParseG2PayParameters(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return e
	}
	if refused := g2FundedCheck(p); len(refused) != 0 {
		return refused
	}
	_, e = fmt.Fprintln(out, "G2_FUNDED_PREFLIGHT_OK")
	return e
}
