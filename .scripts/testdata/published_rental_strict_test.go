package main

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

const (
	publishedKey  = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
	publishedHash = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89"
	publishedSig  = "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a"
	curveOrder    = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	parserEntry   = "NONCANONICAL_REACHED_LIB_PARSER"
)

// Claim: official BIP-340 vector 1 passes the public certificate verifier with
// s > n/2; this protects against accidentally imposing an ECDSA low-S rule.
func TestPublishedRentalValidHighS(t *testing.T) {
	s, _ := new(big.Int).SetString(publishedSig[64:], 16)
	n, _ := new(big.Int).SetString(curveOrder, 16)
	if s.Cmp(new(big.Int).Rsh(n, 1)) <= 0 || s.Cmp(n) >= 0 {
		t.Fatal("invalid high-s control")
	}
	if !rental.VerifySignature(publishedKey, publishedHash, publishedSig) {
		t.Fatal("valid high-s control refused")
	}
}

// Claim: the bounded vendored-library sentinel is active for this exact s=n
// input. Application source is unchanged; this alone makes no validity claim.
func TestPublishedParserSentinelControl(t *testing.T) {
	defer func() {
		if got := recover(); got != parserEntry {
			t.Fatalf("parser sentinel not active: %v", got)
		}
	}()
	raw, err := hex.DecodeString(publishedSig[:64] + curveOrder)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = schnorr.ParseSignature(raw)
}

// Claim: s=n is refused before the library parser through the public rental
// certificate path. Both old/new uninstrumented implementations may reject it
// mathematically; only parser-entry instrumentation distinguishes the bypass.
func TestPublishedRentalRejectsBeforeLibraryParse(t *testing.T) {
	defer func() {
		if got := recover(); got != nil {
			if got == parserEntry {
				t.Fatal("PUBLISHED_RENTAL_STRICT_GATE_MISSING: " + parserEntry)
			}
			panic(got)
		}
	}()
	if rental.VerifySignature(publishedKey, publishedHash, strings.ToLower(publishedSig[:64]+curveOrder)) {
		t.Fatal("noncanonical signature admitted")
	}
}
