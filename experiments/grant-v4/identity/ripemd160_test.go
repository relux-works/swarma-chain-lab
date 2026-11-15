package identity

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ripemd160"
)

// TestRIPEMD160PublishedVectors checks the pinned pure Go digest against all nine original published vectors.
func TestRIPEMD160PublishedVectors(t *testing.T) {
	// Source: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
	data, err := os.ReadFile("testdata/ripemd160-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			ID, Message, Digest string
			Repeat              int
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 9 {
		t.Fatalf("want nine published vectors, got %d", len(fixture.Vectors))
	}
	for _, v := range fixture.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			h := ripemd160.New()
			h.Write([]byte(strings.Repeat(v.Message, v.Repeat)))
			if got := hex.EncodeToString(h.Sum(nil)); got != v.Digest {
				t.Fatalf("published RIPEMD-160 vector: got %s; want %s", got, v.Digest)
			}
		})
	}
}

// TestBIP340IdentityKnownAnswer checks HASH160 and P2PKH bytes for the published BIP-340 vector index 0 key.
func TestBIP340IdentityKnownAnswer(t *testing.T) {
	// Public x: bitcoin/bips, bip-0340/test-vectors.csv, index 0; compressed with prefix 02.
	// Source: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
	p := pin(t, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
	digest := p.Hash160()
	if got := hex.EncodeToString(digest[:]); got != "7dd65592d0ab2fe0d0257d571abf032cd9db93dc" {
		t.Fatalf("HASH160: got %s", got)
	}
	script := append([]byte{0x76, 0xa9, 0x14}, digest[:]...)
	script = append(script, 0x88, 0xac)
	if got := hex.EncodeToString(script); got != "76a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac" {
		t.Fatalf("P2PKH: got %s", got)
	}
	if readAddress(script, p, Height{}, Chain{}) != Controlled {
		t.Fatal("known-answer P2PKH was not controlled by the published test pin")
	}
}
