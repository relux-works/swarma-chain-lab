package grantcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	v4wire "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire"
)

// TestV4B4aDifferential compares all 112 literal B4a-exported vector octets with
// the pinned specification input and the landed reader's verdict. B4a re-drafts
// the 11 valid encodings; the 97 rejection and four proposal fixtures are retained
// inputs, not issuer-produced grants. Any disagreement is a finding, never a
// reason to normalize either side. Successful reader objects must preserve bytes.
func TestV4B4aDifferential(t *testing.T) {
	raw, err := os.ReadFile("testdata/b4a-grant-v4.json")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != "227c20bc5017d67b7d87384e7e3559db4b736affeb481e682bd264639b577b28" {
		t.Fatal("B4a export pin", err)
	}
	var corpus map[string]json.RawMessage
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	groups, spec := v4Vectors(t)
	issuer := map[string]v4Vector{}
	for _, group := range []string{"valid", "invalid", "compound", "undetermined"} {
		var rows []v4Vector
		if err := json.Unmarshal(corpus[group], &rows); err != nil || len(rows) != len(groups[group]) {
			t.Fatal("B4a group inventory", group, err)
		}
		for _, row := range rows {
			if _, exists := spec[row.ID]; !exists || issuer[row.ID].ID != "" {
				t.Fatal("B4a id inventory", row.ID)
			}
			issuer[row.ID] = row
		}
	}
	if len(issuer) != 112 {
		t.Fatalf("B4a inventory %d, want 112", len(issuer))
	}
	var read func(v4Vector) (*v4wire.SignedGrant, error)
	read = func(row v4Vector) (*v4wire.SignedGrant, error) {
		ctx := v4wire.GrantContext{Reference: row.Context.Reference}
		if row.Context.Parent != "" {
			var err error
			ctx.Parent, err = read(issuer[row.Context.Parent])
			if err != nil {
				t.Fatal("B4a verified parent control", err)
			}
		}
		return v4wire.VerifyGrant(v4Hex(t, row.SignedFormHex), ctx)
	}
	for _, group := range []string{"valid", "invalid", "compound", "undetermined"} {
		for _, expected := range groups[group] {
			t.Run(expected.ID, func(t *testing.T) {
				row := issuer[expected.ID]
				octets := v4Hex(t, row.SignedFormHex)
				if !bytes.Equal(octets, v4Hex(t, expected.SignedFormHex)) {
					t.Fatal("FINDING: B4a issuer octets differ from reader fixture")
				}
				g, err := read(row)
				want := expected.Expect
				if group == "undetermined" {
					want = "ok"
				}
				if v4Code(err) != want {
					t.Fatalf("FINDING: landed reader verdict %s, want %s", v4Code(err), want)
				}
				if err != nil {
					if g != nil {
						t.Fatal("FINDING: refused issuer input returned authority")
					}
					return
				}
				if !bytes.Equal(g.Bytes(), octets) {
					t.Fatal("FINDING: landed reader changed B4a issuer octets")
				}
				if group == "valid" {
					digest := g.Digest()
					if row.Payload != "" && string(g.Payload()) != row.Payload || g.Signature() != row.Signature || hex.EncodeToString(digest[:]) != row.Digest || g.ID() != row.GrantID || g.ContentAddress() != row.Address || hex.EncodeToString(g.SealScript()) != row.SealScript {
						t.Fatal("FINDING: landed reader derivation differs from B4a")
					}
				}
			})
		}
	}
}
