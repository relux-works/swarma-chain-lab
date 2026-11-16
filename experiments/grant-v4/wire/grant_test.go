package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func grantVectors(t *testing.T) (map[string][]vector, map[string]vector) {
	t.Helper()
	raw, err := os.ReadFile("testdata/grant-v4.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != "66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106" {
		t.Fatal("pinned grant vectors changed")
	}
	var root map[string]json.RawMessage
	decode(t, raw, &root)
	groups, byID := map[string][]vector{}, map[string]vector{}
	for _, name := range []string{"valid", "invalid", "compound", "undetermined"} {
		var rows []vector
		decode(t, root[name], &rows)
		groups[name] = rows
		for _, v := range groups[name] {
			if byID[v.str("id")] != nil {
				t.Fatal("duplicate vector id")
			}
			byID[v.str("id")] = v
		}
	}
	return groups, byID
}

func readGrantVector(t *testing.T, v vector, byID map[string]vector, proposals bool) (*SignedGrant, error) {
	t.Helper()
	var c struct {
		Parent    string  `json:"parent"`
		Reference *string `json:"reference"`
	}
	if v["context"] != nil {
		decode(t, v["context"], &c)
	}
	ctx := GrantContext{Reference: c.Reference, JudgeProposals: proposals}
	if c.Parent != "" {
		var err error
		ctx.Parent, err = readGrantVector(t, byID[c.Parent], byID, proposals)
		if err != nil {
			t.Fatal("parent control", err)
		}
	}
	return VerifyGrant(v.octets(t, "signed_form_hex"), ctx)
}

func grantVectorStep(id, code string) int {
	switch code {
	case "WIRE_SIZE", "WIRE_JSON", "WIRE_DUPLICATE", "WIRE_VALUE", "WIRE_NUMBER", "WIRE_STRING", "WIRE_NOT_CANONICAL":
		return 1
	case "WIRE_TYPE":
		return 3
	case "WIRE_MEMBER":
		if id == "grant-i-03" {
			return 2
		}
		return 4
	case "WIRE_INTEGER", "WIRE_KEY":
		return 4
	case "WIRE_SIGNATURE_FORM":
		return 5
	case "CHAIN_DEPTH", "NOT_DELEGABLE":
		return 6
	case "WIRE_SIGNATURE", "CHILD_SIGNER":
		return 7
	case "WIRE_ID":
		if id == "grant-i-48" {
			return 8
		}
		return 6
	case "GRANT_SHAPE", "GRANT_DELEGATE":
		return 9
	default:
		return 0
	}
}

// TestGrantVectors proves all 112 pinned outcomes, exact valid bytes/hashes, and refusal step precedence through VerifyGrant.
func TestGrantVectors(t *testing.T) {
	groups, byID := grantVectors(t)
	counts := map[string]int{}
	var table bytes.Buffer
	for _, group := range []string{"valid", "invalid", "compound", "undetermined"} {
		for _, v := range groups[group] {
			counts[group]++
			id := v.str("id")
			t.Run(id, func(t *testing.T) {
				// Each negative is executed beside a valid control, including
				// compound vectors and the memberless legacy stand-in.
				control := v.str("valid_neighbour")
				if group != "valid" {
					if control == "" {
						control = "grant-v-01"
					}
					if _, err := readGrantVector(t, byID[control], byID, true); err != nil {
						t.Fatal("positive control", err)
					}
				}
				outcomes := make([]string, 0, 2)
				for _, proposals := range []bool{false, true} {
					g, err := readGrantVector(t, v, byID, proposals)
					want := v.str("expect")
					if group == "undetermined" {
						want = "ok"
						if proposals {
							want = "GRANT_DELEGATE"
						}
					}
					wantCode(t, err, want)
					outcomes = append(outcomes, want)
					if err != nil {
						if g != nil {
							t.Fatal("refusal returned a grant")
						}
						var failure *GrantFailure
						if !errors.As(err, &failure) || failure.Step != grantVectorStep(id, want) {
							t.Fatalf("precedence: %#v, want step %d", failure, grantVectorStep(id, want))
						}
					} else if group == "valid" {
						equalBytes(t, g.Bytes(), v.octets(t, "signed_form_hex"))
						if v.str("payload") != "" {
							equalBytes(t, g.Payload(), []byte(v.str("payload")))
						}
						equalHex(t, g.Digest(), v.str("typed_digest"))
						if g.ID() != v.str("grant_id") || g.ContentAddress() != v.str("content_address") || g.Signature() != v.str("signature") || hex.EncodeToString(g.SealScript()) != v.str("seal_script") {
							t.Fatal("derived value differs from pin")
						}
					}
				}
				fmt.Fprintf(&table, "%s\t%s\t%s\n", id, outcomes[0], outcomes[1])
			})
		}
	}
	for group, count := range map[string]int{"valid": 11, "invalid": 84, "compound": 13, "undetermined": 4} {
		if counts[group] != count {
			t.Fatalf("%s: got %d, want %d", group, counts[group], count)
		}
	}
	if len(byID) != 112 {
		t.Fatalf("count = %d, want 112", len(byID))
	}
	// The optional destination is test evidence only, never verifier input.
	if path := os.Getenv("GRANT_VERDICT_TABLE"); path != "" {
		if bytes.Count(table.Bytes(), []byte{'\n'}) != 112 {
			t.Fatal("verdict table requires all 112 executed vectors")
		}
		if err := os.WriteFile(path, table.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestGrantClockMember proves an otherwise-valid height grant refuses an unlisted clock member before signature verification.
func TestGrantClockMember(t *testing.T) {
	_, byID := grantVectors(t)
	v := byID["grant-v-01"]
	if _, err := readGrantVector(t, v, byID, false); err != nil {
		t.Fatal(err)
	}
	b := v.octets(t, "signed_form_hex")
	b = bytes.Replace(b, []byte(`"contract":`), []byte(`"clock":1,"contract":`), 1)
	_, err := VerifyGrant(b, GrantContext{})
	wantCode(t, err, string(WireMember))
}

// TestGrantImmutable proves result bytes and input bytes cannot mutate a previously verified parent or its hashes.
func TestGrantImmutable(t *testing.T) {
	_, byID := grantVectors(t)
	b := byID["grant-v-03"].octets(t, "signed_form_hex")
	g, err := VerifyGrant(b, GrantContext{})
	if err != nil {
		t.Fatal(err)
	}
	id, digest := g.ID(), g.Digest()
	for _, data := range [][]byte{b, g.Bytes(), g.Payload(), g.SealScript()} {
		for i := range data {
			data[i] = 0
		}
	}
	if g.ID() != id || g.Digest() != digest || strings.ContainsRune(string(g.Bytes()), 0) {
		t.Fatal("verified grant was mutable")
	}
	if _, err := VerifyGrant(g.Bytes(), GrantContext{}); err != nil {
		t.Fatal("unchanged positive control", err)
	}
}
