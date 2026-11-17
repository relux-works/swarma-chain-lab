package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type childVectorV4 struct {
	ID, Mode, Expect, SpecCase string
	Step                       int
	Parent, Child, Ancestor    json.RawMessage
	Neighbour                  string `json:"valid_neighbour"`
}

func childVectorsV4(t *testing.T) []childVectorV4 {
	t.Helper()
	b, err := os.ReadFile("testdata/child-v4.json")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Spec    string          `json:"spec_commit"`
		Scalars []int           `json:"public_test_scalars"`
		Vectors []childVectorV4 `json:"vectors"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatal(err)
	}
	if set.Spec != "1e58a9f91eba35ff19de25388031f0264c01eecc" || len(set.Scalars) != 3 {
		t.Fatal("wrong fixture pin or public key set")
	}
	ids := map[string]bool{}
	for _, v := range set.Vectors {
		if ids[v.ID] {
			t.Fatal("duplicate vector", v.ID)
		}
		ids[v.ID] = true
	}
	for _, v := range set.Vectors {
		if !ids[v.Neighbour] {
			t.Fatal("missing neighbour", v.ID)
		}
	}
	return set.Vectors
}

func childPairV4(t *testing.T, v childVectorV4) (*SignedGrant, *SignedGrant, error) {
	t.Helper()
	var ctx GrantContext
	if v.Ancestor != nil {
		g, err := VerifyGrant(v.Ancestor, GrantContext{})
		if err != nil {
			t.Fatal("ancestor precondition", err)
		}
		ctx.Parent = g
	}
	p, err := VerifyGrant(v.Parent, ctx)
	if err != nil {
		t.Fatal("parent precondition", err)
	}
	c, err := VerifyGrant(v.Child, GrantContext{Parent: p})
	return p, c, err
}

func childWantV4(t *testing.T, err error, want string, step int) {
	t.Helper()
	if want == "ok" {
		if err != nil {
			t.Fatalf("comparison refused valid neighbour: %v", err)
		}
		return
	}
	var f *ChildAttenuationFailure
	if !errors.As(err, &f) || f.Step != step {
		t.Fatalf("refusal = %v, want %s at F%d", err, want, step)
	}
	if want == "OPEN" {
		if f.Code != "" || f.Open == "" || f.Unwrap() != nil || !strings.HasPrefix(f.Error(), "OPEN F") {
			t.Fatalf("OPEN must refuse without inventing a protocol code: %+v", f)
		}
	} else if f.Open != "" || f.Code != Code(want) || !errors.Is(err, Code(want)) {
		t.Fatalf("refusal = %v, want exact code %s", err, want)
	}
}

// These groups prove exact first refusals of the document prefix, including
// equality versus x-coordinate separation, both parities, and precedence.
// A valid prefix stops OPEN at F13; it is never described as admitted authority.
func runChildPrefixV4(t *testing.T, keep func(string) bool) {
	for _, v := range childVectorsV4(t) {
		if v.Mode != "prefix" || !keep(v.ID) {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			p, c, err := childPairV4(t, v)
			if err != nil {
				t.Fatal("child precondition", err)
			}
			pb, cb := p.Bytes(), c.Bytes()
			childWantV4(t, CheckChildAttenuationV4(p, c), v.Expect, v.Step)
			if !bytes.Equal(pb, p.Bytes()) || !bytes.Equal(cb, c.Bytes()) {
				t.Fatal("comparison changed signed documents")
			}
		})
	}
}
func TestChildV4Prefix(t *testing.T) {
	runChildPrefixV4(t, func(id string) bool {
		return !strings.Contains(id, "reuse") && !strings.Contains(id, "delegation-") && !strings.Contains(id, "childseal-") && !strings.HasPrefix(id, "ordinal-")
	})
}
func TestChildV4RoleKeys(t *testing.T) {
	runChildPrefixV4(t, func(id string) bool {
		return strings.Contains(id, "reuse") || strings.Contains(id, "delegation-") || strings.Contains(id, "childseal-") || id == "prefix-open"
	})
}
func TestChildV4Ordinal(t *testing.T) {
	runChildPrefixV4(t, func(id string) bool { return strings.HasPrefix(id, "ordinal-") || id == "prefix-open" })
}

// F14-F18 are tested against the first signed template directly, never through
// a fabricated solution of F13. These positive/negative controls prove only the
// individual template comparisons; even their valid pairs publicly refuse OPEN.
func TestChildV4Template(t *testing.T) {
	for _, v := range childVectorsV4(t) {
		if v.Mode != "template" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			p, c, err := childPairV4(t, v)
			if err != nil {
				t.Fatal("child precondition", err)
			}
			pb, cb := p.Bytes(), c.Bytes()
			template := p.object.payload.root.get("delegate").get("groups").elements[0].get("template")
			childWantV4(t, checkChildTemplateV4(p.object.payload.root, c.object.payload.root, template), v.Expect, v.Step)
			// A successful private comparison must never bypass unresolved F13.
			childWantV4(t, CheckChildAttenuationV4(p, c), "OPEN", 13)
			if !bytes.Equal(pb, p.Bytes()) || !bytes.Equal(cb, c.Bytes()) {
				t.Fatal("template comparison changed signed documents")
			}
		})
	}
}

// The verified parent is the depth context in W11.8: two links read, a third
// link refuses in the reader. It cannot become an already verified input to
// the evaluator. Cross-parent substitution also refuses before comparisons.
func TestChildV4Documents(t *testing.T) {
	var baseline *SignedGrant
	var original *SignedGrant
	var other *SignedGrant
	for _, v := range childVectorsV4(t) {
		if v.Mode == "reader" {
			t.Run(v.ID, func(t *testing.T) {
				_, c, err := childPairV4(t, v)
				if c != nil || !errors.Is(err, Code(v.Expect)) {
					t.Fatalf("reader = %v, want %s with no object", err, v.Expect)
				}
			})
		}
		if v.ID == "prefix-open" {
			var err error
			baseline, original, err = childPairV4(t, v)
			if err != nil {
				t.Fatal(err)
			}
		}
		if v.ID == "missing-childseal" {
			var err error
			other, _, err = childPairV4(t, v)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	childWantV4(t, CheckChildAttenuationV4(baseline, original), "OPEN", 13)
	childWantV4(t, CheckChildAttenuationV4(other, original), "WIRE_ID", 2)
	childWantV4(t, CheckChildAttenuationV4(nil, original), "WIRE_ID", 2)
	childWantV4(t, CheckChildAttenuationV4(&SignedGrant{}, original), "WIRE_ID", 2)
	childWantV4(t, CheckChildAttenuationV4(baseline, nil), "OPEN", 2)
	childWantV4(t, CheckChildAttenuationV4(baseline, &SignedGrant{}), "OPEN", 2)
	childWantV4(t, CheckChildAttenuationV4(baseline, baseline), "OPEN", 2)
}
