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
	Neighbour                  string                      `json:"valid_neighbour"`
	Observation                *ParentNameObservation      `json:"observation"`
	InputIndex                 int                         `json:"input_index"`
	Selected                   *ChildAttenuationEvaluation `json:"selected"`
}

func childVectorsV4(t *testing.T) []childVectorV4 {
	t.Helper()
	b, err := os.ReadFile("testdata/child-v4.json")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Spec    string          `json:"spec_commit"`
		Example string          `json:"j12_example"`
		Scalars []int           `json:"public_test_scalars"`
		Vectors []childVectorV4 `json:"vectors"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatal(err)
	}
	if set.Spec != "464c445fd52ce0ec8bdc52c0ead8a866a7b77f56" || len(set.Scalars) != 3 {
		t.Fatal("wrong fixture pin or public key set")
	}
	if set.Example != "Take a parent with two groups. The first has ranges of three and of two coins,\nthe second one range of four. The parent has nine rows. The ordinals 1 to 3 are\nthe coins of the first range in the order of their output indices, 4 and 5\nthose of the second, and 6 to 9 those of the second group. A child with the\nordinal 5 is checked against the template of the first group and against the\nsecond coin of its second range, and a child with the ordinal 10 refuses as\n`CHILD_ORDINAL` before any row is read." {
		t.Fatal("J12 example is not reproduced exactly")
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
	if strings.HasPrefix(want, "input:") {
		var input *ParentNameObservationError
		var protocol Code
		var failure *ChildAttenuationFailure
		if !errors.As(err, &input) || string(input.Kind) != strings.TrimPrefix(want, "input:") ||
			errors.As(err, &protocol) || errors.As(err, &failure) || errors.Unwrap(err) != nil {
			t.Fatalf("input refusal = %v, want typed %s without protocol code", err, want)
		}
		return
	}
	var f *ChildAttenuationFailure
	if !errors.As(err, &f) || f.Step != step {
		t.Fatalf("refusal = %v, want %s at F%d", err, want, step)
	}
	if f.Code != Code(want) || !errors.Is(err, Code(want)) {
		t.Fatalf("refusal = %v, want exact code %s", err, want)
	}
	if f.Again != ChildAgainNo && f.Again != ChildAgainState && f.Again != ChildAgainInput {
		t.Fatalf("unknown Again mark: %q", f.Again)
	}
	if step != 2 && step != 11 && f.Again != ChildAgainNo {
		t.Fatalf("Again = %q, want no at F%d under the stated profile set", f.Again, step)
	}
}

// These groups prove exact first refusals of the document prefix, including
// equality versus x-coordinate separation, both parities, and precedence.
// Passing the evaluated slice is not admitted authority.
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
			childWantV4(t, childEvaluationErrorV4(t, p, c, v.Observation), v.Expect, v.Step)
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

// F14-F18 preserve private comparisons and also run through public F13 selection.
// Their positive and negative controls prove the slice, not full admission.
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
			// The public path must give the same ordered selected-template outcome.
			childWantV4(t, childEvaluationErrorV4(t, p, c, v.Observation), v.Expect, v.Step)
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
	childWantV4(t, childEvaluationErrorV4(t, baseline, original, nil), "ok", 0)
	childWantV4(t, childEvaluationErrorV4(t, other, original, nil), "WIRE_ID", 2)
	childWantV4(t, childEvaluationErrorV4(t, nil, original, nil), "WIRE_ID", 2)
	childWantV4(t, childEvaluationErrorV4(t, &SignedGrant{}, original, nil), "WIRE_ID", 2)
	{
		result, err := CheckChildAttenuationV4(baseline, nil, nil)
		var input *ChildDocumentInputError
		var protocol Code
		if !errors.As(err, &input) || input.Kind != "missing" || errors.As(err, &protocol) || result != (ChildAttenuationEvaluation{}) {
			t.Fatalf("wrong verified-child input refusal: %v, result %+v", err, result)
		}
	}
	{
		result, err := CheckChildAttenuationV4(baseline, &SignedGrant{}, nil)
		var input *ChildDocumentInputError
		var protocol Code
		if !errors.As(err, &input) || input.Kind != "missing" || errors.As(err, &protocol) || result != (ChildAttenuationEvaluation{}) {
			t.Fatalf("wrong verified-child input refusal: %v, result %+v", err, result)
		}
	}
	{
		result, err := CheckChildAttenuationV4(baseline, baseline, nil)
		var input *ChildDocumentInputError
		var protocol Code
		if !errors.As(err, &input) || input.Kind != "root" || errors.As(err, &protocol) || result != (ChildAttenuationEvaluation{}) {
			t.Fatalf("wrong verified-child input refusal: %v, result %+v", err, result)
		}
	}
}

// F11 separates the delegation key from every supplied channel key. A valid
// nonmember passes F11 and the evaluated slice. Inputs are from the
// caller's observation; these cases do not prove provenance or node health.
func TestChildV4ParentNameObservation(t *testing.T) {
	for _, v := range childVectorsV4(t) {
		if v.Mode != "observation" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			p, c, err := childPairV4(t, v)
			if err != nil {
				t.Fatal("child precondition", err)
			}
			pb, cb := p.Bytes(), c.Bytes()
			before, err := json.Marshal(v.Observation)
			if err != nil {
				t.Fatal(err)
			}
			verdict := childEvaluationErrorV4(t, p, c, v.Observation)
			childWantV4(t, verdict, v.Expect, v.Step)
			var input *ParentNameObservationError
			if strings.HasPrefix(v.Expect, "input:") && (!errors.As(verdict, &input) || input.KeyIndex != v.InputIndex) {
				t.Fatalf("wrong input error index: %v, want %d", input, v.InputIndex)
			}
			after, err := json.Marshal(v.Observation)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pb, p.Bytes()) || !bytes.Equal(cb, c.Bytes()) || !bytes.Equal(before, after) {
				t.Fatal("comparison changed documents or observation")
			}
		})
	}
}

// A refused slice returns no selected-row result, including after selection.
func childEvaluationErrorV4(t *testing.T, parent, child *SignedGrant, observation *ParentNameObservation) error {
	t.Helper()
	result, err := CheckChildAttenuationV4(parent, child, observation)
	if err != nil && result != (ChildAttenuationEvaluation{}) {
		t.Fatalf("refusal leaked a partial row result: %+v", result)
	}
	return err
}

// The generated signed neighbours select every group/range/coin position and
// preserve F12-F18 precedence; selected outpoints assert numeric index order.
func TestChildV4Selection(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.Mode != "selection" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			parent, child, err := childPairV4(t, vector)
			if err != nil {
				t.Fatal("child precondition", err)
			}
			beforeParent, beforeChild := parent.Bytes(), child.Bytes()
			result, err := CheckChildAttenuationV4(parent, child, nil)
			childWantV4(t, err, vector.Expect, vector.Step)
			if err == nil && (vector.Selected == nil || result != *vector.Selected) {
				t.Fatalf("selected row = %+v, want %+v", result, vector.Selected)
			}
			if err != nil && result != (ChildAttenuationEvaluation{}) {
				t.Fatal("refusal leaked a partial row result")
			}
			if !bytes.Equal(beforeParent, parent.Bytes()) || !bytes.Equal(beforeChild, child.Bytes()) {
				t.Fatal("selection changed signed documents")
			}
		})
	}
}

// An invalid ordinal must refuse before a template is read. Removing the
// already-verified private template contents instruments that semantic read
// boundary. A serializable empty object preserves the F2 identifier recheck;
// the private child binding is recomputed, without claiming valid signatures
// for this instrument. This is not a supported caller input or admission test.
func TestChildV4BoundBeforeTemplate(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.Mode != "selection" || (vector.ID != "selection-zero" && vector.ID != "selection-ten") {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			parent, child, err := childPairV4(t, vector)
			if err != nil {
				t.Fatal(err)
			}
			groups := parent.object.payload.root.get("delegate").get("groups").elements
			for _, group := range groups {
				for index := range group.members {
					if group.members[index].name == "template" {
						group.members[index].value = &value{kind: '{'}
					}
				}
			}
			child.object.payload.root.get("parent").text = parent.ID()
			defer func() {
				if recover() != nil {
					t.Error("template read before ordinal bound")
				}
			}()
			childWantV4(t, childEvaluationErrorV4(t, parent, child, nil), "CHILD_ORDINAL", 13)
		})
	}
}

// Both JudgeProposals settings retain the verified-parent precondition. The
// listed-certifier controls reach F13(a) or the child-signature pipeline instead.
func TestChildV4CompositionPrecondition(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.Mode != "composition" {
			continue
		}
		for _, judge := range []bool{false, true} {
			t.Run(vector.ID+"/proposals-"+map[bool]string{false: "off", true: "on"}[judge], func(t *testing.T) {
				parent, err := VerifyGrant(vector.Parent, GrantContext{JudgeProposals: judge})
				if vector.Step == 1 {
					var failure *GrantFailure
					if parent != nil || !errors.As(err, &failure) || failure.Code != GrantDelegate || failure.Step != 9 || failure.Rule != 4 {
						t.Fatalf("parent = %v, failure = %+v; want GRANT_DELEGATE at pipeline step 9 rule 4", parent, failure)
					}
					return
				}
				if err != nil {
					t.Fatal("listed-certifier control", err)
				}
				child, err := VerifyGrant(vector.Child, GrantContext{Parent: parent, JudgeProposals: judge})
				if vector.Expect == "CHILD_SIGNER" {
					var failure *GrantFailure
					if child != nil || !errors.As(err, &failure) || failure.Code != ChildSigner || failure.Step != 7 {
						t.Fatalf("child failure = %+v; want CHILD_SIGNER at pipeline step 7", failure)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				childWantV4(t, childEvaluationErrorV4(t, parent, child, nil), vector.Expect, vector.Step)
			})
		}
	}
}

// F11 distinguishes immutable octet hits from state-dependent channel hits.
// The same valid observation control passes; no cache or node policy is proved.
func TestChildV4Again(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		want, selected := map[string]ChildAgain{"child-seal-before-observation": ChildAgainNo, "delegation-in-set": ChildAgainState}[vector.ID]
		if !selected || vector.Mode != "observation" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			parent, child, err := childPairV4(t, vector)
			if err != nil {
				t.Fatal(err)
			}
			err = childEvaluationErrorV4(t, parent, child, vector.Observation)
			childWantV4(t, err, "DELEGATE_KEY_REUSE", 11)
			var failure *ChildAttenuationFailure
			if !errors.As(err, &failure) || failure.Again != want {
				t.Fatalf("Again = %+v, want %s", failure, want)
			}
		})
	}
}

// A missing/root child is an input error even without a parent; only a real
// child presented without its parent carries WIRE_ID with Again=input.
func TestChildV4InputPrecedence(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.ID != "prefix-open" {
			continue
		}
		parent, child, err := childPairV4(t, vector)
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name  string
			child *SignedGrant
			kind  string
		}{{"missing", nil, "missing"}, {"root", parent, "root"}} {
			t.Run(test.name, func(t *testing.T) {
				result, err := CheckChildAttenuationV4(nil, test.child, nil)
				var input *ChildDocumentInputError
				var protocol Code
				if !errors.As(err, &input) || input.Kind != test.kind || errors.As(err, &protocol) || errors.Unwrap(err) != nil || result != (ChildAttenuationEvaluation{}) {
					t.Fatalf("input precedence: %v, result %+v", err, result)
				}
			})
		}
		t.Run("missing-parent", func(t *testing.T) {
			err := childEvaluationErrorV4(t, nil, child, nil)
			childWantV4(t, err, "WIRE_ID", 2)
			var failure *ChildAttenuationFailure
			if !errors.As(err, &failure) || failure.Again != ChildAgainInput {
				t.Fatalf("missing-parent Again = %+v, want input", failure)
			}
		})
		childWantV4(t, childEvaluationErrorV4(t, parent, child, nil), "ok", 0)
	}
}
