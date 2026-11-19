package wire

import (
	"fmt"
	"strings"
	"testing"
)

// The pair inventory is independent of the generator's metadata: deleting a
// joint or a quantifier position must fail rather than shrink the evidence.
func TestChildV4PairCoverage(t *testing.T) {
	rows := []string{"f5", "f8", "f9", "f10", "f11", "f12", "f13a", "f14", "f15", "f16", "f17a", "f17b", "f18"}
	expected := map[string]bool{}
	for earlierIndex, earlier := range rows {
		for _, later := range rows[earlierIndex+1:] {
			expected["pair-"+earlier+"-before-"+later] = true
		}
	}
	for _, role := range []string{"seal-even", "seal-odd", "key", "owner-even", "owner-odd"} {
		for _, cs := range []string{"cs1", "cs3"} {
			expected["pair-f10-"+cs+"-before-f11-"+role] = true
		}
		expected["pair-f11-"+role+"-before-channel"] = true
	}
	ids := map[string]bool{}
	for _, vector := range childVectorsV4(t) {
		ids[vector.ID] = true
		if len(vector.Pair) != 0 {
			if !expected[vector.ID] || len(vector.Pair) != 2 || len(vector.Controls) != 2 {
				t.Fatalf("unexpected or incomplete pair %s", vector.ID)
			}
			delete(expected, vector.ID)
		}
	}
	if len(expected) != 0 {
		t.Fatalf("missing precedence pairs: %v", expected)
	}
	for position := range 3 {
		for _, amount := range []string{"0", "1"} {
			for _, missing := range []bool{false, true} {
				id := fmt.Sprintf("limit-missing-position-%d-amount-%s-%t", position, amount, missing)
				if !ids[id] {
					t.Fatalf("missing quantifier control %s", id)
				}
			}
		}
	}
}

// Every generated joint holds the two declared triggers; isolated controls
// pin each trigger separately. Masked downstream defects need not be absent.
func TestChildV4Precedence(t *testing.T) {
	vectors := childVectorsV4(t)
	byID := make(map[string]childVectorV4, len(vectors))
	for _, vector := range vectors {
		byID[vector.ID] = vector
	}
	for _, vector := range vectors {
		if vector.Mode != "pair" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			parent, child, err := childPairV4(t, vector)
			if err != nil {
				t.Fatal(err)
			}
			childWantV4(t, childEvaluationErrorV4(t, parent, child, vector.Observation), vector.Expect, vector.Step)
			for _, controlID := range vector.Controls {
				control, exists := byID[controlID]
				if !exists {
					t.Fatalf("missing isolated control %s", controlID)
				}
				controlParent, controlChild, err := childPairV4(t, control)
				if err != nil {
					t.Fatal(err)
				}
				controlAgain := ChildAgainNo
				if controlID == "delegation-in-set" {
					controlAgain = ChildAgainState
				}
				childWantV4(t, childEvaluationErrorV4(t, controlParent, controlChild, control.Observation), control.Expect, control.Step, controlAgain)
			}
		})
	}
}

// Both policy values exercise the evaluator, not a patched expectation:
// only coherent A passes after adoption; B/unset stay closed and contradictory
// caller facts are input errors under both policies, with no partial result.
func TestChildV4ValuePolicies(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if !strings.HasPrefix(vector.ID, "value-") || vector.Mode != "observation" {
			continue
		}
		for _, adopted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/adopted-%t", vector.ID, adopted), func(t *testing.T) {
				parent, child, err := childPairV4(t, vector)
				if err != nil {
					t.Fatal(err)
				}
				beforeParent, beforeChild := string(parent.Bytes()), string(child.Bytes())
				want := vector.Expect
				if adopted && want == "implementation:no-key" {
					want = "ok"
				}
				result, err := checkChildAttenuationPolicyV4(parent, child, vector.Observation, adopted)
				childWantV4(t, err, want, vector.Step)
				if err != nil && result != (ChildAttenuationEvaluation{}) {
					t.Fatal("policy refusal leaked selection")
				}
				if beforeParent != string(parent.Bytes()) || beforeChild != string(child.Bytes()) {
					t.Fatal("policy mutated documents")
				}
			})
		}
	}
}

// These are defensive F2 guards on a deliberately breached verified-input
// boundary. VerifyGrant cannot construct a child of a child or a parent
// without delegate; these tests do not claim such documents verify.
func TestChildV4DefensiveF2(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.ID != "prefix-open" {
			continue
		}
		for _, kind := range []string{"depth", "not-delegable"} {
			t.Run(kind, func(t *testing.T) {
				parent, child, err := childPairV4(t, vector)
				if err != nil {
					t.Fatal(err)
				}
				root := parent.object.payload.root
				want := "NOT_DELEGABLE"
				if kind == "depth" {
					want = "CHAIN_DEPTH"
					root.members = append(root.members, member{name: "parent", value: &value{kind: 's', text: parent.ID()}})
				} else {
					for index, entry := range root.members {
						if entry.name == "delegate" {
							root.members = append(root.members[:index], root.members[index+1:]...)
							break
						}
					}
				}
				child.object.payload.root.get("parent").text = parent.ID()
				childWantV4(t, childEvaluationErrorV4(t, parent, child, nil), want, 2)
			})
		}
	}
}
