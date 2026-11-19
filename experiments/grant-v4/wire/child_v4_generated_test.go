package wire

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func generatedRowsV4() [][]string {
	return [][]string{
		{"f5-contract"}, {"f8-genesis"},
		{"f9-grantkey", "f9-iowner", "f9-recipient-key", "f9-recipient-owner", "f9-pseal", "f9-notary"},
		{"f10-cs1", "f10-cs3-delegation", "f10-cs3-grantkey", "f10-cs3-iowner", "f10-cs3-recipient-key", "f10-cs3-recipient-owner", "f10-cs3-pseal", "f10-cs3-notary"},
		{"f11-octet-seal-even", "f11-octet-seal-odd", "f11-octet-key", "f11-octet-owner-even", "f11-octet-owner-odd", "f11-value-no-key", "f11-contradictory-no-key", "f11-value-refused", "f11-contradictory-refused", "f11-value-unset", "f11-contradictory-unset", "f11-value-unknown", "f11-contradictory-unknown", "f11-input-name", "f11-input-identity", "f11-input-chain", "f11-input-empty", "f11-input-key", "f11-input-duplicate", "f11-input-unexpected", "f11-channel"},
		{"f12-seal"}, {"f13a-zero", "f13a-overcount"}, {"f14-name", "f14-key"},
		{"f15-key", "f15-key-mode", "f15-name", "f15-owner", "f15-parity", "f15-name-mode", "f15-class"},
		{"f16-action"}, {"f17a-missing-0", "f17a-missing-1"}, {"f17b-template", "f17b-child"}, {"f18-upper", "f18-lower"},
	}
}

func generatedInventoryV4(vectors []childVectorV4) error {
	byID := map[string]childVectorV4{}
	for _, vector := range vectors {
		byID[vector.ID] = vector
	}
	check := func(first, second string) error {
		id := "form-pair-" + first + "-before-" + second
		vector, found := byID[id]
		if !found || len(vector.TriggerPair) != 2 || vector.TriggerPair[0] != first || vector.TriggerPair[1] != second || len(vector.Controls) != 2 || vector.Controls[0] != "form-control-"+first || vector.Controls[1] != "form-control-"+second {
			return fmt.Errorf("missing or incomplete trigger pair %s", id)
		}
		return nil
	}
	rows := generatedRowsV4()
	for _, id := range []string{"adopt-f10-cs3-grantkey-before-f11-key", "adopt-f10-cs3-iowner-before-f11-key", "adopt-unknown-with-other-key"} {
		if _, found := byID[id]; !found {
			return fmt.Errorf("missing adopted vector %s", id)
		}
	}
	for earlierIndex, earlier := range rows {
		for _, form := range earlier {
			if _, found := byID["form-control-"+form]; !found {
				return fmt.Errorf("missing form control %s", form)
			}
		}
		for _, later := range rows[earlierIndex+1:] {
			for _, form := range earlier {
				if err := check(form, later[0]); err != nil {
					return err
				}
			}
			for _, form := range later[1:] {
				if err := check(earlier[0], form); err != nil {
					return err
				}
			}
		}
	}
	for _, octet := range rows[4][:5] {
		for _, later := range rows[4][5:] {
			if err := check(octet, later); err != nil {
				return err
			}
		}
	}
	for _, kind := range []string{"notaries", "actions", "channel-member", "channel-key", "channel-duplicate", "limits", "template-keys", "cs3-notaries"} {
		for position := range 3 {
			for _, bad := range []bool{false, true} {
				id := fmt.Sprintf("quant-%s-position-%d-bad-%t", kind, position, bad)
				if _, found := byID[id]; !found {
					return fmt.Errorf("missing quantifier control %s", id)
				}
			}
		}
	}
	for _, id := range []string{"f2-ref-before-depth", "f2-ref-before-notdelegable", "f2-depth-before-notdelegable", "f2-ref-before-f5", "f2-ref-before-f8"} {
		if vector, found := byID[id]; !found || vector.Probe == "" {
			return fmt.Errorf("missing F2 probe %s", id)
		}
	}
	return nil
}

// Every row-form joint and quantifier position is required independently of
// generator metadata; removal controls prove that the inventory fails closed.
func TestChildV4GeneratedInventory(t *testing.T) {
	vectors := childVectorsV4(t)
	if err := generatedInventoryV4(vectors); err != nil {
		t.Fatal(err)
	}
	for index, vector := range vectors {
		if vector.Mode != "generated" && vector.Mode != "f2-order" {
			continue
		}
		t.Run("remove-"+vector.ID, func(t *testing.T) {
			remaining := append([]childVectorV4{}, vectors[:index]...)
			remaining = append(remaining, vectors[index+1:]...)
			if err := generatedInventoryV4(remaining); err == nil || !strings.Contains(err.Error(), vector.ID) && !strings.Contains(err.Error(), strings.TrimPrefix(vector.ID, "form-control-")) {
				t.Fatalf("inventory accepted missing evidence %s: %v", vector.ID, err)
			}
		})
	}
}

// Generated signed inputs drive exact trigger precedence and quantifiers.
// Contradictory states and their octet overlaps run under BOTH policy values.
func TestChildV4Generated(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.Mode != "generated" {
			continue
		}
		policies := []bool{false}
		if vector.BothPolicies {
			policies = append(policies, true)
		}
		for _, policy := range policies {
			t.Run(fmt.Sprintf("%s/policy-%t", vector.ID, policy), func(t *testing.T) {
				parent, child, err := childPairV4(t, vector)
				if err != nil {
					t.Fatal(err)
				}
				beforeParent, beforeChild := parent.Bytes(), child.Bytes()
				result, err := checkChildAttenuationPolicyV4(parent, child, vector.Observation, policy)
				again := vector.Again
				if again == "" {
					again = ChildAgainNo
				}
				childWantV4(t, err, vector.Expect, vector.Step, again)
				if err != nil && result != (ChildAttenuationEvaluation{}) {
					t.Fatal("refusal leaked a partial selection")
				}
				if !bytes.Equal(beforeParent, parent.Bytes()) || !bytes.Equal(beforeChild, child.Bytes()) {
					t.Fatal("evaluation mutated signed inputs")
				}
			})
		}
	}
}

// Q1/Q2 cross verified inputs only after independent VerifyGrant calls.
// The depth > no-delegate joint deliberately breaches the verified boundary;
// nearby single-defect controls are TestChildV4DefensiveF2.
func TestChildV4GeneratedF2(t *testing.T) {
	vectors := childVectorsV4(t)
	byID := map[string]childVectorV4{}
	for _, vector := range vectors {
		byID[vector.ID] = vector
	}
	for _, vector := range vectors {
		if vector.Mode != "f2-order" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			first, exists := byID[vector.Sources[0]]
			if !exists {
				t.Fatal("missing first source")
			}
			parent, child, err := childPairV4(t, first)
			if err != nil {
				t.Fatal(err)
			}
			childWantV4(t, childEvaluationErrorV4(t, parent, child, first.Observation), first.Expect, first.Step)
			switch vector.Probe {
			case "cross-depth", "cross-root":
				second, exists := byID[vector.Sources[1]]
				if !exists {
					t.Fatal("missing second source")
				}
				otherParent, otherChild, err := childPairV4(t, second)
				if err != nil {
					t.Fatal(err)
				}
				childWantV4(t, childEvaluationErrorV4(t, otherParent, otherChild, second.Observation), second.Expect, second.Step)
				if vector.Probe == "cross-depth" {
					parent = child
				}
				child = otherChild
			case "breach-depth":
				root := parent.object.payload.root
				root.members = append(root.members, member{name: "parent", value: &value{kind: 's', text: parent.ID()}})
				for index, entry := range root.members {
					if entry.name == "delegate" {
						root.members = append(root.members[:index], root.members[index+1:]...)
						break
					}
				}
				child.object.payload.root.get("parent").text = parent.ID()
			default:
				t.Fatal("unknown F2 probe")
			}
			childWantV4(t, childEvaluationErrorV4(t, parent, child, nil), vector.Expect, 2)
		})
	}
}
