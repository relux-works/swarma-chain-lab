package rental

import (
	"strings"
	"testing"
)

// Distinct sorted leaf sets of even/odd/single widths verify each member;
// wrong leaf, root, direction, count and path cardinality fail beside valid proofs.
func TestBatchProofs(t *testing.T) {
	for _, count := range []int{1, 2, 3, 5, 8, BatchCapacity} {
		ids := make([]string, count)
		for i := range ids {
			ids[i] = Hash([]byte{byte(i)})
		}
		batch, e := BuildBatch(ids)
		if e != nil {
			t.Fatal(e)
		}
		for i, id := range batch.IDs {
			proof := batch.Proofs[i]
			if !VerifyBatchProof(id, batch.Root, count, proof) {
				t.Fatal("valid membership rejected")
			}
			if VerifyBatchProof(Hash([]byte("foreign")), batch.Root, count, proof) {
				t.Fatal("wrong leaf admitted")
			}
			if VerifyBatchProof(id, strings.Repeat("f", 64), count, proof) {
				t.Fatal("wrong root admitted")
			}
			wrong := proof
			wrong.Count++
			if VerifyBatchProof(id, batch.Root, count, wrong) {
				t.Fatal("wrong count admitted")
			}
			wrong = proof
			wrong.Index = count
			if VerifyBatchProof(id, batch.Root, count, wrong) {
				t.Fatal("out-of-range index admitted")
			}
			wrong = proof
			wrong.Siblings = append(append([]string{}, proof.Siblings...), strings.Repeat("a", 64))
			if VerifyBatchProof(id, batch.Root, count, wrong) {
				t.Fatal("extra sibling admitted")
			}
			if len(proof.Siblings) > 0 {
				wrong = proof
				wrong.Siblings = append([]string{}, proof.Siblings[1:]...)
				if VerifyBatchProof(id, batch.Root, count, wrong) {
					t.Fatal("missing sibling admitted")
				}
			}
			if !VerifyBatchProof(id, batch.Root, count, proof) {
				t.Fatal("positive neighbor changed")
			}
		}
	}
	for _, badIDs := range [][]string{nil, {}, {"bad"}, {strings.Repeat("a", 64), strings.Repeat("a", 64)}, make([]string, BatchCapacity+1)} {
		if _, e := BuildBatch(badIDs); e == nil {
			t.Fatal("invalid batch accepted")
		}
		if _, e := BuildBatch([]string{strings.Repeat("b", 64)}); e != nil {
			t.Fatal(e)
		}
	}
}
