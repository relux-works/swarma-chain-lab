package rental

import (
	"encoding/hex"
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
			if !VerifyBatchProof(id, batch.Commitment, proof) {
				t.Fatal("valid membership rejected")
			}
			if VerifyBatchProof(Hash([]byte("foreign")), batch.Commitment, proof) {
				t.Fatal("wrong leaf admitted")
			}
			if VerifyBatchProof(id, strings.Repeat("f", 64), proof) {
				t.Fatal("wrong root admitted")
			}
			wrong := proof
			wrong.Count++
			if VerifyBatchProof(id, batch.Commitment, wrong) {
				t.Fatal("wrong count admitted")
			}
			wrong = proof
			wrong.Index = count
			if VerifyBatchProof(id, batch.Commitment, wrong) {
				t.Fatal("out-of-range index admitted")
			}
			wrong = proof
			wrong.Siblings = append(append([]string{}, proof.Siblings...), strings.Repeat("a", 64))
			if VerifyBatchProof(id, batch.Commitment, wrong) {
				t.Fatal("extra sibling admitted")
			}
			if len(proof.Siblings) > 0 {
				wrong = proof
				wrong.Siblings = append([]string{}, proof.Siblings[1:]...)
				if VerifyBatchProof(id, batch.Commitment, wrong) {
					t.Fatal("missing sibling admitted")
				}
			}
			if !VerifyBatchProof(id, batch.Commitment, proof) {
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

// Three leaves and the same leaves with a duplicated tail have an identical
// odd-tail Merkle root, but MUST have different anchored commitments. A forged
// count cannot reuse the original commitment or pass its membership proof.
func TestBatchCardinalityCommitment(t *testing.T) {
	batch, e := BuildBatch([]string{Hash([]byte("a")), Hash([]byte("b")), Hash([]byte("c"))})
	if e != nil {
		t.Fatal(e)
	}
	a, b, c := merkleLeaf(batch.IDs[0]), merkleLeaf(batch.IDs[1]), merkleLeaf(batch.IDs[2])
	duplicatedRoot := merkleNode(merkleNode(a, b), merkleNode(c, c))
	if hex.EncodeToString(duplicatedRoot) != batch.Root {
		t.Fatal("duplicate-tail witness not applied")
	}
	duplicateCommitment := hex.EncodeToString(batchCommitment(duplicatedRoot, 4))
	if duplicateCommitment == batch.Commitment {
		t.Fatal("duplicated tail kept commitment")
	}
	// Independent byte construction pins the domain and uint64 big-endian form.
	exact := append([]byte("swarma-batch-v1"), []byte{0, 0, 0, 0, 0, 0, 0, 3}...)
	exact = append(exact, duplicatedRoot...)
	if Hash(exact) != batch.Commitment {
		t.Fatal("batch domain/count encoding")
	}
	proof := batch.Proofs[0]
	if !VerifyBatchProof(batch.IDs[0], batch.Commitment, proof) {
		t.Fatal("valid neighbor")
	}
	proof.Count = 4
	if VerifyBatchProof(batch.IDs[0], batch.Commitment, proof) {
		t.Fatal("mutated count accepted")
	}
	if _, e := BuildBatch(append(append([]string(nil), batch.IDs...), batch.IDs[2])); e == nil || e.Error() != "BATCH_ID" {
		t.Fatal("duplicate issuer ids accepted")
	}
}
