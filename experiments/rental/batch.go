package rental

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const BatchCapacity = 256

type BatchProof struct {
	Version  int      `json:"version"`
	Index    int      `json:"index"`
	Count    int      `json:"count"`
	Siblings []string `json:"siblings"`
}
type Batch struct {
	Root       string       `json:"root"`
	Commitment string       `json:"commitment"`
	IDs        []string     `json:"ids"`
	Proofs     []BatchProof `json:"proofs"`
}

func merkleLeaf(id string) []byte {
	h := sha256.Sum256(append([]byte{0}, mustDecodeKey(id)...))
	return h[:]
}
func merkleNode(left, right []byte) []byte {
	b := append([]byte{1}, left...)
	b = append(b, right...)
	h := sha256.Sum256(b)
	return h[:]
}

func batchCommitment(root []byte, count int) []byte {
	b := []byte("swarma-batch-v1")
	b = binary.BigEndian.AppendUint64(b, uint64(count))
	b = append(b, root...)
	h := sha256.Sum256(b)
	return h[:]
}

// BuildBatch sorts distinct envelope ids, domain-separates leaf/internal hashes
// and duplicates the odd last node. Anchors are optional audit data, never a
// substitute for signature/name/seal checks or a proof of issuance time.
func BuildBatch(ids []string) (Batch, error) {
	var batch Batch
	if len(ids) < 1 || len(ids) > BatchCapacity {
		return batch, bad("BATCH_BOUND")
	}
	batch.IDs = append([]string(nil), ids...)
	slices.Sort(batch.IDs)
	var level [][]byte
	for i, id := range batch.IDs {
		if !digest(id) || (i > 0 && id == batch.IDs[i-1]) {
			return Batch{}, bad("BATCH_ID")
		}
		level = append(level, merkleLeaf(id))
		batch.Proofs = append(batch.Proofs, BatchProof{Version: 1, Index: i, Count: len(ids), Siblings: []string{}})
	}
	positions := make([]int, len(ids))
	for i := range positions {
		positions[i] = i
	}
	for len(level) > 1 {
		for i, index := range positions {
			sibling := index ^ 1
			if sibling >= len(level) {
				sibling = index
			}
			batch.Proofs[i].Siblings = append(batch.Proofs[i].Siblings, hex.EncodeToString(level[sibling]))
			positions[i] /= 2
		}
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			right := i + 1
			if right == len(level) {
				right = i
			}
			next = append(next, merkleNode(level[i], level[right]))
		}
		level = next
	}
	batch.Root = hex.EncodeToString(level[0])
	batch.Commitment = hex.EncodeToString(batchCommitment(level[0], len(ids)))
	return batch, nil
}

// VerifyBatchProof binds membership, proof shape and cardinality to the actual
// anchored commitment. Count is encoded as uint64 big-endian under the fixed
// swarma-batch-v1 domain, eliminating duplicate-odd-tail cardinality ambiguity.
func VerifyBatchProof(id, commitment string, p BatchProof) bool {
	if !digest(id) || !digest(commitment) || p.Count < 1 || p.Count > BatchCapacity || p.Version != 1 || p.Index < 0 || p.Index >= p.Count || p.Siblings == nil {
		return false
	}
	hash := merkleLeaf(id)
	index, width := p.Index, p.Count
	used := 0
	for width > 1 {
		if used >= len(p.Siblings) || !digest(p.Siblings[used]) {
			return false
		}
		sibling := mustDecodeKey(p.Siblings[used])
		used++
		if index^1 >= width && hex.EncodeToString(sibling) != hex.EncodeToString(hash) {
			return false
		}
		if index%2 == 0 {
			hash = merkleNode(hash, sibling)
		} else {
			hash = merkleNode(sibling, hash)
		}
		index /= 2
		width = (width + 1) / 2
	}
	return used == len(p.Siblings) && hex.EncodeToString(batchCommitment(hash, p.Count)) == commitment
}

type BatchAnchorPlan struct {
	Plan  Plan  `json:"plan"`
	Batch Batch `json:"batch"`
}

// MakeBatchAnchorPlan is disabled unless explicitly requested. It is offline,
// unsigned and does not reserve/spend any seal or assert node state. Funding
// inputs require independent live ownership and reservation review before use.
func MakeBatchAnchorPlan(p Policy, s PlanSpec, ids []string, enabled bool) (BatchAnchorPlan, error) {
	var result BatchAnchorPlan
	if !enabled {
		return result, bad("BATCH_DISABLED")
	}
	if e := p.validateDetached(); e != nil {
		return result, e
	}
	if s.Kind != "batch-anchor" || s.ChangeScript != p.SealScript || len(s.Inputs) < 1 || len(s.Inputs) > 16 {
		return result, bad("BATCH_TEMPLATE")
	}
	batch, e := BuildBatch(ids)
	if e != nil {
		return result, e
	}
	tx := su.Transaction{Version: 2}
	var total int64
	seen := map[su.Point]bool{}
	for _, in := range s.Inputs {
		if in.Role != "funding" || in.Script != p.SealScript || !digest(in.Point.TxID) || seen[in.Point] || in.ValueSat < 1 || in.ValueSat > MaxMoney-total {
			return result, bad("BATCH_FUNDING")
		}
		seen[in.Point] = true
		total += in.ValueSat
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Script: make([]byte, 140), Sequence: 0xfffffffe})
	}
	rootScript := append([]byte{0x6a, 32}, mustDecodeKey(batch.Commitment)...)
	tx.Outputs = []su.Output{{Value: 0, Script: rootScript}, {Value: 0, Script: mustDecodeKey(p.SealScript)}}
	size, fee, change, e := su.ReserveLegacyFee(tx, total)
	if e != nil {
		return result, e
	}
	plan := Plan{Version: 2, Network: p.Network, Genesis: p.Genesis, Kind: "batch-anchor", Offline: true, TransactionVersion: 2, Inputs: s.Inputs, Outputs: []su.PlanOutput{{ValueSat: 0, Script: hex.EncodeToString(rootScript), Role: "batch-commitment"}, {ValueSat: change, Script: p.SealScript, Role: "change"}}, FeeRate: 200, FeeSat: fee, MaxSignedVBytes: size, RequiredReview: "Offline unsigned audit plan; independently verify prevouts, pool reservations, ownership and signing policy before use. No issuance or broadcast authority."}
	return BatchAnchorPlan{plan, batch}, nil
}
