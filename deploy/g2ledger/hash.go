package g2ledger

import (
	"crypto/sha256"
	"hash"
	"os"
	"sort"
)

func newDigest() hash.Hash { return sha256.New() }
func sortEntries(es []os.DirEntry) {
	sort.Slice(es, func(i, j int) bool { return es[i].Name() < es[j].Name() })
}
