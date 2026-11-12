package wallet

// Owner S2, freeze amendment 1 (A5/A6) migration: the integration gate for
// reconcile authorization through the PUBLIC OpenJournalV2 with a keyed
// JournalHeaderV2. The frozen contract names three sites that each call
// VerifyReconcileV2: Append (after assigning Seq, before the record is
// durable), open/replay, and FoldLedgerV2 (under j.Header().ReceiptKey).
// Every refusal below has a valid neighbour at the same site. The signing
// preimage is assembled independently in px1jSignAt (px1_journal_test.go).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const px1jFA1Now = int64(1794441599)

// px1jFA1Set is one journal image: its header and every record with its Seq.
// The last record is the release under test; every earlier record is valid
// under h.
type px1jFA1Set struct {
	h    JournalHeaderV2
	recs []JournalRecordV2
}

func (s px1jFA1Set) last() JournalRecordV2 { return s.recs[len(s.recs)-1] }

// px1jFA1Prefix is reserve(grant, nonce) at Seq 1 and its uncertain outcome
// at Seq 2: a 50000-atom debit retained until a verified release.
func px1jFA1Prefix(grant, nonce int) []JournalRecordV2 {
	r := px1jReserve(grant, nonce, px1jFA1Now, 50000, 1)
	r.Seq = 1
	u := px1jFollowRec(r, RecordUncertain, "uncertain", px1jFA1Now)
	u.Seq = 2
	return []JournalRecordV2{r, u}
}

// px1jFA1Release is the unsigned "absent" release of released atoms of the
// reserve record r, appended at time at.
func px1jFA1Release(r JournalRecordV2, released, at int64) JournalRecordV2 {
	return px1jRelease(r, &ReconcileRecordV2{TargetSeq: r.Seq, Evidence: "absent", Height: 100, BlockHash: px1jHex(9), ReleasedSat: released, NoteSHA256: px1jHex(5)}, at)
}

// px1jFA1SignV1 signs rec's payload with testKey(n) over the superseded
// freeze preimage SHA256("swarma-wallet-reconcile-v1" || canonical(payload
// with signature "")), which binds neither the journal nor the position.
func px1jFA1SignV1(t *testing.T, rec JournalRecordV2, n int) JournalRecordV2 {
	t.Helper()
	c := *rec.Reconcile
	c.Signature = ""
	digest := sha256.Sum256(append([]byte("swarma-wallet-reconcile-v1"), canonical(c)...))
	key, _ := testKey(byte(n))
	sig, e := schnorr.Sign(key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	c.Signature = hex.EncodeToString(sig.Serialize())
	rec.Reconcile = &c
	return rec
}

// px1jWithSignature returns rec carrying the signature of from: the bytes of
// one authorization lifted onto another record.
func px1jWithSignature(rec, from JournalRecordV2) JournalRecordV2 {
	c := *rec.Reconcile
	c.Signature = from.Reconcile.Signature
	rec.Reconcile = &c
	return rec
}

func px1jConcat(a []JournalRecordV2, b ...JournalRecordV2) []JournalRecordV2 {
	return append(append([]JournalRecordV2{}, a...), b...)
}

// px1jWriteSegment stores recs as the single segment of a fresh private
// journal directory, byte-for-byte as the engine would write it.
func px1jWriteSegment(t *testing.T, s px1jFA1Set) string {
	t.Helper()
	d := px1jPrivateDir(t)
	seg := JournalSegmentV2{Header: s.h, Index: 1, PrevSHA256: px1jZeroHash, FirstSeq: 1, Records: s.recs}
	if e := os.WriteFile(filepath.Join(d, px1jSegmentName(1)), canonical(seg), 0600); e != nil {
		t.Fatal(e)
	}
	return d
}

// px1jFA1Case is one refusal and its valid neighbour. before is the debit
// retained before the release under test, after the debit retained once the
// neighbour's release applies.
type px1jFA1Case struct {
	name           string
	refused, valid px1jFA1Set
	before, after  int64
}

func px1jFA1Cases(t *testing.T) []px1jFA1Case {
	h := px1jWalletHeader(px1jReceiptKeyN)
	prefix := px1jFA1Prefix(1, 1)
	rel := px1jFA1Release(prefix[0], 50000, px1jFA1Now)
	signed := px1jSignAt(t, h, rel, 3, px1jReceiptKeyN) // the A6 authorization for (h, grant 1, nonce 1, Seq 3)
	other := h
	other.Binding = px1jHex(8) // another journal under the same receipt key (T12)
	grant2, nonce2 := px1jFA1Prefix(2, 1), px1jFA1Prefix(1, 2)
	rel2, relN := px1jFA1Release(grant2[0], 50000, px1jFA1Now), px1jFA1Release(nonce2[0], 50000, px1jFA1Now)
	rel2.Seq, relN.Seq = 3, 3
	track := px1jFollowRec(prefix[0], RecordTrack, TrackConflicted, px1jFA1Now)
	track.Seq = 3
	track.Track = &TrackRecordV2{State: TrackConflicted, Height: 100, BlockHash: px1jHex(9), ConflictTxID: px1jHex(6)}
	late := rel
	late.Seq = 4
	partial := px1jSignAt(t, h, px1jFA1Release(prefix[0], 20000, px1jFA1Now), 3, px1jReceiptKeyN)
	again := partial
	again.Seq, again.LastTime = 4, px1jFA1Now+ReconcileMinIntervalSeconds
	return []px1jFA1Case{
		{"v1 preimage", px1jFA1Set{h, px1jConcat(prefix, px1jFA1SignV1(t, signed, px1jReceiptKeyN))}, px1jFA1Set{h, px1jConcat(prefix, signed)}, 50000, 0},
		{"stranger key", px1jFA1Set{h, px1jConcat(prefix, px1jSignAt(t, h, rel, 3, 8))}, px1jFA1Set{h, px1jConcat(prefix, signed)}, 50000, 0},
		{"empty receipt key", px1jFA1Set{px1jWalletHeader(0), px1jConcat(prefix, signed)}, px1jFA1Set{h, px1jConcat(prefix, signed)}, 50000, 0},
		{"cross-journal", px1jFA1Set{other, px1jConcat(prefix, signed)}, px1jFA1Set{other, px1jConcat(prefix, px1jSignAt(t, other, rel, 3, px1jReceiptKeyN))}, 50000, 0},
		{"cross-grant", px1jFA1Set{h, px1jConcat(grant2, px1jWithSignature(rel2, signed))}, px1jFA1Set{h, px1jConcat(grant2, px1jSignAt(t, h, rel2, 3, px1jReceiptKeyN))}, 50000, 0},
		{"cross-nonce", px1jFA1Set{h, px1jConcat(nonce2, px1jWithSignature(relN, signed))}, px1jFA1Set{h, px1jConcat(nonce2, px1jSignAt(t, h, relN, 3, px1jReceiptKeyN))}, 50000, 0},
		{"cross-seq", px1jFA1Set{h, px1jConcat(prefix, track, px1jWithSignature(late, signed))}, px1jFA1Set{h, px1jConcat(prefix, track, px1jSignAt(t, h, late, 4, px1jReceiptKeyN))}, 50000, 0},
		{"replay of an applied release", px1jFA1Set{h, px1jConcat(prefix, partial, again)}, px1jFA1Set{h, px1jConcat(prefix, partial, px1jSignAt(t, h, again, 4, px1jReceiptKeyN))}, 30000, 10000},
	}
}

// px1jFA1Append opens a fresh journal under s.h through OpenJournalV2,
// appends every record but the last (each must keep its Seq) and returns
// the journal, its directory and the error of appending the last record.
func px1jFA1Append(t *testing.T, s px1jFA1Set) (JournalV2, string, error) {
	t.Helper()
	dir := px1jPrivateDir(t)
	j, e := OpenJournalV2(dir, "journal-v2.lock", s.h, JournalLimitsV2{SpendCapacity: 4})
	if e != nil {
		t.Fatal("open", e)
	}
	t.Cleanup(j.Close)
	for _, r := range s.recs[:len(s.recs)-1] {
		if out := px1jMust(t, j, r); out.Seq != r.Seq {
			t.Fatal("fixture seq", r.Seq, out.Seq)
		}
	}
	_, e = j.Append(s.last())
	return j, dir, e
}

func px1jFA1Spend(t *testing.T, l LedgerView, e error, grant string) int64 {
	t.Helper()
	if e != nil {
		t.Fatal("fold", e)
	}
	return l.SpendUsed(grant)
}

// Claim (A5/A6 migration gate): through the public OpenJournalV2 with a keyed
// header, a release refuses at every site unless it carries the header
// ReceiptKey's signature over ReconcileDigestV2 for this journal's binding and
// the record's own grant_id, nonce and Seq. Refused, per case: a receipt-key
// signature over the v1 preimage, a stranger key's signature, a journal whose
// header names no key (""), and the bytes of a valid authorization lifted to
// another journal, grant, nonce or Seq (including a replay of an applied
// release). Append refuses RECONCILE_AUTHORIZATION and nothing becomes
// durable (the reopened journal ends before it); open/replay of the same
// image refuses JOURNAL_SEGMENT; FoldLedgerV2 of it served by a foreign
// JournalV2 refuses RECONCILE_AUTHORIZATION. The neighbour, the same image
// with the correct signature, applies at all three sites.
func TestPX1jFA1ReleaseGate(t *testing.T) {
	for _, c := range px1jFA1Cases(t) {
		t.Run(c.name, func(t *testing.T) {
			grant := c.refused.recs[0].GrantID
			n := uint64(len(c.refused.recs))
			t.Run("append", func(t *testing.T) {
				j, dir, e := px1jFA1Append(t, c.refused)
				if e == nil || e.Error() != CodeReconcileAuthorization {
					t.Fatalf("APPEND_UNVERIFIED %s: %v", c.name, e)
				}
				l, fe := FoldLedgerV2(j)
				if j.Usage().LastSeq != n-1 || px1jFA1Spend(t, l, fe, grant) != c.before {
					t.Fatal("refused release changed the journal", j.Usage())
				}
				j.Close()
				r, e := OpenJournalV2(dir, "journal-v2.lock", c.refused.h, JournalLimitsV2{SpendCapacity: 4})
				if e != nil || r.Usage().LastSeq != n-1 {
					t.Fatal("refused release became durable", e)
				}
				r.Close()
				v, vdir, e := px1jFA1Append(t, c.valid)
				if e != nil {
					t.Fatal("valid neighbour refused at Append", e)
				}
				l, fe = FoldLedgerV2(v)
				if px1jFA1Spend(t, l, fe, grant) != c.after {
					t.Fatal("valid neighbour did not release")
				}
				v.Close()
				if r, e = OpenJournalV2(vdir, "journal-v2.lock", c.valid.h, JournalLimitsV2{SpendCapacity: 4}); e != nil || r.Usage().LastSeq != n {
					t.Fatal("valid neighbour did not reopen", e)
				}
				r.Close()
			})
			t.Run("open", func(t *testing.T) {
				if j, e := OpenJournalV2(px1jWriteSegment(t, c.refused), "journal-v2.lock", c.refused.h, JournalLimitsV2{SpendCapacity: 4}); e == nil || e.Error() != CodeJournalSegment {
					if e == nil {
						j.Close()
					}
					t.Fatalf("REPLAY_UNVERIFIED %s: %v", c.name, e)
				}
				j, e := OpenJournalV2(px1jWriteSegment(t, c.valid), "journal-v2.lock", c.valid.h, JournalLimitsV2{SpendCapacity: 4})
				if e != nil {
					t.Fatal("valid neighbour did not open", e)
				}
				defer j.Close()
				l, fe := FoldLedgerV2(j)
				if j.Usage().LastSeq != n || px1jFA1Spend(t, l, fe, grant) != c.after {
					t.Fatal("valid neighbour did not replay its release")
				}
			})
			t.Run("fold", func(t *testing.T) {
				if l, e := FoldLedgerV2(px1jListJournal{c.refused.h, c.refused.recs}); e == nil || e.Error() != CodeReconcileAuthorization {
					spend := int64(-1)
					if e == nil {
						spend = l.SpendUsed(grant)
					}
					t.Fatalf("FOLD_UNVERIFIED %s: %v spend=%d", c.name, e, spend)
				}
				l, e := FoldLedgerV2(px1jListJournal{c.valid.h, c.valid.recs})
				if px1jFA1Spend(t, l, e, grant) != c.after {
					t.Fatal("valid neighbour did not fold its release")
				}
				l, e = FoldLedgerV2(px1jListJournal{c.refused.h, c.refused.recs[:n-1]})
				if px1jFA1Spend(t, l, e, grant) != c.before {
					t.Fatal("records before the refused release must fold")
				}
			})
		})
	}
}

// Claim: Append verifies the Seq it assigns, not the Seq the caller claims.
// A release signed for Seq 3 and submitted claiming Seq 3 after a track took
// Seq 3 (so it lands at 4) refuses RECONCILE_AUTHORIZATION, and so does a
// release whose caller-chosen Seq 99 matches its own signature; nothing is
// stored. The neighbour signed for the assigned Seq 4 applies and reopens.
func TestPX1jFA1AppendAssignsSeq(t *testing.T) {
	dir := px1jPrivateDir(t)
	h := px1jWalletHeader(px1jReceiptKeyN)
	j, e := OpenJournalV2(dir, "journal-v2.lock", h, JournalLimitsV2{SpendCapacity: 4})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { j.Close() }()
	reserve := px1jMust(t, j, px1jReserve(1, 1, px1jFA1Now, 50000, 1))
	px1jMust(t, j, px1jFollowRec(reserve, RecordUncertain, "uncertain", px1jFA1Now))
	stale := px1jSignNext(t, j, px1jFA1Release(reserve, 50000, px1jFA1Now), px1jReceiptKeyN) // signed for Seq 3
	track := px1jFollowRec(reserve, RecordTrack, TrackConfirmed, px1jFA1Now)
	track.Track = &TrackRecordV2{State: TrackConfirmed, Height: 100, BlockHash: px1jHex(9), Confirmations: 1}
	px1jMust(t, j, track)
	if _, e = j.Append(stale); e == nil || e.Error() != CodeReconcileAuthorization {
		t.Fatal("APPEND_TRUSTS_CALLER_SEQ stale", e)
	}
	chosen := px1jSignAt(t, h, px1jFA1Release(reserve, 50000, px1jFA1Now), 99, px1jReceiptKeyN)
	if _, e = j.Append(chosen); e == nil || e.Error() != CodeReconcileAuthorization {
		t.Fatal("APPEND_TRUSTS_CALLER_SEQ chosen", e)
	}
	if j.Usage().LastSeq != 3 {
		t.Fatal("refused release stored")
	}
	if out := px1jMust(t, j, px1jSignNext(t, j, stale, px1jReceiptKeyN)); out.Seq != 4 {
		t.Fatal("neighbour seq", out.Seq)
	}
	j.Close()
	if j, e = OpenJournalV2(dir, "journal-v2.lock", h, JournalLimitsV2{SpendCapacity: 4}); e != nil || j.Usage().LastSeq != 4 {
		t.Fatal("neighbour must reopen", e)
	}
}

// px1jFA1OffCurveX is the smallest x for which x^3+7 is a quadratic
// non-residue mod the secp256k1 field prime (Euler's criterion), so no curve
// point has it as its x coordinate. Computed without the BIP-340 library.
func px1jFA1OffCurveX() string {
	p, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	half := new(big.Int).Rsh(pm1, 1)
	for x := int64(1); ; x++ {
		y2 := new(big.Int).Exp(big.NewInt(x), big.NewInt(3), p)
		y2.Add(y2, big.NewInt(7)).Mod(y2, p)
		if new(big.Int).Exp(y2, half, p).Cmp(pm1) == 0 {
			return fmt.Sprintf("%064x", x)
		}
	}
}

// Claim (A5, open): OpenJournalV2 refuses JOURNAL_SEGMENT for a ReceiptKey
// that is neither "" nor a valid x-only key (upper-case hex, 63 hex digits, a
// 33-byte compressed key, non-hex, an x with no curve point, x = p), both for
// a new directory (nothing is created) and over an existing journal. The
// neighbours "" and the valid fixture key open. A foreign JournalV2 whose
// header names a malformed key folds no release (RECONCILE_AUTHORIZATION)
// while its records before the release fold. Limit: the fixture controls
// below check that each malformed value is in fact refused by the BIP-340
// parser or the lowercase-hex rule.
func TestPX1jFA1MalformedReceiptKey(t *testing.T) {
	valid := px1jWalletHeader(px1jReceiptKeyN).ReceiptKey
	if strings.ToUpper(valid) == valid {
		t.Fatal("fixture key has no hex letters")
	}
	offCurve := px1jFA1OffCurveX()
	for _, x := range []string{offCurve, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"} {
		raw, _ := hex.DecodeString(x)
		if _, e := schnorr.ParsePubKey(raw); e == nil {
			t.Fatal("fixture control: key parses", x)
		}
	}
	existing := px1jPrivateDir(t)
	j, e := OpenJournalV2(existing, "journal-v2.lock", px1jWalletHeader(px1jReceiptKeyN), JournalLimitsV2{SpendCapacity: 4})
	if e != nil {
		t.Fatal(e)
	}
	px1jMust(t, j, px1jReserve(1, 1, px1jFA1Now, 50000, 1))
	j.Close()
	h := px1jWalletHeader(px1jReceiptKeyN)
	prefix := px1jFA1Prefix(1, 1)
	signed := px1jSignAt(t, h, px1jFA1Release(prefix[0], 50000, px1jFA1Now), 3, px1jReceiptKeyN)
	for _, c := range []struct{ name, key string }{
		{"upper-case", strings.ToUpper(valid)},
		{"63 hex digits", valid[:63]},
		{"compressed 33 bytes", "02" + valid},
		{"non-hex", "zz" + valid[2:]},
		{"off-curve x", offCurve},
		{"x equal to p", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := h
			bad.ReceiptKey = c.key
			fresh := px1jPrivateDir(t)
			if j, e := OpenJournalV2(fresh, "journal-v2.lock", bad, JournalLimitsV2{SpendCapacity: 4}); e == nil || e.Error() != CodeJournalSegment {
				if e == nil {
					j.Close()
				}
				t.Fatalf("MALFORMED_KEY_ACCEPTED %s: %v", c.name, e)
			}
			if entries, _ := os.ReadDir(fresh); len(entries) != 0 {
				t.Fatal("refused open wrote state")
			}
			if j, e := OpenJournalV2(existing, "journal-v2.lock", bad, JournalLimitsV2{SpendCapacity: 4}); e == nil || e.Error() != CodeJournalSegment {
				if e == nil {
					j.Close()
				}
				t.Fatalf("MALFORMED_KEY_ACCEPTED existing %s: %v", c.name, e)
			}
			if _, e := FoldLedgerV2(px1jListJournal{bad, px1jConcat(prefix, signed)}); e == nil || e.Error() != CodeReconcileAuthorization {
				t.Fatal("release folded under a malformed key", e)
			}
			if l, e := FoldLedgerV2(px1jListJournal{bad, prefix}); px1jFA1Spend(t, l, e, prefix[0].GrantID) != 50000 {
				t.Fatal("records without a release must fold")
			}
		})
	}
	t.Run("neighbours", func(t *testing.T) {
		for _, key := range []string{"", valid} {
			ok := h
			ok.ReceiptKey = key
			j, e := OpenJournalV2(px1jPrivateDir(t), "journal-v2.lock", ok, JournalLimitsV2{SpendCapacity: 4})
			if e != nil {
				t.Fatalf("valid receipt key %q refused: %v", key, e)
			}
			j.Close()
		}
		if j, e := OpenJournalV2(existing, "journal-v2.lock", h, JournalLimitsV2{SpendCapacity: 4}); e != nil || j.Usage().LastSeq != 1 {
			t.Fatal("existing journal under its own key", e)
		} else {
			j.Close()
		}
	})
}

// Claim (A5, header pin): receipt_key is part of the whole-header comparison.
// A journal created under the fixture key and holding no reconcile refuses
// JOURNAL_SEGMENT when reopened under "" or a stranger key, and a journal
// created under "" refuses under the fixture key; each reopens under its own
// header.
func TestPX1jFA1ReceiptKeyPinned(t *testing.T) {
	for _, c := range []struct {
		created int
		others  []int
	}{{px1jReceiptKeyN, []int{0, 8}}, {0, []int{px1jReceiptKeyN}}} {
		dir := px1jPrivateDir(t)
		j, e := OpenJournalV2(dir, "journal-v2.lock", px1jWalletHeader(c.created), JournalLimitsV2{SpendCapacity: 4})
		if e != nil {
			t.Fatal(e)
		}
		px1jMust(t, j, px1jReserve(1, 1, px1jFA1Now, 50000, 1))
		j.Close()
		for _, n := range c.others {
			if j, e := OpenJournalV2(dir, "journal-v2.lock", px1jWalletHeader(n), JournalLimitsV2{SpendCapacity: 4}); e == nil || e.Error() != CodeJournalSegment {
				if e == nil {
					j.Close()
				}
				t.Fatalf("RECEIPT_KEY_UNPINNED created %d reopened %d: %v", c.created, n, e)
			}
		}
		if j, e = OpenJournalV2(dir, "journal-v2.lock", px1jWalletHeader(c.created), JournalLimitsV2{SpendCapacity: 4}); e != nil || j.Usage().LastSeq != 1 {
			t.Fatal("own header must reopen", c.created, e)
		}
		j.Close()
	}
}

// Claim (MIGRATION, service layer): the G2 service-layer journal header
// carries ReceiptKey "" (it never holds a reconcile record), and an opener
// that hands back a journal under a keyed header refuses JOURNAL_SEGMENT at
// service startup; the product opener is the neighbour that starts.
func TestPX1jFA1ServiceHeader(t *testing.T) {
	clock := int64(500)
	s := px1jServiceFixture(t, px1jStateDir(t), &clock, 4)
	if h := s.g2.journal.Header(); h.ReceiptKey != "" || h.Layer != JournalLayerService {
		t.Fatalf("SERVICE_RECEIPT_KEY %+v", h)
	}
	open := func(substitute bool) error {
		x := &ActionService{config: ServiceConfig{StateDir: px1jStateDir(t)}, clock: func() int64 { return clock }}
		x.state = serviceState{1, px1jHex(77), []serviceEntry{}}
		deps := px1jServiceDeps{validate: func(G2OperatorConfig) error { return nil }, open: func(dir, lock string, h JournalHeaderV2, l JournalLimitsV2) (JournalV2, error) {
			if substitute {
				h.ReceiptKey = px1jWalletHeader(px1jReceiptKeyN).ReceiptKey
			}
			return OpenJournalV2(dir, lock, h, l)
		}}
		e := x.px1jOpenService(px1Operator(), x.state.Binding, deps)
		if x.g2 != nil {
			x.g2.journal.Close()
		}
		return e
	}
	if e := open(true); e == nil || e.Error() != CodeJournalSegment {
		t.Fatal("SERVICE_RECEIPT_KEY substituted header", e)
	}
	if e := open(false); e != nil {
		t.Fatal("product opener neighbour", e)
	}
}

// Claim: a verified signature is necessary, not sufficient. FoldLedgerV2
// still applies the journal's own table after VerifyReconcileV2: a foreign
// JournalV2 serving a correctly signed release above the retained debit, one
// whose target_seq is not the reserve, or one citing "absent" evidence with a
// spender refuses JOURNAL_RECORD; the correctly signed in-bounds release
// folds to a zero retained debit.
func TestPX1jFA1FoldTableAfterVerify(t *testing.T) {
	h := px1jWalletHeader(px1jReceiptKeyN)
	prefix := px1jFA1Prefix(1, 1)
	for _, c := range []struct {
		name   string
		mutate func(*ReconcileRecordV2)
	}{
		{"above the retained debit", func(c *ReconcileRecordV2) { c.ReleasedSat = 50001 }},
		{"target is not the reserve", func(c *ReconcileRecordV2) { c.TargetSeq = 2 }},
		{"absent naming a spender", func(c *ReconcileRecordV2) { c.ConflictTxID = px1jHex(6) }},
		{"in bounds", nil},
	} {
		rel := px1jFA1Release(prefix[0], 50000, px1jFA1Now)
		if c.mutate != nil {
			c.mutate(rel.Reconcile)
		}
		signed := px1jSignAt(t, h, rel, 3, px1jReceiptKeyN)
		if VerifyReconcileV2(h, signed) != nil {
			t.Fatal("fixture control: signature does not verify", c.name)
		}
		l, e := FoldLedgerV2(px1jListJournal{h, px1jConcat(prefix, signed)})
		if c.mutate == nil {
			if px1jFA1Spend(t, l, e, prefix[0].GrantID) != 0 {
				t.Fatal("in-bounds neighbour did not fold")
			}
			continue
		}
		if e == nil || e.Error() != px1jCodeRecord {
			spend := int64(-1)
			if e == nil {
				spend = l.SpendUsed(prefix[0].GrantID)
			}
			t.Fatalf("FOLD_TABLE_UNCHECKED %s: %v spend=%d", c.name, e, spend)
		}
	}
}
