package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type f6StartupChain struct {
	base         *f6Node
	transactions map[string]*f6Node
	sends        []string
}

func f6StartupChainFor(r JournalRecordV2) *f6StartupChain {
	n := &f6Node{reserve: r}
	return &f6StartupChain{base: n, transactions: map[string]*f6Node{f6Transaction(r).ID(): n}, sends: []string{f6Transaction(r).ID()}}
}
func (n *f6StartupChain) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	switch method {
	case "listtransactions":
		rows := []map[string]string{}
		for _, id := range n.sends {
			rows = append(rows, map[string]string{"txid": id, "category": "send"})
		}
		return canonical(rows), nil
	case "getrawtransaction":
		if tx := n.transactions[args[0].(string)]; tx != nil {
			return tx.Call(ctx, method, args...)
		}
		return nil, fail("RPC_NO_SUCH_TX")
	case "getblock":
		ids := []string{}
		for id := range n.transactions {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		height := 95
		if n.base.change == "k5" {
			height = 96
		}
		return canonical(map[string]any{"hash": px1jHex(95), "height": height, "tx": ids}), nil
	}
	return n.base.Call(ctx, method, args...)
}
func f6StartupCheck(t *testing.T, j JournalV2, n *f6StartupChain) error {
	t.Helper()
	check, e := NewStartupReconciler(startupReconcileRoute{Node: n, observer: n, network: "regtest", genesis: su.RegtestGenesis})
	if e != nil {
		t.Fatal(e)
	}
	return check.Reconcile(context.Background(), j)
}
func f6ReleaseForStartup(t *testing.T, j JournalV2, r JournalRecordV2, n *f6StartupChain, at int64) ReconcileResult {
	t.Helper()
	key, _ := testKey(9)
	result, e := reconcileLocked(context.Background(), j, n, key, f6Request(r), px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return at })
	if e != nil {
		t.Fatal(e)
	}
	return result
}

// Claim (+): the runtime's real startup constructor recognizes exactly the
// receipt-key-signed conflict X from an opened journal; release accounting is
// retained across reopen. The no-release neighbor still rejects X.
func TestF6StartupNamedConflict(t *testing.T) {
	j, r, dir := f6Journal(t)
	n := f6StartupChainFor(r)
	if e := f6StartupCheck(t, j, n); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatal("F6_STARTUP_UNRELEASED_X", e)
	}
	f6ReleaseForStartup(t, j, r, n, time.Now().Unix())
	h := j.Header()
	j.Close()
	j, e := OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4})
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	lab := px1oNewRuntimeLab(t)
	lab.r.deps.newReconciler = NewStartupReconciler
	lab.env.wallet = j
	lab.env.walletRoute = n
	lab.env.observer = n
	lab.env.network = "regtest"
	// The runtime must supply the admitted network's genesis to the observer.
	lab.env.genesis = su.RegtestGenesis
	if e = lab.r.start(context.Background(), lab.env); e != nil || !lab.r.ready {
		t.Fatal("F6_STARTUP_NAMED_X", e)
	}
	ledger, e := FoldLedgerV2(j)
	if e != nil || ledger.SpendUsed(r.GrantID) != 0 || ledger.InputReserved(r.Inputs[0]) {
		t.Fatal("F6_STARTUP_RELEASE_ACCOUNTING", e)
	}
	if used, count := ledger.DayUsage(r.GrantID, r.Day); used != 0 || count != 1 || ledger.UncertainSat(r.GrantID) != 0 {
		t.Fatal("F6_STARTUP_RELEASE_DAY_ACCOUNTING", used, count)
	}
}

// Claim (-): a valid release naming X does not exempt unrelated wallet send Y.
// Removing Y from wallet history is the valid neighbor; startup never writes.
func TestF6StartupOnlyNamedSend(t *testing.T) {
	j, r, _ := f6Journal(t)
	defer j.Close()
	n := f6StartupChainFor(r)
	f6ReleaseForStartup(t, j, r, n, time.Now().Unix())
	seq := j.Usage().LastSeq
	n.sends = append(n.sends, px1jHex(989))
	if e := f6StartupCheck(t, j, n); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatal("F6_STARTUP_UNRELATED_Y", e)
	}
	n.sends = n.sends[:1]
	if e := f6StartupCheck(t, j, n); e != nil {
		t.Fatal("F6_STARTUP_X_NEIGHBOR", e)
	}
	if j.Usage().LastSeq != seq {
		t.Fatal("F6_STARTUP_WROTE")
	}
}

// Claim (-, T13): restoring a valid older journal lacking the release still
// rejects the wallet's send X; the unchanged released journal passes.
func TestF6StartupRollback(t *testing.T) {
	j, r, dir := f6Journal(t)
	path := filepath.Join(dir, px1jSegmentName(1))
	older, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	n := f6StartupChainFor(r)
	f6ReleaseForStartup(t, j, r, n, time.Now().Unix())
	newer, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	h := j.Header()
	j.Close()
	for _, c := range []struct {
		name string
		raw  []byte
		want string
	}{{"rollback", older, CodeStateReconcileRequired}, {"current", newer, ""}} {
		t.Run(c.name, func(t *testing.T) {
			if e := os.WriteFile(path, c.raw, 0600); e != nil {
				t.Fatal(e)
			}
			opened, e := OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4})
			if e != nil {
				t.Fatal(e)
			}
			defer opened.Close()
			e = f6StartupCheck(t, opened, n)
			if c.want == "" {
				if e != nil {
					t.Fatal("F6_STARTUP_CURRENT", e)
				}
			} else if e == nil || e.Error() != c.want {
				t.Fatal("F6_STARTUP_ROLLBACK_ACCEPTED", e)
			}
		})
	}
}

// Claim (-): signature tampering and a broken segment chain are rejected at
// OpenJournalV2; authentically signed false tip/depth fails startup evidence
// validation. Neither recognizes X. Restoring exact bytes passes.
// Regression (startup-signed-depth-fixture-masking): the five-confirmation
// historical tip has its actual active hash, while the current tip has six.
func TestF6StartupTamperedOrUnchained(t *testing.T) {
	for _, kind := range []string{"signature", "chain", "signed-tip", "signed-depth"} {
		t.Run(kind, func(t *testing.T) {
			dir := px1jPrivateDir(t)
			j, e := OpenJournalV2(dir, px1WalletJournalLock, px1jWalletHeader(9), JournalLimitsV2{SpendCapacity: 4, SegmentMaxRecords: 2})
			if e != nil {
				t.Fatal(e)
			}
			r := px1jMust(t, j, px1jReserve(1, 1, time.Now().Unix()-10, 50000, 1))
			px1jMust(t, j, px1jFollowRec(r, RecordUncertain, "uncertain", r.LastTime))
			n := f6StartupChainFor(r)
			f6ReleaseForStartup(t, j, r, n, time.Now().Unix())
			h := j.Header()
			j.Close()
			path := filepath.Join(dir, px1jSegmentName(2))
			valid, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var seg JournalSegmentV2
			if json.Unmarshal(valid, &seg) != nil {
				t.Fatal("fixture segment")
			}
			if kind == "signature" {
				seg.Records[0].Reconcile.ConflictTxID = px1jHex(989)
			} else if kind == "chain" {
				seg.PrevSHA256 = px1jHex(989)
			} else {
				if kind == "signed-tip" {
					seg.Records[0].Reconcile.BlockHash = px1jHex(989)
				} else {
					seg.Records[0].Reconcile.Height = 99 // only five at the signed tip
					raw, e := n.Call(context.Background(), "getblockhash", int64(99))
					if e != nil || json.Unmarshal(raw, &seg.Records[0].Reconcile.BlockHash) != nil {
						t.Fatal("F6_SIGNED_DEPTH_FIXTURE_HASH", e)
					}
				}
				key, _ := testKey(9)
				digest, e := ReconcileDigestV2(h, seg.Records[0])
				if e != nil {
					t.Fatal(e)
				}
				sig, e := schnorr.Sign(key, digest)
				if e != nil {
					t.Fatal(e)
				}
				seg.Records[0].Reconcile.Signature = hex.EncodeToString(sig.Serialize())
				if e := VerifyReconcileV2(h, seg.Records[0]); e != nil {
					t.Fatal("F6_SIGNED_EVIDENCE_FIXTURE_SIGNATURE", e)
				}
			}
			if e = os.WriteFile(path, canonical(seg), 0600); e != nil {
				t.Fatal(e)
			}
			openedBad, openErr := OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4, SegmentMaxRecords: 2})
			if kind == "signed-tip" || kind == "signed-depth" {
				if openErr != nil {
					t.Fatal(openErr)
				}
				startupErr := f6StartupCheck(t, openedBad, n)
				openedBad.Close()
				if startupErr == nil || startupErr.Error() != CodeReconcileEvidence {
					t.Fatal("F6_STARTUP_FALSE_EVIDENCE", startupErr)
				}
			} else {
				if openErr == nil {
					openedBad.Close()
					t.Fatal("F6_STARTUP_UNVERIFIED_OPEN", kind)
				}
				if openErr.Error() != CodeJournalSegment {
					t.Fatal(openErr)
				}
			}
			if e = os.WriteFile(path, valid, 0600); e != nil {
				t.Fatal(e)
			}
			opened, e := OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4, SegmentMaxRecords: 2})
			if e != nil {
				t.Fatal(e)
			}
			defer opened.Close()
			if e = f6StartupCheck(t, opened, n); e != nil {
				t.Fatal("F6_STARTUP_RESTORED", e)
			}
			// A valid signature alone is not hash-chain provenance.
			unchained := &fakeJournal{header: opened.Header(), records: px1sRecords(t, opened)}
			if e = f6StartupCheck(t, unchained, n); e == nil || e.Error() != CodeJournalSegment {
				t.Fatal("F6_STARTUP_FOREIGN_CHAIN", e)
			}
		})
	}
}

// Claim (-): k=5 cannot append any release or change retained debit. The same
// consistent conflict at k=6 appends and can be recognized by startup.
func TestF6StartupDepthAtAppend(t *testing.T) {
	j, r, _ := f6Journal(t)
	defer j.Close()
	n := f6StartupChainFor(r)
	n.base.change = "k5"
	key, _ := testKey(9)
	seq := j.Usage().LastSeq
	result, e := reconcileLocked(context.Background(), j, n, key, f6Request(r), px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return time.Now().Unix() })
	if e == nil || e.Error() != CodeReconcileEvidence || result.MayHaveWritten || j.Usage().LastSeq != seq {
		t.Fatal("F6_STARTUP_K5_APPENDED", result, e)
	}
	ledger, e := FoldLedgerV2(j)
	if e != nil || ledger.SpendUsed(r.GrantID) != r.Reserved {
		t.Fatal("F6_STARTUP_K5_DEBIT", e)
	}
	n.base.change = ""
	f6ReleaseForStartup(t, j, r, n, time.Now().Unix())
	if e = f6StartupCheck(t, j, n); e != nil {
		t.Fatal("F6_STARTUP_K6_NEIGHBOR", e)
	}
}

// Claim (-): lifting the signed release for X to later conflict Y fails journal open;
// keeping X's original valid release still does not whitelist Y. A fresh signed
// release for Y after the hour is the valid neighbor that clears only Y.
func TestF6StartupReleaseReplay(t *testing.T) {
	j, r, dir := f6Journal(t)
	n := f6StartupChainFor(r)
	at := time.Now().Unix()
	x := f6ReleaseForStartup(t, j, r, n, at)
	second := px1jMust(t, j, px1jReserve(1, 2, at+1, 50000, 2))
	n.transactions[f6Transaction(second).ID()] = &f6Node{reserve: second}
	n.sends = append(n.sends, f6Transaction(second).ID())
	path := filepath.Join(dir, px1jSegmentName(1))
	valid, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	h := j.Header()
	j.Close()
	var seg JournalSegmentV2
	if e = json.Unmarshal(valid, &seg); e != nil || len(seg.Records) != 4 {
		t.Fatal("replay fixture", e)
	}
	lifted := px1jFollowRec(second, RecordReconcile, "released", at+3600)
	lifted.Seq = 5
	payload := *x.Record.Reconcile
	payload.TargetSeq = second.Seq
	payload.ConflictTxID = f6Transaction(second).ID()
	lifted.Reconcile = &payload
	seg.Records = append(seg.Records, lifted)
	if e = os.WriteFile(path, canonical(seg), 0600); e != nil {
		t.Fatal(e)
	}
	if opened, e := OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4}); e == nil {
		opened.Close()
		t.Fatal("F6_STARTUP_REPLAY_OPENED")
	} else if e.Error() != CodeJournalSegment {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, valid, 0600); e != nil {
		t.Fatal(e)
	}
	j, e = OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4})
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if e = f6StartupCheck(t, j, n); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatal("F6_STARTUP_REPLAY_CLEARED_Y", e)
	}
	f6ReleaseForStartup(t, j, second, n, at+3600)
	if e = f6StartupCheck(t, j, n); e != nil {
		t.Fatal("F6_STARTUP_FRESH_Y", e)
	}
}
