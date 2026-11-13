package wallet

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// ReconcileConfirmations is the release bound, independent of tracker alerts.
const ReconcileConfirmations int64 = 6

type ReconcileRequest struct {
	TargetSeq    uint64
	ReleasedSat  int64
	Evidence     string
	ConflictTxID string
	NotePath     string
}

type ReconcileResult struct {
	Record         *JournalRecordV2 `json:"record,omitempty"`
	Verified       bool             `json:"verified"`
	MayHaveWritten bool             `json:"may_have_written"`
}

// ReconcileWallet is the sole operator entrypoint. It opens no listener and
// sends no transaction. Installed inputs retain the daemon's DK5 admission;
// private state ownership binds the caller to the service UID. The operator
// must stop the daemon first: service, wallet and journal locks are exclusive.
func ReconcileWallet(ctx context.Context, configPath string, q ReconcileRequest) (ReconcileResult, error) {
	var result ReconcileResult
	if q.TargetSeq == 0 || q.ReleasedSat < 1 || q.Evidence != "conflict" || !hexN(q.ConflictTxID, 32) {
		return result, fail(CodeReconcileEvidence)
	}
	c, e := LoadServiceConfig(configPath)
	if e != nil {
		return result, e
	}
	if e = validServiceIdentityAndPaths(c); e != nil {
		return result, e
	}
	if c.G2 == nil {
		return result, fail("SERVICE_PROFILE")
	}
	if c.StateDir == filepath.Dir(c.Socket) || c.WalletConfig == c.ReceiptKeyFile {
		return result, fail("SERVICE_PATH")
	}
	if e = ValidateG2OperatorConfig(*c.G2); e != nil {
		return result, e
	}
	wc, e := LoadInstalledWalletConfig(c.WalletConfig)
	if e != nil {
		return result, e
	}
	network, genesis := serviceNetworkPins(c.Network, c.Genesis)
	if wc.Network != network || wc.Genesis != genesis {
		return result, fail("SERVICE_WALLET_NETWORK")
	}
	if c.StateDir == wc.StateDir || c.StateDir == wc.Policy.StateDir || c.StateDir == wc.ObjectsDir || c.StateDir == wc.WalletDir || c.StateDir == wc.MemoryZone {
		return result, fail("SERVICE_PATH")
	}
	// Never initialize a fresh journal to repair missing history.
	if _, e = os.Lstat(filepath.Join(wc.StateDir, px1jSegmentName(1))); e != nil {
		return result, fail("STATE_UNAVAILABLE")
	}
	lock, e := durable.Open(c.StateDir, "service.lock")
	if e != nil {
		return result, e
	}
	defer lock.Close()
	key, e := loadReceiptKey(c.ReceiptKeyFile)
	if e != nil {
		return result, e
	}
	if hex.EncodeToString(schnorr.SerializePubKey(key.PubKey())) == c.Grantee {
		return result, fail("SERVICE_KEY_SEPARATION")
	}
	w, e := px1OpenServiceWallet(wc, c, key)
	if e != nil {
		return result, e
	}
	defer w.Close()
	note, e := privateBytes(q.NotePath, 65536)
	if e != nil {
		return result, e
	}
	defer clear(note)
	return reconcileLocked(ctx, w.PX1Journal(), w.node, key, q, Hash(note), network, genesis, func() int64 { return time.Now().Unix() })
}

// Tests inject time/node/append faults only through this unexported helper.
// No CLI, environment or configuration can replace the production clock.
func reconcileLocked(ctx context.Context, j JournalV2, node su.Node, key *btcec.PrivateKey, q ReconcileRequest, noteHash, network, genesis string, clock func() int64) (ReconcileResult, error) {
	var result ReconcileResult
	if ctx.Err() != nil {
		return result, fail("RECONCILE_INTERRUPTED")
	}
	now := clock()
	if j == nil || j.Poisoned() {
		return result, fail("STATE_UNAVAILABLE")
	}
	if q.Evidence != "conflict" || !hexN(q.ConflictTxID, 32) {
		return result, fail(CodeReconcileEvidence)
	}
	ledger, e := FoldLedgerV2(j)
	if e != nil {
		return result, e
	}
	var reserve JournalRecordV2
	retained := int64(0)
	last := int64(-1)
	e = j.Iterate(1, func(r JournalRecordV2) error {
		if r.Seq == q.TargetSeq && r.Kind == RecordReserve {
			reserve = r
			retained = r.Reserved
		}
		if r.Kind == RecordReconcile && r.Reconcile != nil {
			last = r.LastTime
			if r.Reconcile.TargetSeq == q.TargetSeq {
				retained -= r.Reconcile.ReleasedSat
			}
		}
		return nil
	})
	if e != nil {
		return result, e
	}
	if now < j.Usage().LastTime {
		return result, fail(CodeClockRollback)
	}
	if last >= 0 && (now < last || now-last < ReconcileMinIntervalSeconds) {
		return result, fail(CodeReconcileRateLimited)
	}
	if reserve.Seq == 0 || q.ReleasedSat < 1 || q.ReleasedSat > retained || !ledger.InputReserved(reserve.Inputs[0]) {
		return result, fail("JOURNAL_RECORD")
	}
	tip, e := reconcileConflict(ctx, node, reserve, q.ConflictTxID, network, genesis)
	if e != nil {
		return result, e
	}
	at := clock()
	if at < now {
		return result, fail(CodeClockRollback)
	}
	rec := reserve
	rec.Seq = j.Usage().LastSeq + 1
	rec.Kind = RecordReconcile
	rec.Phase = "released"
	rec.LastTime = at
	rec.Service = nil
	rec.Track = nil
	rec.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "conflict", Height: tip.Blocks, BlockHash: tip.Best, ConflictTxID: q.ConflictTxID, ReleasedSat: q.ReleasedSat, NoteSHA256: noteHash}
	digest, e := ReconcileDigestV2(j.Header(), rec)
	if e != nil {
		return result, e
	}
	sig, e := schnorr.Sign(key, digest)
	if e != nil {
		return result, fail(CodeReconcileAuthorization)
	}
	rec.Reconcile.Signature = hex.EncodeToString(sig.Serialize())
	if e = VerifyReconcileV2(j.Header(), rec); e != nil {
		return result, e
	}
	if ctx.Err() != nil {
		return result, fail("RECONCILE_INTERRUPTED")
	}
	appended, e := j.Append(rec)
	if e != nil {
		result.MayHaveWritten = j.Poisoned() || e.Error() == "JOURNAL_WRITE_UNCERTAIN"
		return result, e
	}
	result.Record = &appended
	result.MayHaveWritten = true
	if e = VerifyReconcileV2(j.Header(), appended); e != nil {
		return result, e
	}
	if _, e = FoldLedgerV2(j); e != nil {
		return result, e
	}
	result.Verified = true
	return result, nil
}

type reconcileTip struct {
	Chain  string `json:"chain"`
	Blocks int64  `json:"blocks"`
	Best   string `json:"bestblockhash"`
}

func reconcileConflict(ctx context.Context, node su.Node, reserve JournalRecordV2, conflict, network, genesis string) (reconcileTip, error) {
	var tip reconcileTip
	bad := func(e error) (reconcileTip, error) {
		if e != nil && strings.HasPrefix(e.Error(), "RPC_") {
			return tip, e
		}
		return tip, fail(CodeReconcileEvidence)
	}
	if conflict == reserve.TxID {
		return bad(nil)
	}
	observation := su.NewReadObservation(ctx, node)
	defer observation.Close()
	if e := observation.Start(network, genesis); e != nil {
		return bad(e)
	}
	start := observation.Tip()
	tip = reconcileTip{Chain: start.Chain, Blocks: start.Blocks, Best: start.Best}
	view, tx, e := observation.PaymentTransaction(conflict)
	if e != nil {
		return bad(e)
	}
	if view.Confirmations < ReconcileConfirmations {
		return bad(nil)
	}
	spends := false
	for _, in := range tx.Inputs {
		for _, reserved := range reserve.Inputs {
			if in.Point == reserved {
				spends = true
			}
		}
	}
	if !spends {
		return bad(nil)
	}
	header, e := observation.Confirmed(view)
	if e != nil {
		return bad(e)
	}
	if header.Confirmations < ReconcileConfirmations {
		return bad(nil)
	}
	if e = observation.Stable(); e != nil {
		return bad(e)
	}
	return tip, nil
}
