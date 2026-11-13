package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type f6Node struct {
	reserve JournalRecordV2
	change  string
	tips    int
}

func f6Transaction(r JournalRecordV2) *su.Transaction {
	inputs := []su.Input{}
	for _, p := range r.Inputs {
		inputs = append(inputs, su.Input{Point: p, Sequence: 0xffffffff})
	}
	return &su.Transaction{Version: 1, Inputs: inputs, Outputs: []su.Output{{Value: 1, Script: []byte{0x51}}}}
}
func (n *f6Node) transaction() *su.Transaction {
	tx := f6Transaction(n.reserve)
	if n.change == "input" {
		tx.Inputs[0].TxID = px1jHex(42)
	}
	return tx
}
func (n *f6Node) Call(_ context.Context, m string, args ...any) (json.RawMessage, error) {
	if n.change == "rpc" {
		return nil, fail("RPC_UNAVAILABLE")
	}
	switch m {
	case "getblockchaininfo":
		n.tips++
		chain := "regtest"
		best := px1jHex(100)
		if n.change == "chain" {
			chain = "main"
		}
		if n.change == "tip" && n.tips > 1 {
			best = px1jHex(101)
		}
		return canonical(map[string]any{"chain": chain, "blocks": 100, "headers": 100, "bestblockhash": best, "initialblockdownload": false}), nil
	case "getblockhash":
		h := int64(0)
		switch v := args[0].(type) {
		case int:
			h = int64(v)
		case int64:
			h = v
		case float64:
			h = int64(v)
		}
		if h == 0 {
			g := su.RegtestGenesis
			if n.change == "genesis" {
				g = px1jHex(99)
			}
			return canonical(g), nil
		}
		if h == 99 || h == 100 {
			return canonical(px1jHex(int(h))), nil
		}
		if n.change == "inactive" {
			return canonical(px1jHex(94)), nil
		}
		return canonical(px1jHex(95)), nil
	case "getrawtransaction":
		tx := n.transaction()
		id := tx.ID()
		if n.change == "txid" {
			id = px1jHex(87)
		}
		k := int64(6)
		if n.change == "k5" {
			k = 5
		}
		vin := []any{}
		for _, in := range tx.Inputs {
			vin = append(vin, map[string]any{"txid": in.TxID, "vout": in.Vout, "scriptSig": map[string]string{"hex": ""}})
		}
		return canonical(map[string]any{"txid": id, "hex": hex.EncodeToString(tx.Bytes()), "blockhash": px1jHex(95), "confirmations": k, "vin": vin, "vout": []any{map[string]any{"n": 0, "value": su.Coins(1), "scriptPubKey": map[string]string{"hex": "51"}}}}), nil
	case "getblockheader":
		hash := args[0].(string)
		h, k := int64(95), int64(6)
		if hash == px1jHex(100) {
			h, k = 100, 1
		} else if n.change == "k5" {
			h, k = 96, 5
		} else if n.change == "height" {
			h = 101
		}
		return canonical(map[string]any{"hash": hash, "height": h, "confirmations": k}), nil
	case "getblock":
		ids := []string{n.transaction().ID()}
		if n.change == "membership" {
			ids = []string{px1jHex(86)}
		}
		height := 95
		if n.change == "k5" {
			height = 96
		}
		return canonical(map[string]any{"hash": px1jHex(95), "height": height, "tx": ids}), nil
	}
	return nil, fail("RPC_METHOD_FORBIDDEN")
}
func f6Journal(t *testing.T) (JournalV2, JournalRecordV2, string) {
	t.Helper()
	return f6JournalWithPlan(t, false)
}
func f6JournalWithPlan(t *testing.T, ownPlan bool) (JournalV2, JournalRecordV2, string) {
	t.Helper()
	dir := px1jPrivateDir(t)
	j := px1jOpenWallet(t, dir, JournalLimitsV2{SpendCapacity: 4})
	r := px1jReserve(1, 1, time.Now().Unix()-10, 50000, 1)
	if ownPlan {
		r.TxID = f6Transaction(r).ID()
	}
	r = px1jMust(t, j, r)
	px1jMust(t, j, px1jFollowRec(r, RecordUncertain, "uncertain", r.LastTime))
	return j, r, dir
}
func f6JournalFingerprint(t *testing.T, dir string) string {
	t.Helper()
	paths, e := filepath.Glob(filepath.Join(dir, "journal-v2-*.json"))
	if e != nil || len(paths) == 0 {
		t.Fatal("fixture journal files", e)
	}
	files := map[string]string{}
	for _, path := range paths {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		files[filepath.Base(path)] = Hash(b)
	}
	return Hash(canonical(files))
}
func f6Request(r JournalRecordV2) ReconcileRequest {
	return ReconcileRequest{TargetSeq: r.Seq, ReleasedSat: r.Reserved, Evidence: "conflict", ConflictTxID: f6Transaction(r).ID()}
}

// Claim: the operator core accepts a six-confirmation input conflict and refuses
// neighboring unsafe evidence/amount/key/clock cases without a release or debit
// change. These are simulated own-node observations, not Core qualification.
// Regression (conflict-input-fixture-masking): input and own-plan have coherent
// raw bytes/txids/active membership, so only the intended exclusion can refuse.
func TestF6ReconcileRefusals(t *testing.T) {
	for _, name := range []string{"valid", "k5", "chain", "genesis", "tip", "inactive", "input", "txid", "height", "membership", "rpc", "absent", "own-plan", "zero", "over", "target", "key", "clock"} {
		t.Run(name, func(t *testing.T) {
			j, r, dir := f6JournalWithPlan(t, name == "own-plan")
			defer j.Close()
			q := f6Request(r)
			node := &f6Node{reserve: r, change: name}
			key, _ := testKey(9)
			now := time.Now().Unix()
			want := CodeReconcileEvidence
			switch name {
			case "valid":
				want = ""
			case "rpc":
				want = CodeReconcileEvidence
			case "absent":
				q.Evidence = "absent"
			case "input":
				q.ConflictTxID = node.transaction().ID()
			case "own-plan":
				q.ConflictTxID = r.TxID
			case "zero":
				q.ReleasedSat = 0
				want = "JOURNAL_RECORD"
			case "over":
				q.ReleasedSat = r.Reserved + 1
				want = "JOURNAL_RECORD"
			case "target":
				q.TargetSeq = 999
				want = "JOURNAL_RECORD"
			case "key":
				key, _ = testKey(8)
				want = CodeReconcileAuthorization
			case "clock":
				now = r.LastTime - 1
				want = CodeClockRollback
			}
			if name == "valid" || name == "input" || name == "own-plan" {
				// Establish fixture coherence independently of release refusal.
				o := su.NewReadObservation(context.Background(), node)
				defer o.Close()
				if e := o.Start("regtest", su.RegtestGenesis); e != nil {
					t.Fatal("F6_FIXTURE_CHAIN", e)
				}
				view, tx, e := o.PaymentTransaction(q.ConflictTxID)
				if e != nil || tx == nil || tx.ID() != q.ConflictTxID {
					t.Fatal("F6_FIXTURE_RAW_BINDING", e)
				}
				if _, e := o.Confirmed(view); e != nil || o.Stable() != nil {
					t.Fatal("F6_FIXTURE_MEMBERSHIP", e)
				}
				spends := tx.Inputs[0].Point == r.Inputs[0]
				if spends != (name != "input") || (q.ConflictTxID == r.TxID) != (name == "own-plan") {
					t.Fatal("F6_FIXTURE_EXCLUSION")
				}
			}
			seq := j.Usage().LastSeq
			before := f6JournalFingerprint(t, dir)
			result, e := reconcileLocked(context.Background(), j, node, key, q, px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return now })
			if want == "" {
				if e != nil || !result.Verified || result.Record == nil || VerifyReconcileV2(j.Header(), *result.Record) != nil {
					t.Fatalf("F6_VALID_REJECTED: %+v %v", result, e)
				}
				return
			}
			if e == nil || e.Error() != want || result.MayHaveWritten || j.Usage().LastSeq != seq {
				t.Fatalf("F6_UNSAFE_RELEASE %s: %+v %v", name, result, e)
			}
			if f6JournalFingerprint(t, dir) != before {
				t.Fatal("F6_REFUSAL_CHANGED_JOURNAL")
			}
			l, e := FoldLedgerV2(j)
			if e != nil || l.SpendUsed(r.GrantID) != r.Reserved || !l.InputReserved(r.Inputs[0]) {
				t.Fatal("F6_REFUSAL_CHANGED_DEBIT", e)
			}
		})
	}
}

// Claim: global rate limiting rejects a fresh partial release at +3599 and
// accepts +3600 using test-only injected time. Reopen verifies the signed
// journal, retained debit and original-day count; old signed bytes cannot replay.
func TestF6RateAndReopen(t *testing.T) {
	j, r, dir := f6Journal(t)
	q := f6Request(r)
	q.ReleasedSat = 1
	key, _ := testKey(9)
	now := time.Now().Unix()
	first, e := reconcileLocked(context.Background(), j, &f6Node{reserve: r}, key, q, px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return now })
	if e != nil {
		t.Fatal(e)
	}
	seq := j.Usage().LastSeq
	for _, delta := range []int64{3599, 3600} {
		result, e := reconcileLocked(context.Background(), j, &f6Node{reserve: r}, key, q, px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return now + delta })
		if delta == 3599 {
			if e == nil || e.Error() != CodeReconcileRateLimited || result.MayHaveWritten || j.Usage().LastSeq != seq {
				t.Fatal("F6_HOURLY_BYPASS", e)
			}
		} else if e != nil {
			t.Fatal("F6_HOUR_BOUNDARY", e)
		}
	}
	h := j.Header()
	j.Close()
	j, e = OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4})
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	l, e := FoldLedgerV2(j)
	if e != nil || l.SpendUsed(r.GrantID) != r.Reserved-2 {
		t.Fatal("F6_REOPEN_DEBIT", e)
	}
	_, count := l.DayUsage(r.GrantID, r.Day)
	if count != 1 {
		t.Fatal("F6_DAY_COUNT_RETURNED")
	}
	if _, e = j.Append(*first.Record); e == nil || e.Error() != CodeReconcileAuthorization {
		t.Fatal("F6_SIGNED_REPLAY", e)
	}
}

type f6UncertainAppend struct{ JournalV2 }

func (j f6UncertainAppend) Append(r JournalRecordV2) (JournalRecordV2, error) {
	_, e := j.JournalV2.Append(r)
	if e != nil {
		return JournalRecordV2{}, e
	}
	return JournalRecordV2{}, fail("JOURNAL_WRITE_UNCERTAIN")
}

// Claim: an append whose ACK is lost after the actual write returns possible
// write, not safe refusal; reopening finds one signed release, never a retry.
func TestF6AmbiguousWrite(t *testing.T) {
	j, r, dir := f6Journal(t)
	key, _ := testKey(9)
	result, e := reconcileLocked(context.Background(), f6UncertainAppend{j}, &f6Node{reserve: r}, key, f6Request(r), px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return time.Now().Unix() })
	if e == nil || !result.MayHaveWritten || result.Verified {
		t.Fatal("F6_AMBIGUOUS_REPORTED_SAFE", result, e)
	}
	h := j.Header()
	j.Close()
	j, e = OpenJournalV2(dir, px1WalletJournalLock, h, JournalLimitsV2{SpendCapacity: 4})
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	l, e := FoldLedgerV2(j)
	if e != nil || l.SpendUsed(r.GrantID) != 0 || j.Usage().LastSeq != 3 {
		t.Fatal("F6_AMBIGUOUS_LOST", e)
	}
}

func f6Installed(t *testing.T) (string, ServiceConfig, Config, JournalRecordV2) {
	t.Helper()
	c := px1ServiceUnitConfig(t)
	op := px1Operator()
	c.G2 = &op
	s, e := OpenActionService(c)
	if e != nil {
		t.Fatal(e)
	}
	r := px1jMust(t, s.wallet.PX1Journal(), px1jReserve(1, 1, time.Now().Unix()-10, 50000, 1))
	px1jMust(t, s.wallet.PX1Journal(), px1jFollowRec(r, RecordUncertain, "uncertain", r.LastTime))
	s.Close()
	wc, e := LoadInstalledWalletConfig(c.WalletConfig)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(c.WalletConfig), "service.json")
	writeInstalled(t, path, canonical(c))
	return path, c, wc, r
}

// Claim: public operator entrypoint refuses a live service lock and serializes
// concurrent callers so at most one release is appended. Installed ownership
// uses the existing explicitly synthetic DK5 unit seam, not host qualification.
func TestF6OperatorLocksConcurrent(t *testing.T) {
	path, c, wc, r := f6Installed(t)
	note := filepath.Join(t.TempDir(), "note")
	if e := os.WriteFile(note, []byte("public fixture note"), 0600); e != nil {
		t.Fatal(e)
	}
	q := f6Request(r)
	q.NotePath = note
	lock, e := durable.Open(c.StateDir, "service.lock")
	if e != nil {
		t.Fatal(e)
	}
	if got, e := ReconcileWallet(context.Background(), path, q); e == nil || e.Error() != "STATE_BUSY" || got.MayHaveWritten {
		t.Fatal("F6_LIVE_LOCK_BYPASS", e)
	}
	lock.Close()
	// Both invocations use real RPC clients on a private HTTP fixture.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		json.NewDecoder(req.Body).Decode(&body)
		node := &f6Node{reserve: r}
		raw, e := node.Call(req.Context(), body.Method, body.Params...)
		if e != nil {
			t.Error(e)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": json.RawMessage(raw), "error": nil})
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	wc.Observer.Port = port
	wc.Wallet.Route.Port = port
	wc.Broadcast.Port = port
	// Rebind a fresh existing journal to the changed private fixture node.
	// This is fixture setup only, never operator recovery.
	os.Remove(filepath.Join(wc.StateDir, px1jSegmentName(1)))
	os.Remove(filepath.Join(c.StateDir, px1jSegmentName(1)))
	writeInstalled(t, c.WalletConfig, canonical(wc))
	s, e := OpenActionService(c)
	if e != nil {
		t.Fatal(e)
	}
	r = px1jMust(t, s.wallet.PX1Journal(), px1jReserve(1, 1, time.Now().Unix()-10, 50000, 1))
	px1jMust(t, s.wallet.PX1Journal(), px1jFollowRec(r, RecordUncertain, "uncertain", r.LastTime))
	s.Close()
	if e = os.Remove(filepath.Dir(c.Socket)); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	answers := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := ReconcileWallet(context.Background(), path, q); answers <- e }()
	}
	wg.Wait()
	close(answers)
	ok := 0
	for e := range answers {
		if e == nil {
			ok++
		} else if e.Error() != "STATE_BUSY" && e.Error() != CodeReconcileRateLimited && e.Error() != "JOURNAL_RECORD" {
			t.Fatal(e)
		}
	}
	if ok != 1 {
		t.Fatal("F6_CONCURRENT_RELEASES", ok)
	}
	key, e := loadReceiptKey(c.ReceiptKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	w, e := px1OpenServiceWallet(wc, c, key)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()

	n := 0
	w.PX1Journal().Iterate(1, func(rec JournalRecordV2) error {
		if rec.Kind == RecordReconcile {
			n++
		}
		return nil
	})
	if n != 1 {
		t.Fatal("F6_CONCURRENT_APPEND_COUNT", n)
	}
}

// Claim: startup integrity still rejects an unknown send; a conflict release
// does not manufacture a matching original reservation for that transaction.
func TestF6StartupUnknownSend(t *testing.T) {
	j, _, _ := f6Journal(t)
	defer j.Close()
	node := f6StartupNode{}
	r, e := NewStartupReconciler(node)
	if e != nil {
		t.Fatal(e)
	}
	seq := j.Usage().LastSeq
	if e = r.Reconcile(context.Background(), j); e == nil || e.Error() != CodeStateReconcileRequired || j.Usage().LastSeq != seq {
		t.Fatal("F6_STARTUP_BYPASS", e)
	}
}

type f6StartupNode struct{}

func (f6StartupNode) Call(context.Context, string, ...any) (json.RawMessage, error) {
	return canonical([]map[string]any{{"txid": px1jHex(88), "category": "send"}}), nil
}

// Claim: cancellation after evidence collection still cannot append a release.
func TestF6InterruptedBeforeAppend(t *testing.T) {
	j, r, _ := f6Journal(t)
	defer j.Close()
	key, _ := testKey(9)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, e := reconcileLocked(ctx, j, &f6Node{reserve: r}, key, f6Request(r), px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return time.Now().Unix() })
	if e == nil || e.Error() != "RECONCILE_INTERRUPTED" || result.MayHaveWritten || j.Usage().LastSeq != 2 {
		t.Fatal("F6_CANCELLED_WRITE", result, e)
	}
}

// Claim: a release of another retained request shares the same hourly budget.
func TestF6RateAcrossTargets(t *testing.T) {
	j, r, _ := f6Journal(t)
	defer j.Close()
	key, _ := testKey(9)
	now := time.Now().Unix()
	if _, e := reconcileLocked(context.Background(), j, &f6Node{reserve: r}, key, f6Request(r), px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return now }); e != nil {
		t.Fatal(e)
	}
	second := px1jMust(t, j, px1jReserve(1, 2, now+1, 50000, 2))
	q := f6Request(second)
	seq := j.Usage().LastSeq
	if got, e := reconcileLocked(context.Background(), j, &f6Node{reserve: second}, key, q, px1jHex(3), "regtest", su.RegtestGenesis, func() int64 { return now + 3599 }); e == nil || e.Error() != CodeReconcileRateLimited || got.MayHaveWritten || j.Usage().LastSeq != seq {
		t.Fatal("F6_CROSS_REQUEST_HOURLY", e)
	}
}

// Claim: production entrypoint preserves service-UID validation, receipt-key
// journal binding, W2 rejection, existing-state requirement and wallet lock.
// All files/identities here are isolated DK5 fixtures, not installed-host proof.
func TestF6OperatorAdmission(t *testing.T) {
	for _, name := range []string{"agent-uid", "wrong-key", "w2", "missing-journal", "wallet-lock", "network-pin", "config-network", "grantee-curve", "relative-config"} {
		t.Run(name, func(t *testing.T) {
			path, c, wc, r := f6Installed(t)
			note := filepath.Join(t.TempDir(), "note")
			os.WriteFile(note, []byte("public fixture note"), 0600)
			q := f6Request(r)
			q.NotePath = note
			want := ""
			switch name {
			case "network-pin":
				c.Genesis = px1jHex(123)
				want = "SERVICE_NETWORK_PIN"
			case "config-network":
				c.Network = "main"
				c.Genesis = su.MainGenesis
				want = "SERVICE_WALLET_NETWORK"
			case "grantee-curve":
				c.Grantee = strings.Repeat("f", 64)
				want = "SERVICE_CONFIG"
			case "relative-config":
				c.ReceiptKeyFile = "relative-key"
				want = "SERVICE_PATH"
			case "agent-uid":
				c.PeerUID = uint32(os.Getuid())
				want = "SERVICE_CONFIG"
			case "wrong-key":
				key, _ := testKey(8)
				writeInstalled(t, c.ReceiptKeyFile, []byte(hex.EncodeToString(key.Serialize())))
				want = CodeJournalSegment
			case "w2":
				c.G2 = nil
				want = "SERVICE_PROFILE"
			case "missing-journal":
				os.Remove(filepath.Join(wc.StateDir, px1jSegmentName(1)))
				want = "STATE_UNAVAILABLE"
			case "wallet-lock":
				w, e := Open(wc)
				if e != nil {
					t.Fatal(e)
				}
				defer w.Close()
				want = "STATE_BUSY"
			}
			writeInstalled(t, path, canonical(c))
			got, e := ReconcileWallet(context.Background(), path, q)
			if e == nil || e.Error() != want || got.MayHaveWritten || got.Record != nil {
				t.Fatal("F6_ADMISSION_BYPASS", name, got, e)
			}
			if name == "missing-journal" {
				if _, e := os.Stat(filepath.Join(wc.StateDir, px1jSegmentName(1))); !os.IsNotExist(e) {
					t.Fatal("F6_INITIALIZED_RECOVERY_JOURNAL")
				}
			}
		})
	}
}

// Claim: daemon admission still needs its runtime socket directory; offline
// reconciliation binds the service UID through the signed config's private
// durable state and can reach its lock guard after systemd removes runtime/.
func TestF6OfflineRuntimeDirectory(t *testing.T) {
	path, c, _, r := f6Installed(t)
	if e := os.Remove(filepath.Dir(c.Socket)); e != nil {
		t.Fatal(e)
	}
	if s, e := OpenActionService(c); e == nil {
		s.Close()
		t.Fatal("F6_DAEMON_RUNTIME_WAIVED")
	} else if e.Error() != "SERVICE_SOCKET_DIR" {
		t.Fatal(e)
	}
	lock, e := durable.Open(c.StateDir, "service.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	q := f6Request(r)
	q.NotePath = "/unused/public-note"
	if result, e := ReconcileWallet(context.Background(), path, q); e == nil || e.Error() != "STATE_BUSY" || result.MayHaveWritten {
		t.Fatal("F6_OFFLINE_RUNTIME_REQUIRED", result, e)
	}
}

// Claim: the release's executor timestamp is sampled after evidence collection,
// so RPC latency is not subtracted from the next hourly interval. A clock that
// steps backward during evidence refuses without appending; stable time is valid.
func TestF6ClockAtAppend(t *testing.T) {
	for _, delta := range []int64{-1, 0, 30} {
		t.Run(strconv.FormatInt(delta, 10), func(t *testing.T) {
			j, r, _ := f6Journal(t)
			defer j.Close()
			key, _ := testKey(9)
			now := time.Now().Unix()
			n := 0
			clock := func() int64 {
				n++
				if n == 1 {
					return now
				}
				return now + delta
			}
			got, e := reconcileLocked(context.Background(), j, &f6Node{reserve: r}, key, f6Request(r), px1jHex(3), "regtest", su.RegtestGenesis, clock)
			if delta < 0 {
				if e == nil || e.Error() != CodeClockRollback || got.MayHaveWritten || j.Usage().LastSeq != 2 {
					t.Fatal("F6_CLOCK_DURING_EVIDENCE", got, e)
				}
				return
			}
			if e != nil || got.Record == nil || got.Record.LastTime != now+delta {
				t.Fatal("F6_TIMESTAMP_BEFORE_EVIDENCE", got, e)
			}
		})
	}
}
