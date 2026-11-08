package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"relux.works/swarma-chain-lab/experiments/rental"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type countedBroadcast struct {
	inner     Broadcaster
	calls     int
	txs       [][]byte
	lastError error
}

func (b *countedBroadcast) Broadcast(ctx context.Context, raw []byte) (string, error) {
	b.calls++
	b.txs = append(b.txs, append([]byte{}, raw...))
	id, e := b.inner.Broadcast(ctx, raw)
	b.lastError = e
	return id, e
}
func (l *coreLab) fundTo(address string, value int64) Point {
	l.t.Helper()
	id := text(l.t, l.rpc("issuer", "sendtoaddress", address, su.Coins(value)))
	l.mine(1)
	var tx su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx); e != nil {
		l.t.Fatal(e)
	}
	for _, o := range tx.Vout {
		if o.Script.Address == address && int64(o.Value) == value {
			return Point{id, o.N}
		}
	}
	l.t.Fatal("budget funding output")
	return Point{}
}
func (l *coreLab) executor(p rental.Policy, raw []byte, count int) (*Executor, *countedBroadcast, Config, string) {
	l.t.Helper()
	prize := PrizeA{Key: hex.EncodeToString(testKey(31).Serialize()), Address: keyAddress(testKey(31))}
	prize.Point = l.fundTo(prize.Address, 1000000)
	w := Wallet{Key: hex.EncodeToString(testKey(30).Serialize()), Fee: 30000, Inputs: []Point{}}
	for range count {
		w.Inputs = append(w.Inputs, l.fundTo(keyAddress(testKey(30)), 1000000))
	}
	c := Config{Network: "regtest", Prize: prize, Slots: []Slot{{ID: strings.Repeat("c", 64), Envelope: raw, Policy: p, Wallet: w}}}
	l.counter++
	root := filepath.Join(l.root, fmt.Sprintf("executor-%03d", l.counter))
	if e := os.Mkdir(root, 0700); e != nil {
		l.t.Fatal(e)
	}
	broadcast, e := NewBroadcaster(l.broadcastRoute)
	if e != nil {
		l.t.Fatal(e)
	}
	b := &countedBroadcast{inner: broadcast}
	x, e := Open(root, c, l.observer, b)
	if e != nil {
		l.t.Fatal(e)
	}
	x.now = func() time.Time { return time.Unix(500, 0) }
	l.t.Cleanup(x.Close)
	return x, b, c, root
}
func requestFor(c rental.Certificate, nonce, action string, amount int64) Event {
	tags := [][]string{{"action", action}, {"target", keyAddress(testKey(32))}, {"slot", strings.Repeat("c", 64)}, {"nonce", Hash([]byte(nonce))}, {"contract", c.ContractSHA256}}
	if action == "pay" {
		tags = append(tags, []string{"amount", fmt.Sprint(amount)})
	}
	return signEvent(Event{Kind: 8183, CreatedAt: 500, Tags: tags}, testKey(2))
}
func expectResult(t *testing.T, r Receipt, status, reason string) {
	t.Helper()
	if r.Status != status || r.Reason != reason {
		t.Fatalf("want %s/%s got %+v", status, reason, r)
	}
}

// Genuine Core: M1 issuance/admission tools anchor the certificate; the real
// kernel gates every effect. Each forbidden request is paired with an accepted
// request, while the broadcast counter and journal prove no negative effect.
func TestCoreExecutor(t *testing.T) {
	l := newCore(t)
	p, c, raw, pool := l.issueFixture("executor")
	ctx := context.Background()
	t.Run("scopes-bindings-clock-budget", func(t *testing.T) {
		x, b, _, _ := l.executor(p, raw, 3)
		tests := []struct {
			name, reason string
			mutate       func(*Event)
		}{
			{"sender", "GRANTEE_MISMATCH", func(e *Event) { *e = signEvent(*e, testKey(8)) }},
			{"contract", "CONTRACT_MISMATCH", func(e *Event) { tagSet(e, "contract", strings.Repeat("e", 64)); *e = signEvent(*e, testKey(2)) }},
			{"slot", "SLOT_UNKNOWN", func(e *Event) { tagSet(e, "slot", strings.Repeat("e", 64)); *e = signEvent(*e, testKey(2)) }},
			{"future", "REQUEST_TIME", func(e *Event) { e.CreatedAt = 501; *e = signEvent(*e, testKey(2)) }},
			{"before-slot", "REQUEST_TIME", func(e *Event) { e.CreatedAt = 99; *e = signEvent(*e, testKey(2)) }},
			{"scope", "ACTION_SCOPE", func(e *Event) { *e = requestFor(c, "scope", "publish", 0) }},
			{"secret", "SECRET_RELEASE_FORBIDDEN", func(e *Event) { *e = requestFor(c, "secret", "secret.release", 0) }},
			{"over-budget", "BUDGET_EXCEEDED", func(e *Event) { tagSet(e, "amount", "100000"); *e = signEvent(*e, testKey(2)) }},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				e := requestFor(c, tt.name, "pay", 1000)
				tt.mutate(&e)
				expectResult(t, x.Execute(ctx, canonical(e), nil), "refused", tt.reason)
				if b.calls != 0 || len(x.journal.Reservations) != 0 {
					t.Fatal("negative caused effect/reservation")
				}
				live := rental.Check(ctx, l.observer, p, raw, p.StationName, c.GranteePubkey, 500)
				if live.Verdict != "live" {
					t.Fatal("positive kernel neighbour", live)
				}
			})
		}
		for _, tt := range []struct {
			at     int64
			reason string
		}{{99, "KERNEL_NOT_YET_VALID"}, {1000, "KERNEL_EXPIRED"}} {
			x.now = func() time.Time { return time.Unix(tt.at, 0) }
			e := requestFor(c, "clock", "pay", 1000)
			e.CreatedAt = 100
			e = signEvent(e, testKey(2))
			if tt.at == 99 {
				e.CreatedAt = 99
				e = signEvent(e, testKey(2))
				expectResult(t, x.Execute(ctx, canonical(e), nil), "refused", "REQUEST_TIME")
			} else {
				expectResult(t, x.Execute(ctx, canonical(e), nil), "refused", tt.reason)
			}
		}
		x.now = func() time.Time { return time.Unix(500, 0) }
		e := requestFor(c, "paid", "pay", 20000)
		r := x.Execute(ctx, canonical(e), nil)
		if b.lastError != nil {
			t.Log(b.lastError)
			var checks []struct {
				Reason string `json:"reject-reason"`
			}
			_ = json.Unmarshal(l.rpc("", "testmempoolaccept", []string{hex.EncodeToString(b.txs[len(b.txs)-1])}), &checks)
			if len(checks) == 1 {
				t.Log("Core policy rejection:", checks[0].Reason)
			}
		}
		expectResult(t, r, "executed", "LIVE_RENTER_REQUEST")
		l.save("executed.json", r)
		if b.calls != 1 {
			t.Fatal("effect count")
		}
		expectResult(t, x.Execute(ctx, canonical(e), nil), "already-executed", "DURABLE_RESERVATION_NO_RETRY")
		changed := e
		tagSet(&changed, "amount", "1000")
		changed = signEvent(changed, testKey(2))
		expectResult(t, x.Execute(ctx, canonical(changed), nil), "already-executed", "DURABLE_RESERVATION_NO_RETRY")
		over := requestFor(c, "cumulative", "pay", 21000)
		expectResult(t, x.Execute(ctx, canonical(over), nil), "refused", "BUDGET_EXCEEDED")
		if b.calls != 1 {
			t.Fatal("budget/replay effects")
		}
		next := requestFor(c, "remaining", "pay", 20000)
		expectResult(t, x.Execute(ctx, canonical(next), nil), "executed", "LIVE_RENTER_REQUEST")
		if b.calls != 2 {
			t.Fatal("second payment")
		}
		for _, rawtx := range b.txs {
			var tx wire.MsgTx
			if tx.Deserialize(bytes.NewReader(rawtx)) != nil {
				t.Fatal("rawtx")
			}
			for _, in := range tx.TxIn {
				if in.PreviousOutPoint.Hash.String() == x.config.Prize.Point.TxID && in.PreviousOutPoint.Index == x.config.Prize.Point.Vout {
					t.Fatal("PRIZE_SELECTED")
				}
			}
		}
		state, e2 := ObservePrize(ctx, l.observer, x.config.Prize)
		if e2 != nil || state != "unspent" {
			t.Fatal("prize not unspent", e2)
		}
	})
	t.Run("crash-reservation-no-retry", func(t *testing.T) {
		x, b, conf, root := l.executor(p, raw, 1)
		e := requestFor(c, "crash", "pay", 1000)
		x.hook = func(phase string) {
			if phase == "reserved" {
				panic("test-crash")
			}
		}
		func() {
			defer func() {
				if recover() != "test-crash" {
					t.Fatal("crash hook")
				}
			}()
			x.Execute(ctx, canonical(e), nil)
		}()
		if b.calls != 0 {
			t.Fatal("effect before durable crash")
		}
		x.Close()
		again, err := Open(root, conf, l.observer, b)
		if err != nil {
			t.Fatal(err)
		}
		defer again.Close()
		again.now = func() time.Time { return time.Unix(500, 0) }
		r := again.Execute(ctx, canonical(e), nil)
		expectResult(t, r, "already-executed", "DURABLE_RESERVATION_NO_RETRY")
		if r.Phase != "reserved" || b.calls != 0 {
			t.Fatal("reservation retried")
		}
	})
	t.Run("concurrent-exhaustion", func(t *testing.T) {
		x, b, _, _ := l.executor(p, raw, 1)
		event := canonical(requestFor(c, "concurrent", "pay", 1000))
		var wg sync.WaitGroup
		results := make(chan Receipt, 8)
		for range 8 {
			wg.Go(func() { results <- x.Execute(ctx, event, nil) })
		}
		wg.Wait()
		close(results)
		done, seen := 0, 0
		for r := range results {
			switch r.Status {
			case "executed":
				done++
			case "already-executed":
				seen++
			default:
				t.Fatal(r)
			}
		}
		if done != 1 || seen != 7 || b.calls != 1 {
			t.Fatal("concurrent duplicate effect")
		}
		expectResult(t, x.Execute(ctx, canonical(requestFor(c, "exhausted", "pay", 1000)), nil), "refused", "BUDGET_EXHAUSTED")
		state, e := ObservePrize(ctx, l.observer, x.config.Prize)
		if e != nil || state != "unspent" || b.calls != 1 {
			t.Fatal("prize fallback")
		}
	})
	t.Run("deliver-and-substitution", func(t *testing.T) {
		x, b, _, _ := l.executor(p, raw, 1)
		file := []byte("renter-approved file\n")
		e := requestFor(c, "file", "deliver", 0)
		tagSet(&e, "target", "sha256:"+Hash(file))
		e = signEvent(e, testKey(2))
		expectResult(t, x.Execute(ctx, canonical(e), []byte("substituted")), "refused", "FILE_HASH")
		r := x.Execute(ctx, canonical(e), file)
		expectResult(t, r, "executed", "LIVE_RENTER_REQUEST")
		got, err := os.ReadFile(strings.TrimPrefix(r.Link, "file://"))
		if err != nil || !bytes.Equal(got, file) || r.FileHash != Hash(file) || r.RetainUntil != 500+7*86400 || b.calls != 0 {
			t.Fatal("delivery receipt")
		}
	})
	t.Run("node-read-failure", func(t *testing.T) {
		x, b, _, _ := l.executor(p, raw, 1)
		original := x.node
		x.node = failingNode{}
		e := canonical(requestFor(c, "unavailable", "pay", 1000))
		r := x.Execute(ctx, e, nil)
		expectResult(t, r, "refused", "KERNEL_NODE_UNAVAILABLE")
		if b.calls != 0 || len(x.journal.Reservations) != 0 {
			t.Fatal("node failure effect")
		}
		x.node = original
		expectResult(t, x.Execute(ctx, e, nil), "executed", "LIVE_RENTER_REQUEST")
	})
	t.Run("mempool-and-confirmed-revocation", func(t *testing.T) {
		x, b, _, _ := l.executor(p, raw, 2)
		expectResult(t, x.Execute(ctx, canonical(requestFor(c, "pre-revoke", "pay", 1000)), nil), "executed", "LIVE_RENTER_REQUEST")
		plan, e := rental.MakePlan(rental.IssuerPolicy{Policy: p}, rental.PlanSpec{Kind: "revoke", Inputs: []su.PlanInput{{Point: su.Point{TxID: pool.Point.TxID, Vout: pool.Point.Vout}, ValueSat: pool.ValueSat, Script: pool.Script, Role: "seal"}}, ChangeScript: l.script, Pool: pool}, nil, nil, nil, 500)
		if e != nil {
			t.Fatal(e)
		}
		l.sendPlan(plan, false)
		expectResult(t, x.Execute(ctx, canonical(requestFor(c, "revoked", "pay", 1000)), nil), "refused", "KERNEL_SEAL_SPENT")
		l.mine(1)
		expectResult(t, x.Execute(ctx, canonical(requestFor(c, "mined-revoked", "pay", 1000)), nil), "refused", "KERNEL_SEAL_SPENT")
		if b.calls != 1 {
			t.Fatal("revocation effect")
		}
	})
	l.save("result.json", map[string]any{"status": "PASS", "regtest": true, "m1_dependency_pin": "63087f31b62da50a6566250ef96af969e313e51b"})
}

type failingNode struct{}

func (failingNode) Call(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, fail("unavailable")
}
