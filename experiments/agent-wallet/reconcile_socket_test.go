package wallet

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim (row 20, real AF_UNIX socket): reconcile, unknown-action and injected
// reconcile payload requests never append a release in either journal. A valid
// read traverses the same socket and succeeds. This same-UID fixture proves
// wire separation, not actual separate-UID filesystem custody (T18).
func TestF6Row20Socket(t *testing.T) {
	now := time.Now().Unix()
	s := px1jServiceFixture(t, px1jPrivateDir(t), &now, 4)
	j, _, _ := f6Journal(t)
	defer j.Close()
	s.wallet.g2 = &px1Wallet{journal: j}
	s.wallet.wallet = f6ReadNode{}
	s.wallet.node = &f6Node{}
	runtime, e := os.MkdirTemp("", "f6-sock-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(runtime)
	s.config.Socket = filepath.Join(runtime, "w.sock")
	s.config.SocketGID = uint32(os.Getgid())
	s.config.PeerUID = uint32(os.Getuid())
	s.config.TimeoutSeconds = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, e := os.Stat(s.config.Socket); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket startup")
		}
		time.Sleep(time.Millisecond)
	}
	assertNoRelease := func() {
		t.Helper()
		for _, journal := range []JournalV2{j, s.PX1ServiceJournal()} {
			journal.Iterate(1, func(r JournalRecordV2) error {
				if r.Kind == RecordReconcile {
					t.Fatal("F6_WIRE_RECONCILE")
				}
				return nil
			})
		}
	}
	r := actionFixture(t, "balance")
	r.CreatedAt = now
	r.Nonce = strings.Repeat("1", 32)
	good := actionEnvelope(t, r)
	for _, action := range []string{"reconcile", "unknown", "status"} {
		q := r
		q.Action = action
		before := [2]uint64{j.Usage().LastSeq, s.PX1ServiceJournal().Usage().LastSeq}
		receipt, _ := socketRaw(t, s, actionEnvelope(t, q))
		if receipt.Receipt.Reason != "ACTION_UNSUPPORTED" {
			t.Fatal("F6_ROW20_REFUSAL", receipt.Receipt.Reason)
		}
		after := [2]uint64{j.Usage().LastSeq, s.PX1ServiceJournal().Usage().LastSeq}
		if before != after {
			t.Fatal("F6_ROW20_JOURNAL_WRITE")
		}
		assertNoRelease()
	}
	injected := []byte(strings.Replace(string(good), `"params":{}`, `"params":{"reconcile":{"released_sat":50000}}`, 1))
	receipt, _ := socketRaw(t, s, injected)
	if receipt.Receipt.Reason != "ACTION_PARAMS" {
		t.Fatal("F6_PAYLOAD_INJECTION", receipt.Receipt.Reason)
	}
	assertNoRelease()
	receipt, _ = socketRaw(t, s, good)
	if receipt.Receipt.Verdict != "executed" {
		t.Fatal("F6_ROW20_VALID_READ", receipt.Receipt.Reason)
	}
	assertNoRelease()
	// The status protocol independently closes a non-status request without a write.
	left, right := net.Pipe()
	doneStatus := make(chan error, 1)
	go func() {
		doneStatus <- ServeStatus(ctx, left, func() (StatusProjectionV1, error) { return StatusProjectionV1{}, nil })
		left.Close()
	}()
	if e := writeActionFrame(right, []byte(`{"v":1,"action":"reconcile"}`)); e != nil {
		t.Fatal(e)
	}
	if _, e := readActionFrame(right); e == nil {
		t.Fatal("F6_STATUS_RECONCILE_REPLY")
	}
	right.Close()
	<-doneStatus
	assertNoRelease()
}

type f6ReadNode struct{}

func (f6ReadNode) Call(context.Context, string, ...any) (json.RawMessage, error) {
	return canonical(map[string]any{"mine": map[string]any{"trusted": 0, "untrusted_pending": 0, "immature": 0}}), nil
}
