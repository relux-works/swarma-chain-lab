package rehearsal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// An owned loopback transport barrier forwards original RPC bytes to the same
// real Core. It never changes a result, forges chain state, or logs credentials.
// Booking stops after the confirmed payment block was delivered, before the
// final snapshot validation; issuer stops before A send and after A acceptance
// but before the acknowledgement. These are external transport crash points,
// not coverage of every internal fsync/signing boundary.
type rpcBarrier struct {
	mu                       sync.Mutex
	server                   *httptest.Server
	upstream                 string
	mode, payment, raw, txid string
	sawPayment               bool
	sends                    int
	hit, release             chan struct{}
}

func newRPCBarrier(route su.Route) *rpcBarrier {
	b := &rpcBarrier{upstream: fmt.Sprintf("http://127.0.0.1:%d/", route.Port)}
	b.server = httptest.NewServer(http.HandlerFunc(b.serve))
	return b
}
func (b *rpcBarrier) route(r su.Route) su.Route {
	u, _ := url.Parse(b.server.URL)
	r.Port, _ = strconv.Atoi(u.Port())
	return r
}
func (b *rpcBarrier) arm(mode, payment string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode, b.payment, b.sawPayment = mode, payment, false
	b.hit, b.release = make(chan struct{}), make(chan struct{})
}
func (b *rpcBarrier) unblock() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode = ""
	if b.release != nil {
		close(b.release)
		b.release = nil
	}
}
func (b *rpcBarrier) close() { b.unblock(); b.server.Close() }
func (b *rpcBarrier) pause(r *http.Request, match bool) {
	if !match {
		return
	}
	b.mu.Lock()
	hit, release := b.hit, b.release
	b.mu.Unlock()
	select {
	case <-hit:
	default:
		close(hit)
	}
	select {
	case <-release:
	case <-r.Context().Done():
	}
}
func (b *rpcBarrier) serve(w http.ResponseWriter, r *http.Request) {
	raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		w.WriteHeader(502)
		return
	}
	var q struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.Unmarshal(raw, &q) != nil {
		w.WriteHeader(400)
		return
	}
	b.mu.Lock()
	before := b.mode == "issuer-before" && q.Method == "sendrawtransaction" || b.mode == "booking" && b.sawPayment && q.Method == "getnetworkinfo"
	if (b.mode == "issuer-before" || b.mode == "issuer-after") && q.Method == "sendrawtransaction" && len(q.Params) == 1 {
		var tx string
		_ = json.Unmarshal(q.Params[0], &tx)
		if b.raw != "" && b.raw != tx {
			b.mu.Unlock()
			w.WriteHeader(409)
			return
		}
		b.raw = tx
	}
	b.mu.Unlock()
	b.pause(r, before)
	if before {
		return
	}
	// A killed caller cannot accidentally release a previously blocked write.
	if r.Context().Err() != nil {
		return
	}
	req, e := http.NewRequestWithContext(r.Context(), http.MethodPost, b.upstream, bytes.NewReader(raw))
	if e != nil {
		w.WriteHeader(502)
		return
	}
	req.Header = r.Header.Clone()
	client := http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	res, e := client.Do(req)
	if e != nil {
		w.WriteHeader(502)
		return
	}
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if e != nil {
		w.WriteHeader(502)
		return
	}
	b.mu.Lock()
	if q.Method == "sendrawtransaction" && res.StatusCode == 200 {
		var v struct {
			Result string `json:"result"`
		}
		_ = json.Unmarshal(body, &v)
		b.txid = v.Result
		b.sends++
	}
	if b.mode == "booking" && q.Method == "getblock" && res.StatusCode == 200 {
		var v struct {
			Result struct {
				Confirmations int `json:"confirmations"`
				Transactions  []struct {
					ID string `json:"txid"`
				} `json:"tx"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &v) == nil && v.Result.Confirmations >= 2 {
			for _, tx := range v.Result.Transactions {
				if tx.ID == b.payment {
					b.sawPayment = true
				}
			}
		}
	}
	after := b.mode == "issuer-after" && q.Method == "sendrawtransaction" && res.StatusCode == 200
	b.mu.Unlock()
	b.pause(r, after)
	if after {
		return
	}
	if r.Context().Err() != nil {
		return
	}
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(body)
}
func (l *lab) crashAt(b *rpcBarrier, p *process) {
	select {
	case <-b.hit:
	case <-p.done:
		p.stopped = true
		p.log.Close()
		l.t.Fatal("crash target exited before barrier")
	case <-time.After(15 * time.Second):
		l.t.Fatal("crash barrier not reached")
	}
	checked(l.t, p.cmd.Process.Kill(), "owned crash PID")
	select {
	case e := <-p.done:
		if e == nil {
			l.t.Fatal("crash did not terminate process")
		}
	case <-time.After(5 * time.Second):
		l.t.Fatal("crash PID did not exit")
	}
	p.stopped = true
	checked(l.t, p.log.Close(), "crashed log close")
	b.unblock()
}
func (l *lab) bookingDisk(id string) booking.BookingV2 {
	raw, e := os.ReadFile(filepath.Join(l.private, "booking/state.json"))
	checked(l.t, e, "booking crash state")
	var s struct {
		Bookings []booking.BookingV2 `json:"bookings"`
	}
	checked(l.t, json.Unmarshal(raw, &s), "booking crash state shape")
	for _, v := range s.Bookings {
		if v.Contract.BookingID == id {
			return v
		}
	}
	l.t.Fatal("booking crash record absent")
	return booking.BookingV2{}
}
func (l *lab) issuerRecord() (string, string, string) {
	root := filepath.Join(l.private, "signer")
	raw, e := os.ReadFile(filepath.Join(root, "ledger.json"))
	checked(l.t, e, "issuer crash ledger")
	var s struct {
		Operations []struct{ Kind, Record string } `json:"operations"`
	}
	checked(l.t, json.Unmarshal(raw, &s), "issuer crash ledger shape")
	if len(s.Operations) != 1 || s.Operations[0].Kind != "grant-issue" {
		l.t.Fatal("issuer duplicate/missing operation")
	}
	raw, e = os.ReadFile(filepath.Join(root, "blob-"+s.Operations[0].Record+".json"))
	checked(l.t, e, "issuer crash durable record")
	var r struct {
		Phase, TxID string
		Raw         string `json:"raw_tx"`
	}
	checked(l.t, json.Unmarshal(raw, &r), "issuer crash record shape")
	return r.Phase, r.TxID, r.Raw
}
func (l *lab) crashIssuer(config string, b *rpcBarrier) {
	var id, raw string
	for i, mode := range []string{"issuer-before", "issuer-after"} {
		b.arm(mode, "")
		role := fmt.Sprintf("issuer-crash-%d", i)
		l.bins[role] = l.bins["signer"]
		p := l.spawn(role, "-config", config, "-once")
		l.crashAt(b, p)
		phase, gotID, gotRaw := l.issuerRecord()
		if phase != "signed" || len(gotID) != 64 || gotRaw == "" {
			l.t.Fatal("issuer crash did not preserve signed phase")
		}
		if i == 0 {
			id, raw = gotID, gotRaw
		} else if gotID != id || gotRaw != raw {
			l.t.Fatal("issuer restart changed transaction")
		}
		b.mu.Lock()
		sends := b.sends
		captured := b.raw
		accepted := b.txid
		b.mu.Unlock()
		if sends != i || captured != raw || i == 1 && accepted != id {
			l.t.Fatal("issuer barrier effect count/bytes mismatch")
		}
	}
	l.signerCycle(config)
	phase, gotID, gotRaw := l.issuerRecord()
	b.mu.Lock()
	sends := b.sends
	b.mu.Unlock()
	if phase != "stored" || gotID != id || gotRaw != raw || sends != 1 {
		l.t.Fatal("issuer recovery duplicated or changed accepted transaction")
	}
	l.evidence["issuer_crash"] = map[string]any{"before_a_killed": true, "lost_ack_killed": true, "same_durable_bytes": true, "broadcast_effects": 1, "single_operation": true, "txid": id, "raw_sha256": rental.Hash([]byte(raw)), "outcome": "exact-bytes recovery"}
	l.evidence["crash_cases"].(map[string]string)["issuer"] = "transport-barriers-pass"
}

// Barrier calibration: a real forwarded response is byte-identical; a matched
// request stalls until caller cancellation and never reaches the upstream.
// The unmatched positive proves this instrument does not block all RPC traffic.
func TestRPCBarrierControl(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		_, _ = io.WriteString(w, `{"result":"ok","error":null,"id":1}`)
	}))
	defer upstream.Close()
	b := newRPCBarrier(su.Route{})
	defer b.close()
	b.upstream = upstream.URL
	post := func(method string) *http.Response {
		r, e := http.Post(b.server.URL, "application/json", bytes.NewBufferString(`{"method":"`+method+`","params":[]}`))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	b.arm("issuer-before", "")
	r := post("getblockchaininfo")
	body, e := io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil || string(body) != `{"result":"ok","error":null,"id":1}` {
		t.Fatal("forwarding control")
	}
	done := make(chan struct{})
	client := http.Client{Timeout: 200 * time.Millisecond}
	go func() {
		r, e := client.Post(b.server.URL, "application/json", bytes.NewBufferString(`{"method":"sendrawtransaction","params":[]}`))
		if e == nil {
			r.Body.Close()
			t.Error("barrier request completed")
		}
		close(done)
	}()
	select {
	case <-b.hit:
	case <-time.After(time.Second):
		t.Fatal("control plant not applied")
	}
	<-done
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 1 {
		t.Fatal("blocked request reached upstream")
	}
}
