package service

// Adopted rev374 reviewer regressions; boundary controls strengthened for N3 r2.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

type rev374Opts struct {
	tipShiftFromCall int32 // 1-based getblockchaininfo index from which the node reports height+1
	regTxid          string
	attestKey        string
	responseBytes    int
	expireAfterHash  int32 // flip the flag after serving this many getblockhash calls
}

func rev374Node(t *testing.T, s *Service, st check.Statement, o rev374Opts, flag *atomic.Bool) {
	t.Helper()
	var infos, hashes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		var value any
		switch q.Method {
		case "getblockchaininfo":
			n := infos.Add(1)
			h := st.TipHeight
			if o.tipShiftFromCall > 0 && n >= o.tipShiftFromCall {
				h++
			}
			value = map[string]any{"chain": "regtest", "blocks": h, "bestblockhash": st.TipHash}
		case "getblockhash":
			n := hashes.Add(1)
			value = st.TipHash
			if flag != nil && o.expireAfterHash > 0 && n >= o.expireAfterHash {
				flag.Store(true)
			}
		case "name_show", "name_history":
			txid := strings.Repeat("11", 32)
			if o.regTxid != "" {
				txid = o.regTxid
			}
			key := s.public
			if o.attestKey != "" {
				key = o.attestKey
			}
			n := map[string]any{"name": "id/certifier", "value": `{"swarma":{"notary":{"attest":"` + key + `"}}}`, "txid": txid, "vout": 0, "height": 1, "expires_in": 1000, "expired": false, "name_encoding": "utf8", "value_encoding": "utf8"}
			value = n
			if q.Method == "name_history" {
				value = []any{n}
			}
		}
		raw, err := json.Marshal(map[string]any{"id": 1, "result": value, "error": nil})
		if err != nil {
			t.Error(err)
			return
		}
		if o.responseBytes > 0 && q.Method == "name_show" {
			if len(raw) > o.responseBytes {
				t.Error("response fixture too large")
				return
			}
			raw = append(raw, []byte(strings.Repeat(" ", o.responseBytes-len(raw)))...)
		}
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	node, e := check.NewNodeNameReader(srv.URL, s.config.RPCCredentialFile)
	if e != nil {
		t.Fatal(e)
	}
	s.node = node
}

func rev374Counted(s *Service) *int32 {
	var n int32
	orig := s.sign
	s.sign = func(d []byte) (string, error) { atomic.AddInt32(&n, 1); return orig(d) }
	return &n
}

func rev374Statement(t *testing.T, req Request) check.Statement {
	var st check.Statement
	if json.Unmarshal(req.Statement, &st) != nil {
		t.Fatal("statement")
	}
	return st
}

// Claim: a tip that advances after Check but before the final pre-sign view is
// refused NODE_TIP_MISMATCH with zero signer calls; the unshifted control attests.
func TestRev374FinalViewTipAdvance(t *testing.T) {
	for _, tc := range []struct {
		shift int32
		want  string
		signs int32
	}{{0, "ATTEST", 1}, {3, "NODE_TIP_MISMATCH", 0}} {
		s, req, _ := setup(t)
		rev374Node(t, s, rev374Statement(t, req), rev374Opts{tipShiftFromCall: tc.shift}, nil)
		n := rev374Counted(s)
		_, r, _ := submit(t, s, encode(t, req))
		if r.Decision != tc.want || atomic.LoadInt32(n) != tc.signs || (tc.signs == 0 && (len(r.SignedAttestation) > 0 || r.AnchorFrame != "")) {
			t.Fatalf("shift=%d got %s signs=%d", tc.shift, r.Decision, *n)
		}
	}
}

// Claim: the chain registration of the notary name must equal the parent
// contract's designated registration; a different outpoint refuses unsigned.
func TestRev374RegistrationMismatch(t *testing.T) {
	for _, tc := range []struct{ txid, want string }{{"", "ATTEST"}, {strings.Repeat("33", 32), "NOTARY_REGISTRATION_MISMATCH"}} {
		s, req, _ := setup(t)
		rev374Node(t, s, rev374Statement(t, req), rev374Opts{regTxid: tc.txid}, nil)
		n := rev374Counted(s)
		_, r, _ := submit(t, s, encode(t, req))
		if r.Decision != tc.want || (tc.want != "ATTEST" && atomic.LoadInt32(n) != 0) {
			t.Fatalf("got %s signs=%d", r.Decision, *n)
		}
	}
}

// Claim: a name value publishing a key other than the service key refuses
// NOTARY_KEY_MISMATCH before any signer call.
func TestRev374NotaryKeyMismatch(t *testing.T) {
	s, req, _ := setup(t)
	rev374Node(t, s, rev374Statement(t, req), rev374Opts{attestKey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}, nil)
	n := rev374Counted(s)
	_, r, _ := submit(t, s, encode(t, req))
	if r.Decision != "NOTARY_KEY_MISMATCH" || atomic.LoadInt32(n) != 0 {
		t.Fatalf("got %s signs=%d", r.Decision, *n)
	}
}

// Claim: the service's own early refusals (policy reference, statement shape)
// make zero signer calls; the same service attests the valid request.
func TestRev374ServiceRefusalsNeverSign(t *testing.T) {
	s, req, _ := setup(t)
	n := rev374Counted(s)
	bad := req
	bad.PolicyReference = strings.Repeat("0", 64)
	if _, r, _ := submit(t, s, encode(t, bad)); r.Decision != "POLICY_REFERENCE" || atomic.LoadInt32(n) != 0 {
		t.Fatalf("policy %s signs=%d", r.Decision, *n)
	}
	bad = req
	bad.Statement = json.RawMessage(`{"unknown":1}`)
	if _, r, _ := submit(t, s, encode(t, bad)); r.Decision != "STATEMENT_FIELD" || atomic.LoadInt32(n) != 0 {
		t.Fatalf("statement %s signs=%d", r.Decision, *n)
	}
	if _, r, _ := submit(t, s, encode(t, req)); r.Decision != "ATTEST" || atomic.LoadInt32(n) != 1 {
		t.Fatalf("control %s signs=%d", r.Decision, *n)
	}
}

type rev374Ctx struct {
	context.Context
	expired *atomic.Bool
}

func (c rev374Ctx) Err() error {
	if c.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

// Claim: a deadline that passes after the final view but before signing yields
// REQUEST_TIMEOUT with zero signer calls (the flag flips when the final
// getblockhash is served). Control: same harness without the flip attests.
func TestRev374PreSignDeadline(t *testing.T) {
	for _, tc := range []struct {
		after int32
		want  string
		signs int32
	}{{0, "", 1}, {3, "REQUEST_TIMEOUT", 0}} {
		s, req, _ := setup(t)
		flag := new(atomic.Bool)
		rev374Node(t, s, rev374Statement(t, req), rev374Opts{expireAfterHash: tc.after}, flag)
		n := rev374Counted(s)
		res, e := s.attest(rev374Ctx{context.Background(), flag}, req)
		got := ""
		if e != nil {
			got = e.Error()
		}
		if got != tc.want || atomic.LoadInt32(n) != tc.signs || (e != nil && len(res.SignedAttestation) > 0) {
			t.Fatalf("after=%d got %q signs=%d", tc.after, got, *n)
		}
	}
}

// Claim: Close clears the key after draining (the key scalar is zero).
func TestRev374KeyZeroAfterClose(t *testing.T) {
	s, _, _ := setup(t)
	if s.key.Key.IsZero() {
		t.Fatal("control: loaded key is zero")
	}
	s.Close()
	if !s.key.Key.IsZero() {
		t.Fatal("key not cleared after Close")
	}
}

// Claim: the credential file must be an owner-only regular file and not a
// symlink. Control: the 0600 regular file loads.
func TestRev374CredentialRules(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "cred")
	put(t, good, []byte("u:p"))
	if _, e := check.NewNodeNameReader("http://127.0.0.1:1", good); e != nil {
		t.Fatal("control", e)
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(good, link) != nil {
		t.Fatal("symlink")
	}
	if _, e := check.NewNodeNameReader("http://127.0.0.1:1", link); e == nil || e.Error() != "NODE_CREDENTIALS" {
		t.Fatal("symlinked credential accepted", e)
	}
	loose := filepath.Join(dir, "loose")
	if os.WriteFile(loose, []byte("u:p"), 0644) != nil || os.Chmod(loose, 0644) != nil {
		t.Fatal("write")
	}
	if _, e := check.NewNodeNameReader("http://127.0.0.1:1", loose); e == nil || e.Error() != "NODE_CREDENTIALS" {
		t.Fatal("0644 credential accepted", e)
	}
}

// Claim: nesting beyond 64 inside a member is refused REQUEST_INVALID before
// any node I/O; an object at depth 64 passes Strict and reaches the policy check.
func TestRev374MemberDepth(t *testing.T) {
	s, _, calls := setup(t)
	for _, tc := range []struct {
		depth  int
		status int
		want   string
	}{{64, 422, "POLICY_REFERENCE"}, {65, 400, "REQUEST_INVALID"}} {
		raw := []byte(`{"parent":` + strings.Repeat(`{"x":`, tc.depth-2) + `{}` + strings.Repeat(`}`, tc.depth-2) + `}`)
		status, r, _ := submit(t, s, raw)
		if status != tc.status || r.Decision != tc.want {
			t.Fatalf("depth %d: %d %s", tc.depth, status, r.Decision)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("I/O")
	}
}

// Claim: a valid RPC name response padded to 1 MiB minus one byte attests;
// the same valid response at 1 MiB plus one refuses unsigned before signing.
func TestRev374RPCResponseCap(t *testing.T) {
	for _, tc := range []struct {
		size  int
		want  string
		signs int32
	}{
		{1048575, "ATTEST", 1}, {1048577, "NODE_RPC_FAILURE", 0},
	} {
		s, req, _ := setup(t)
		rev374Node(t, s, rev374Statement(t, req), rev374Opts{responseBytes: tc.size}, nil)
		n := rev374Counted(s)
		_, r, _ := submit(t, s, encode(t, req))
		if r.Decision != tc.want || atomic.LoadInt32(n) != tc.signs || (tc.signs == 0 && (len(r.SignedAttestation) != 0 || r.AnchorFrame != "")) {
			t.Fatalf("size=%d decision=%s signs=%d", tc.size, r.Decision, atomic.LoadInt32(n))
		}
	}
}

func rev374Serve(t *testing.T, s *Service) string {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan error, 1)
	go func() { exited <- s.runListener(ctx, l) }()
	t.Cleanup(func() { cancel(); <-exited })
	return l.Addr().String()
}

// Claim (slowloris, header): a connection that never finishes its headers is
// closed by the server within ReadHeaderTimeout.
func TestRev374SlowHeaderClosed(t *testing.T) {
	s, _, _ := setup(t)
	s.config.Limits.TimeoutMS = 100
	addr := rev374Serve(t, s)
	c, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "POST /v1/attest HTTP/1.1\r\nHost: x\r\n")
	start := time.Now()
	_, e = io.ReadAll(c)
	if ne, ok := e.(net.Error); ok && ne.Timeout() {
		t.Fatal("slow header connection held open")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("slow header too long")
	}
}

// Claim (header cap): headers far above 8 KiB are refused with 431.
func TestRev374HeaderCap(t *testing.T) {
	s, _, _ := setup(t)
	addr := rev374Serve(t, s)
	for _, tc := range []struct {
		n    int
		want int
	}{{100, 422}, {64 << 10, 431}} {
		c, e := net.Dial("tcp", addr)
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(c, "POST /v1/attest HTTP/1.1\r\nHost: x\r\nX-Pad: "+strings.Repeat("a", tc.n)+"\r\nContent-Length: 2\r\n\r\n{}")
		resp, e := http.ReadResponse(bufioReader(c), nil)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		c.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("pad %d: status %d", tc.n, resp.StatusCode)
		}
	}
}

func bufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }
