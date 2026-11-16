package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

type vector struct {
	Name           string `json:"name"`
	Parent         string `json:"parent"`
	Child          string `json:"child"`
	ParentContract string `json:"parent_contract"`
	ChildContract  string `json:"child_contract"`
	Request        string `json:"request"`
	Policy         string `json:"policy"`
	Statement      string `json:"statement"`
	At             int64  `json:"at"`
	Names          []struct {
		Name         string      `json:"name"`
		Registration check.Point `json:"registration"`
		Value        string      `json:"value"`
		Height       int64       `json:"height"`
		BlockHash    string      `json:"blockhash"`
	} `json:"names"`
}

func fixture(t *testing.T) vector { return fixtureNamed(t, "positive-same-owner") }
func fixtureNamed(t *testing.T, name string) vector {
	t.Helper()
	b, e := os.ReadFile("../../testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Vectors []vector `json:"vectors"`
	}
	if json.Unmarshal(b, &c) != nil {
		t.Fatal("corpus")
	}
	for _, v := range c.Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("missing vector %s", name)
	return vector{}
}
func put(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func setup(t *testing.T) (*Service, Request, *atomic.Int32) {
	t.Helper()
	return setupForVector(t, fixture(t))
}
func setupForVector(t *testing.T, v vector) (*Service, Request, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	pub, e := Keygen(keyPath)
	if e != nil {
		t.Fatal(e)
	}
	var st check.Statement
	_ = json.Unmarshal([]byte(v.Statement), &st)
	calls := new(atomic.Int32)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var q struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		var value any
		switch q.Method {
		case "getblockchaininfo":
			value = map[string]any{"chain": "regtest", "blocks": st.TipHeight, "bestblockhash": st.TipHash}
		case "getblockhash":
			value = st.TipHash
		case "name_show", "name_history":
			n := map[string]any{"name": "id/certifier", "value": "{\"swarma\":{\"notary\":{\"attest\":\"" + pub + "\"}}}", "txid": strings.Repeat("11", 32), "vout": 0, "height": 1, "expires_in": 1000, "expired": false, "name_encoding": "utf8", "value_encoding": "utf8"}
			var name string
			if len(q.Params) > 0 {
				_ = json.Unmarshal(q.Params[0], &name)
			}
			for _, obs := range v.Names {
				if obs.Name == name {
					n["name"] = obs.Name
					n["value"] = obs.Value
					n["txid"] = obs.Registration.TxID
					n["vout"] = obs.Registration.Vout
				}
			}
			value = n
			if q.Method == "name_history" {
				value = []any{n}
			}
		default:
			t.Error("unexpected RPC")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": value, "error": nil})
	}))
	t.Cleanup(rpc.Close)
	put(t, filepath.Join(dir, "credential"), []byte("test-user:test-password"))
	put(t, filepath.Join(dir, "policy"), []byte(v.Policy))
	c := Config{Listen: "127.0.0.1:0", KeyFile: keyPath, RPCEndpoint: rpc.URL, RPCCredentialFile: filepath.Join(dir, "credential"), DeploymentPolicyFile: filepath.Join(dir, "policy"), Limits: Limits{65536, 100, 100, 1000, 2}}
	path := filepath.Join(dir, "config")
	put(t, path, encode(t, c))
	s, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	s.now = func() time.Time { return time.Unix(v.At, 0) }
	req := Request{Parent: json.RawMessage(v.Parent), Child: json.RawMessage(v.Child), ParentContract: json.RawMessage(v.ParentContract), ChildContract: json.RawMessage(v.ChildContract), Request: json.RawMessage(v.Request), PolicyReference: s.reference, Statement: json.RawMessage(v.Statement)}
	return s, req, calls
}
func submit(t *testing.T, s *Service, raw []byte) (int, Response, []byte) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/attest", bytes.NewReader(raw))
	s.ServeHTTP(w, r)
	var result Response
	if json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("response JSON")
	}
	return w.Code, result, w.Body.Bytes()
}

// Generated files are exclusive owner-only regular files. Neither success nor
// failures expose their secret bytes; mode/symlink violations cannot load a key.
func TestKeyCustody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	pub, e := Keygen(path)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 || len(pub) != 64 || strings.Contains(pub, hex.EncodeToString(raw[len(keyHeader):])) {
		t.Fatal("key custody")
	}
	again, e := Keygen(path)
	after, _ := os.ReadFile(path)
	if e == nil || again != "" || !bytes.Equal(raw, after) || strings.Contains(e.Error(), hex.EncodeToString(raw[len(keyHeader):])) {
		t.Fatal("exclusive generation failed")
	}
	key, e := loadKey(path)
	if e != nil {
		t.Fatal(e)
	}
	key.Zero()
	if os.Chmod(path, 0644) != nil {
		t.Fatal("chmod")
	}
	if _, e = loadKey(path); e == nil {
		t.Fatal("insecure mode")
	}
	if os.Chmod(path, 0600) != nil {
		t.Fatal("chmod")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink")
	}
	if _, e = loadKey(link); e == nil {
		t.Fatal("symlink accepted")
	}
}

// The real checker, generated key, envelope verifier and anchor helper all run.
// A deliberately invalid child must retain the exact refusal and never invoke
// the signing function, even though valid node reads and a key are available.
func TestRefusalNeverSigns(t *testing.T) {
	s, req, _ := setup(t)
	original := s.sign
	count := 0
	s.sign = func(d []byte) (string, error) { count++; return original(d) }
	status, result, _ := submit(t, s, encode(t, req))
	if status != 200 || result.Decision != "ATTEST" || count != 1 {
		t.Fatalf("positive %d %s signs=%d", status, result.Decision, count)
	}
	var signed struct {
		Attestation check.Attestation `json:"attestation"`
		Signature   string            `json:"signature"`
	}
	if json.Unmarshal(result.SignedAttestation, &signed) != nil {
		t.Fatal("envelope")
	}
	frame, e := hex.DecodeString(result.AnchorFrame)
	if e != nil || len(frame) != 72 || !bytes.Equal(frame[:7], []byte{0x6a, 3, 0x53, 0x4c, 4, 0x42, 1}) {
		t.Fatal("anchor")
	}
	count = 0
	req.Child = json.RawMessage(`{}`)
	status, result, raw := submit(t, s, encode(t, req))
	if status != 422 || result.Decision != "GRANT_ENCODING" || count != 0 || len(result.SignedAttestation) != 0 || result.AnchorFrame != "" {
		t.Fatalf("refusal %d %s signs=%d", status, result.Decision, count)
	}
	secret, _ := os.ReadFile(s.config.KeyFile)
	if bytes.Contains(raw, secret[len(keyHeader):]) || bytes.Contains(raw, []byte(hex.EncodeToString(secret[len(keyHeader):]))) {
		t.Fatal("secret response")
	}
}

// Size, rate, concurrency, policy substitution, strict JSON and endpoint bounds
// all refuse without producing signed material. The nearby valid control is in
// TestRefusalNeverSigns; these checks never claim real network timing evidence.
func TestRequestBounds(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		s, _, calls := setup(t)
		s.config.Limits.RequestBytes = 1024
		status, r, _ := submit(t, s, []byte(strings.Repeat(" ", 1025)))
		if status != 413 || r.Decision != "REQUEST_TOO_LARGE" || calls.Load() != 0 {
			t.Fatal(status, r.Decision)
		}
	})
	t.Run("rate", func(t *testing.T) {
		s, req, calls := setup(t)
		s.tokens = 0
		status, r, _ := submit(t, s, encode(t, req))
		if status != 429 || r.Decision != "RATE_LIMIT" || calls.Load() != 0 {
			t.Fatal(status, r.Decision)
		}
	})
	t.Run("busy", func(t *testing.T) {
		s, req, calls := setup(t)
		s.slots <- struct{}{}
		s.slots <- struct{}{}
		status, r, _ := submit(t, s, encode(t, req))
		if status != 503 || r.Decision != "BUSY" || calls.Load() != 0 {
			t.Fatal(status, r.Decision)
		}
	})
	t.Run("policy", func(t *testing.T) {
		s, req, calls := setup(t)
		req.PolicyReference = strings.Repeat("0", 64)
		_, r, _ := submit(t, s, encode(t, req))
		if r.Decision != "POLICY_REFERENCE" || calls.Load() != 0 || len(r.SignedAttestation) > 0 {
			t.Fatal(r.Decision)
		}
	})
	t.Run("json", func(t *testing.T) {
		s, _, calls := setup(t)
		for _, raw := range []string{`{"offline_name_fixture":"x"}`, `{"parent":{},"parent":{}}`, `{"Parent":{}}`, `{} {}`, strings.Repeat("[", 65) + strings.Repeat("]", 65)} {
			status, r, _ := submit(t, s, []byte(raw))
			if status != 400 || r.Decision != "REQUEST_INVALID" {
				t.Fatal(status, r.Decision)
			}
		}
		if calls.Load() != 0 {
			t.Fatal("invalid JSON did I/O")
		}
	})
	t.Run("routes", func(t *testing.T) {
		s, _, calls := setup(t)
		for _, v := range [][2]string{{"GET", "/v1/attest"}, {"POST", "/health"}, {"POST", "/v1/attest?x=1"}} {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(v[0], v[1], nil))
			if w.Code == 200 {
				t.Fatal("extra endpoint")
			}
		}
		if calls.Load() != 0 {
			t.Fatal("route did I/O")
		}
	})
}

// Config cannot enable file-backed name observations or accept duplicate,
// unknown, aliased, trailing, null or missing mandatory fields.
func TestServeCannotSelectOfflineFixture(t *testing.T) {
	s, _, _ := setup(t)
	raw := encode(t, s.config)
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"listen":`), []byte(`"listen":"127.0.0.1:1","listen":`), 1), bytes.Replace(raw, []byte(`"request_bytes":`), []byte(`"unknown":1,"request_bytes":`), 1), bytes.Replace(raw, []byte(`"listen":`), []byte(`"offline_name_fixture":"names.json","listen":`), 1), bytes.Replace(raw, []byte(`"listen":`), []byte(`"Listen":`), 1), append(append([]byte{}, raw...), []byte(` {}`)...), []byte(`null`), []byte(`{}`)} {
		path := filepath.Join(t.TempDir(), "config")
		put(t, path, bad)
		got, e := Load(path)
		if e == nil {
			got.Close()
			t.Fatal("invalid config accepted")
		}
	}
}

// A canceled/expired request cannot reach signing; no RPC diagnostics escape.
func TestDeadlineNeverSigns(t *testing.T) {
	s, req, _ := setup(t)
	count := 0
	s.sign = func([]byte) (string, error) { count++; return "", nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, e := s.attest(ctx, req)
	if e == nil || e.Error() != "NODE_RPC_FAILURE" || count != 0 || len(result.SignedAttestation) != 0 {
		t.Fatal("canceled request signed")
	}
}

// A slow body is cut off by the real HTTP server's read deadline; a hanging
// RPC is cut off by the request context. Neither attempt reaches the signer.
func TestNetworkTimeBounds(t *testing.T) {
	t.Run("slow-body", func(t *testing.T) {
		s, _, _ := setup(t)
		s.config.Limits.TimeoutMS = 50
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		exited := make(chan error, 1)
		go func() { exited <- s.runListener(ctx, listener) }()
		defer func() {
			cancel()
			if e := <-exited; e != nil {
				t.Error(e)
			}
		}()
		conn, e := net.Dial("tcp", listener.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		if e = conn.SetDeadline(time.Now().Add(time.Second)); e != nil {
			t.Fatal(e)
		}
		_, e = io.WriteString(conn, "POST /v1/attest HTTP/1.1\r\nHost: localhost\r\nContent-Length: 60000\r\n\r\n{")
		if e != nil {
			t.Fatal(e)
		}
		response, e := http.ReadResponse(bufio.NewReader(conn), nil)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		raw, e := io.ReadAll(response.Body)
		if e != nil || response.StatusCode != 400 || !bytes.Contains(raw, []byte(`"decision":"REQUEST_READ"`)) {
			t.Fatal("slow body did not refuse")
		}
	})
	t.Run("hanging-rpc", func(t *testing.T) {
		s, req, _ := setup(t)
		s.config.Limits.TimeoutMS = 50
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		defer server.Close()
		defer close(release)
		node, e := check.NewNodeNameReader(server.URL, s.config.RPCCredentialFile)
		if e != nil {
			t.Fatal(e)
		}
		s.node = node
		signs := 0
		s.sign = func([]byte) (string, error) { signs++; return "", nil }
		_, result, _ := submit(t, s, encode(t, req))
		if result.Decision != "NODE_RPC_FAILURE" || signs != 0 || len(result.SignedAttestation) > 0 {
			t.Fatal("RPC deadline did not refuse")
		}
	})
}

// Shutdown must retain key validity until an active signature returns, refuse
// new handlers while draining, and leave no handler running after Close.
func TestShutdownDrainsBeforeKeyClear(t *testing.T) {
	s, req, _ := setup(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan int, 1)
	original := s.sign
	s.sign = func(d []byte) (string, error) { close(entered); <-release; return original(d) }
	raw := encode(t, req)
	go func() {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("POST", "/v1/attest", bytes.NewReader(raw)))
		result <- w.Code
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("signer not reached")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	// Observe the closed gate without a timing assumption before releasing work.
	for {
		s.lifecycle.Lock()
		closing := s.closing
		s.lifecycle.Unlock()
		if closing {
			break
		}
		runtime.Gosched()
	}
	select {
	case <-closed:
		t.Fatal("key cleared with active signer")
	default:
	}
	status, r, _ := submit(t, s, raw)
	if status != 503 || r.Decision != "SHUTDOWN" {
		t.Fatal("shutdown accepted request")
	}
	close(release)
	if code := <-result; code != 200 {
		t.Fatal("active signer lost key")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain")
	}
}

// Each documented configured limit accepts both boundary values and rejects
// the nearest outside values. Listener binding stays confined to loopback.
func TestConfigLimitRanges(t *testing.T) {
	s, _, _ := setup(t)
	base := s.config
	for _, tc := range []struct {
		name     string
		min, max int
		set      func(*Config, int)
	}{
		{"bytes", 1024, 1048576, func(c *Config, v int) { c.Limits.RequestBytes = int64(v) }},
		{"rate", 1, 100, func(c *Config, v int) { c.Limits.RequestsPerSecond = v }},
		{"burst", 1, 100, func(c *Config, v int) { c.Limits.Burst = v }},
		{"timeout", 10, 30000, func(c *Config, v int) { c.Limits.TimeoutMS = v }},
		{"concurrent", 1, 32, func(c *Config, v int) { c.Limits.Concurrent = v }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range []int{tc.min - 1, tc.min, tc.max, tc.max + 1} {
				c := base
				tc.set(&c, v)
				if validConfig(c) != (v >= tc.min && v <= tc.max) {
					t.Fatal("limit", v)
				}
			}
		})
	}
	for _, address := range []string{":8080", "0.0.0.0:8080", "192.0.2.1:8080", "localhost:8080"} {
		c := base
		c.Listen = address
		if validConfig(c) {
			t.Fatal("unconfined listen")
		}
	}
}
