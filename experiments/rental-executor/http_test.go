package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real Unix listeners enforce private sockets and distinct admin/claim routes;
// revoked tokens refuse and malformed attempts still create sanitized audit.
func TestTrackBUnix(t *testing.T) {
	b, e := OpenTrackB(rootDir(t), "regtest", prizes())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	root := rootDir(t)
	serve := func(name string, admin bool) *http.Client {
		p := filepath.Join(root, name)
		l, e := ListenUnix(p)
		if e != nil {
			t.Fatal(e)
		}
		i, _ := os.Stat(p)
		if i.Mode().Perm() != 0600 {
			t.Fatal("socket permissions")
		}
		server := HTTPServer(TrackBHandler(b, admin))
		done := make(chan struct{})
		go func() { defer close(done); _ = server.Serve(l) }()
		t.Cleanup(func() { _ = server.Close(); <-done })
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", p)
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport}
	}
	admin := serve("admin.sock", true)
	claim := serve("claim.sock", false)
	call := func(c *http.Client, path, body string, want int) map[string]any {
		t.Helper()
		resp, e := c.Post("http://unix"+path, "application/json", strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("HTTP %d want %d", resp.StatusCode, want)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache")
		}
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil {
			t.Fatal("JSON")
		}
		return v
	}
	slot := strings.Repeat("1", 64)
	mint := call(admin, "/mint", `{"slot":"`+slot+`"}`, 200)
	token, ok := mint["token"].(string)
	if !ok {
		t.Fatal("missing token")
	}
	q := string(canonical(map[string]string{"slot": slot, "token": token}))
	got := call(claim, "/claim", q, 200)
	if got["private_key"] != prizes()[slot] {
		t.Fatal("key mismatch")
	}
	call(claim, "/mint", `{"slot":"`+slot+`"}`, 400)
	call(admin, "/claim", q, 400)
	call(claim, "/claim", `{"slot":null,"token":"x"}`, 400)
	call(admin, "/revoke", `{"slot":"`+slot+`"}`, 200)
	call(claim, "/claim", q, 403)
	raw, _ := b.store.read("trackb.json")
	if bytes.Contains(raw, []byte(token)) {
		t.Fatal("token in audit")
	}
	if _, e := ListenUnix(filepath.Join(root, "admin.sock")); e == nil {
		t.Fatal("existing socket replaced")
	}
}

// Claim throttling returns 429, invalid tokens 403, persistence failure 503;
// valid claims are not blocked by the invalid-token allowance.
func TestTrackBHTTPRefusalStatus(t *testing.T) {
	b, e := OpenTrackB(rootDir(t), "regtest", prizes())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	slot := strings.Repeat("1", 64)
	token, e := b.Mint(slot)
	if e != nil {
		t.Fatal(e)
	}
	h := TrackBHandler(b, false)
	call := func(token string, want int) {
		t.Helper()
		r := httptest.NewRequest("POST", "/claim", bytes.NewReader(canonical(map[string]string{"slot": slot, "token": token})))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal("claim HTTP status", w.Code)
		}
	}
	for i := 0; i <= InvalidClaimsPerWindow; i++ {
		want := 403
		if i == InvalidClaimsPerWindow {
			want = 429
		}
		call(strings.Repeat("0", 64), want)
	}
	call(token, 200)
	b.store.poison = true
	call(token, 503)
}
