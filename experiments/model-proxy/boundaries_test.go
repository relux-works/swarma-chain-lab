package modelproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Admin authorization is exercised at the handler's verified-peer boundary;
// these macOS controls do not claim Linux SO_PEERCRED runtime qualification.
func TestAdminBoundary(t *testing.T) {
	h := fixture(t)
	b := h.b
	b.SlotID = strings.Repeat("d", 64)
	send := func(raw []byte, peer bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://local/v1/registry", strings.NewReader(string(raw)))
		if peer {
			r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		}
		w := httptest.NewRecorder()
		h.s.adminHandler(w, r)
		return w
	}
	raw := canonical(adminRequest{1, "prepare", b})
	if w := send(raw, false); w.Code != 403 {
		t.Fatal("unverified peer accepted")
	}
	if _, e := h.s.Status(b.SlotID); e == nil {
		t.Fatal("forbidden peer wrote registry")
	}
	for _, bad := range [][]byte{append(raw, ' '), []byte(strings.Replace(string(raw), `"op":"prepare"`, `"op":"prepare","op":"activate"`, 1)), []byte(strings.Replace(string(raw), `"v":1`, `"v":2`, 1))} {
		if w := send(bad, true); w.Code != 400 {
			t.Fatal("invalid admin accepted")
		}
	}
	w := send(raw, true)
	var out adminResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.OK || out.Credential == nil || !out.Credential.Valid() {
		t.Fatal("admin valid neighbor refused")
	}
	if h.sendAs(request(false), b.SlotID, out.Credential.Bearer).Code != 401 {
		t.Fatal("prepare activated bearer")
	}
	if w = send(canonical(adminRequest{1, "activate", b}), true); !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatal("activation refused")
	}
	if h.sendAs(request(false), b.SlotID, out.Credential.Bearer).Code != 200 {
		t.Fatal("activated neighbor refused")
	}
	if w = send(canonical(adminRequest{1, "revoke", b}), true); !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatal("revocation refused")
	}
	if h.sendAs(request(false), b.SlotID, out.Credential.Bearer).Code != 401 {
		t.Fatal("revoked admin bearer forwarded")
	}
	if !supportsPeers() {
		if _, e := (Client{SocketPath: "/unavailable/sock"}).Prepare(context.Background(), b); e == nil || e.Error() != "LINUX_ONLY" {
			t.Fatal("non-Linux peer fallback")
		}
	}
}

// Synthetic key files require exact mode, owner, regular single-link storage,
// and no symlink components; refusals never echo the key marker or input path.
func TestPrivateFiles(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "key")
	if e = os.WriteFile(path, []byte(keyMarker), 0400); e != nil {
		t.Fatal(e)
	}
	raw, e := ReadPrivateFile(path, 0400, 4096)
	if e != nil || string(raw) != keyMarker {
		t.Fatal("private valid neighbor refused")
	}
	reject := func(p string) {
		t.Helper()
		b, e := ReadPrivateFile(p, 0400, 4096)
		if e == nil || len(b) != 0 || e.Error() != "PRIVATE_FILE" {
			t.Fatal("private file failed open")
		}
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	reject(path)
	os.Chmod(path, 0400)
	link := filepath.Join(root, "link")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	reject(link)
	hard := filepath.Join(root, "hard")
	if e = os.Link(path, hard); e != nil {
		t.Fatal(e)
	}
	reject(path)
	os.Remove(hard)
	if e = os.WriteFile(filepath.Join(root, "empty"), nil, 0400); e != nil {
		t.Fatal(e)
	}
	reject(filepath.Join(root, "empty"))
	if e = os.WriteFile(filepath.Join(root, "large"), []byte(strings.Repeat("x", 4097)), 0400); e != nil {
		t.Fatal(e)
	}
	reject(filepath.Join(root, "large"))
	if _, e = ReadPrivateFile(path, 0400, 4096); e != nil {
		t.Fatal("valid neighbor after negative cases")
	}
}

// An expiry step while the upstream is blocked cancels locally and retains the
// reservation. This tests own-clock cancellation, not remote billing cessation.
func TestExpiryInFlight(t *testing.T) {
	h := fixture(t)
	h.s.cfg.Timeout = 20 * time.Second
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	h.response = func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- h.send(request(false)) }()
	<-entered
	h.now.Store(h.b.NotAfter)
	select {
	case w := <-done:
		if w.Code != 502 {
			t.Fatal("expired inflight completed")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("own expiry did not cancel")
	}
	if v := h.status(t); v.Exposure != (Counts{100, 10, 1, 230}) || v.InFlight {
		t.Fatal("expiry refunded exposure")
	}
}

// A broken downstream stream cannot erase possibly incurred upstream usage.
type failingWriter struct{ header http.Header }

func (w *failingWriter) Header() http.Header       { return w.header }
func (w *failingWriter) WriteHeader(int)           {}
func (w *failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestClientDisconnect(t *testing.T) {
	h := fixture(t)
	h.response = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sse(7, 3))
	}
	r := httptest.NewRequest("POST", "https://proxy.example/slots/"+h.b.SlotID+"/v1/messages", strings.NewReader(request(true)))
	r.Header.Set("Authorization", "Bearer "+string(h.cred.Bearer))
	h.s.ServeHTTP(&failingWriter{make(http.Header)}, r)
	if v := h.status(t); v.Exposure != (Counts{100, 10, 1, 230}) || v.InFlight {
		t.Fatal("disconnect refunded exposure")
	}
}

// No redirect is followed with the proxy credential, and no ambiguous upstream
// response is retried. The valid fixture tests ordinary generation separately.
func TestRedirectNoRetry(t *testing.T) {
	h := fixture(t)
	h.response = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://untrusted.invalid/steal", 307)
	}
	if w := h.send(request(false)); w.Code != 502 || h.calls.Load() != 1 || h.status(t).Exposure != (Counts{100, 10, 1, 230}) {
		t.Fatal("redirect/retry/refund escaped")
	}
}

// The actual child exits immediately after the durable reserve or settlement.
// Recovery must retain exactly one charge and never resend generation itself.
func TestCrashRecovery(t *testing.T) {
	for _, phase := range []string{"reserved", "settled"} {
		t.Run(phase, func(t *testing.T) {
			h := fixture(t)
			h.s.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestProxyCrashChild$")
			cmd.Env = append(os.Environ(), "MODEL_PROXY_TEST_ROOT="+h.c.StateDir, "MODEL_PROXY_TEST_UPSTREAM="+h.c.Upstream, "MODEL_PROXY_TEST_PHASE="+phase)
			out, e := cmd.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || exit.ExitCode() != 73 {
				t.Fatalf("child did not reach crash boundary: %v %s", e, out)
			}
			h.reopen(t)
			want := Counts{100, 10, 1, 230}
			if phase == "settled" {
				want = Counts{7, 3, 1, 23}
			}
			if v := h.status(t); v.Exposure != want || v.InFlight || h.calls.Load() != 0 {
				t.Fatal("crash lost/duplicated charge", v)
			}
			if h.send(request(false)).Code != 200 {
				t.Fatal("post-crash valid neighbor")
			}
		})
	}
}
func TestProxyCrashChild(t *testing.T) {
	root := os.Getenv("MODEL_PROXY_TEST_ROOT")
	if root == "" {
		t.Skip("subprocess boundary helper")
	}
	s, e := New(Config{StateDir: root, Endpoint: Endpoint{"https://proxy.example", strings.Repeat("a", 64)}, Upstream: os.Getenv("MODEL_PROXY_TEST_UPSTREAM"), APIKey: keyMarker, Models: map[string]Model{modelID: {100, 2, 3, "fixture model bound, not production pricing"}}, Now: func() time.Time { return time.Unix(100, 0) }})
	if e != nil {
		t.Fatal(e)
	}
	id := strings.Repeat("b", 64)
	r := s.state.Records[id]
	p, e := (Messages{}).Parse([]byte(request(false)))
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = s.reserve(context.Background(), id, r.Bearer, p)
	if e != nil {
		t.Fatal(e)
	}
	if os.Getenv("MODEL_PROXY_TEST_PHASE") == "settled" {
		u := Usage{7, 3}
		if e = s.settle(id, &u); e != nil {
			t.Fatal(e)
		}
	}
	os.Exit(73)
}

// Private carriers redact all fmt verbs, including invalid-verb diagnostics;
// malformed origin delimiters cannot become a different request target.
func TestSecretAndOrigin(t *testing.T) {
	c := Credential{Bearer: Secret(keyMarker), Endpoint: Endpoint{URL: "https://proxy.example", CertSHA256: strings.Repeat("a", 64)}}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, value := range []any{Secret(keyMarker), c} {
			if strings.Contains(fmt.Sprintf(format, value), keyMarker) {
				t.Fatal("private formatting leaked")
			}
		}
	}
	for _, raw := range []string{"https://proxy.example?", "https://proxy.example#", "https://proxy.example/path", "https://proxy.example/", "https://PROXY.example", "https://user@proxy.example", "http://proxy.example"} {
		if validOrigin(raw) {
			t.Fatal("noncanonical origin accepted")
		}
	}
	if !validOrigin("https://proxy.example:8443") || !validOrigin("https://proxy.example") {
		t.Fatal("valid origin refused")
	}
}

// At uint64 boundaries a wrapped reservation must not appear below a cap.
// Each isolated arithmetic case has an empty-exposure valid control afterward.
func TestReservationOverflow(t *testing.T) {
	for _, kind := range []string{"input", "output", "requests", "cost"} {
		t.Run(kind, func(t *testing.T) {
			h := fixture(t)
			top := ^uint64(0)
			h.s.mu.Lock()
			r := h.s.state.Records[h.b.SlotID]
			r.Binding.Caps = Caps{top, top, top, 10, top, 0}
			switch kind {
			case "input":
				r.Exposure.Input = top - 99
			case "output":
				r.Exposure.Output = top - 9
			case "requests":
				r.Exposure.Requests = top
			case "cost":
				r.Exposure.Cost = top - 229
			}
			before := r.Exposure
			h.s.state.Records[h.b.SlotID] = r
			h.s.mu.Unlock()
			if w := h.send(request(false)); w.Code != 403 || h.calls.Load() != 0 || h.status(t).Exposure != before {
				t.Fatal("overflow reservation reached upstream or changed exposure")
			}
			h.s.mu.Lock()
			r.Exposure = Counts{}
			h.s.state.Records[h.b.SlotID] = r
			h.s.mu.Unlock()
			if h.send(request(false)).Code != 200 {
				t.Fatal("overflow valid neighbor refused")
			}
		})
	}
}
