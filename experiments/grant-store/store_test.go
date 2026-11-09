package grantstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type lab struct {
	t                               *testing.T
	mu                              sync.RWMutex
	s                               *Server
	http                            *httptest.Server
	writer, reader, other, outsider *nostr.PrivKey
	now                             int64
}

func newLab(t *testing.T) *lab {
	t.Helper()
	l := &lab{t: t, now: 500}
	for _, p := range []**nostr.PrivKey{&l.writer, &l.reader, &l.other, &l.outsider} {
		k, e := nostr.GeneratePrivKey()
		if e != nil {
			t.Fatal(e)
		}
		*p = k
	}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	l.http = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.mu.RLock(); defer l.mu.RUnlock(); l.s.ServeHTTP(w, r) }))
	cfg := Config{Root: root, PublicURL: "http://" + l.http.Listener.Addr().String(), Writers: []string{l.writer.PubKeyHex(), l.other.PubKeyHex()}, MaxBlobBytes: 1024, MaxBlobs: 128, MaxTotalBytes: 65536}
	var e error
	l.s, e = Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	l.s.now = func() time.Time { return time.Unix(l.now, 0) }
	l.http.Start()
	t.Cleanup(func() { l.http.Close(); l.s.Close() })
	return l
}
func (l *lab) reopen() {
	l.t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	cfg := l.s.cfg
	l.s.Close()
	s, e := Open(cfg)
	if e != nil {
		l.t.Fatal(e)
	}
	l.s = s
	l.s.now = func() time.Time { return time.Unix(l.now, 0) }
}
func (l *lab) client(k *nostr.PrivKey) *Client {
	return &Client{Signer: k, Now: func() time.Time { return time.Unix(l.now, 0) }, MaxBytes: 1024}
}
func (l *lab) auth(k *nostr.PrivKey, action, hash string, readers ...string) string {
	l.t.Helper()
	h, e := AuthHeader(k, action, hash, "127.0.0.1", readers, time.Unix(l.now, 0))
	if e != nil {
		l.t.Fatal(e)
	}
	return h
}
func (l *lab) do(method, path, auth string, b []byte) (int, []byte, http.Header) {
	l.t.Helper()
	r, e := http.NewRequest(method, l.http.URL+path, bytes.NewReader(b))
	if e != nil {
		l.t.Fatal(e)
	}
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	res, e := l.http.Client().Do(r)
	if e != nil {
		l.t.Fatal(e)
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(res.Body)
	if e != nil {
		l.t.Fatal(e)
	}
	return res.StatusCode, raw, res.Header
}
func (l *lab) put(b string, readers ...string) string {
	l.t.Helper()
	d, e := l.client(l.writer).Put(context.Background(), l.http.URL, []byte(b), readers)
	if e != nil {
		l.t.Fatal(e)
	}
	return d.SHA256
}
func (l *lab) read(k *nostr.PrivKey, h, want string) {
	l.t.Helper()
	b, e := l.client(k).Get(context.Background(), l.http.URL, h)
	if e != nil || string(b) != want {
		l.t.Fatalf("valid GET failed: %v", e)
	}
}
func editAuth(t *testing.T, h string, k *nostr.PrivKey, edit func(*nostr.Event)) string {
	t.Helper()
	raw, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(h, "Nostr "))
	if e != nil {
		t.Fatal(e)
	}
	ev, e := nostr.ParseEvent(raw)
	if e != nil {
		t.Fatal(e)
	}
	edit(ev)
	if e = k.SignEvent(ev); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(ev)
	return "Nostr " + base64.RawURLEncoding.EncodeToString(b)
}
func rawAuth(t *testing.T, h string, edit func([]byte) []byte) string {
	t.Helper()
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(h, "Nostr "))
	if e != nil {
		t.Fatal(e)
	}
	return "Nostr " + base64.RawURLEncoding.EncodeToString(edit(b))
}
func tag(ev *nostr.Event, name, value string) {
	for i := range ev.Tags {
		if ev.Tags[i][0] == name {
			ev.Tags[i][1] = value
			return
		}
	}
}
func untag(ev *nostr.Event, name string) {
	tags := [][]string{}
	for _, v := range ev.Tags {
		if v[0] != name {
			tags = append(tags, v)
		}
	}
	ev.Tags = tags
}

// Each malformed or unauthorized upload returns its exact rejection without a
// visible blob; the same fixture then accepts an authorized put and reader GET.
func TestUploadControls(t *testing.T) {
	names := []string{"no_auth", "nonwriter", "wrong_hash", "expired", "future", "wrong_action", "wrong_kind", "missing_x", "missing_expiry", "bad_id", "bad_sig", "duplicate_json", "unknown_json", "trailing_json", "duplicate_t", "duplicate_expiry", "duplicate_p", "invalid_reader", "wrong_server", "invalid_server", "oversized_auth", "oversized_body", "excess_lifetime", "empty_content", "bad_base64", "duplicate_x"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			l := newLab(t)
			b := []byte("denied")
			h := l.auth(l.writer, "upload", Hash(b), l.reader.PubKeyHex())
			want := 401
			edit := func(f func(*nostr.Event)) { h = editAuth(t, h, l.writer, f) }
			switch name {
			case "no_auth":
				h = ""
			case "nonwriter":
				h = l.auth(l.outsider, "upload", Hash(b))
				want = 403
			case "wrong_hash":
				edit(func(e *nostr.Event) { tag(e, "x", Hash([]byte("other"))) })
			case "expired":
				edit(func(e *nostr.Event) { e.CreatedAt = 200; tag(e, "expiration", "500") })
			case "future":
				edit(func(e *nostr.Event) { e.CreatedAt = 531 })
			case "wrong_action":
				edit(func(e *nostr.Event) { tag(e, "t", "get") })
			case "wrong_kind":
				edit(func(e *nostr.Event) { e.Kind = 1 })
			case "missing_x":
				edit(func(e *nostr.Event) { untag(e, "x") })
			case "missing_expiry":
				edit(func(e *nostr.Event) { untag(e, "expiration") })
			case "bad_id", "bad_sig":
				h = rawAuth(t, h, func(b []byte) []byte {
					var m map[string]any
					_ = json.Unmarshal(b, &m)
					if name == "bad_id" {
						m["id"] = strings.Repeat("0", 64)
					} else {
						m["sig"] = strings.Repeat("0", 128)
					}
					v, _ := json.Marshal(m)
					return v
				})
			case "duplicate_json":
				h = rawAuth(t, h, func(b []byte) []byte { return append([]byte(`{"kind":24242,`), b[1:]...) })
			case "unknown_json":
				h = rawAuth(t, h, func(b []byte) []byte { return append([]byte(`{"unknown":1,`), b[1:]...) })
			case "trailing_json":
				h = rawAuth(t, h, func(b []byte) []byte { return append(b, []byte(` {}`)...) })
			case "duplicate_t":
				edit(func(e *nostr.Event) { e.Tags = append(e.Tags, []string{"t", "upload"}) })
			case "duplicate_expiry":
				edit(func(e *nostr.Event) { e.Tags = append(e.Tags, []string{"expiration", "800"}) })
			case "duplicate_p":
				edit(func(e *nostr.Event) { e.Tags = append(e.Tags, []string{"p", l.reader.PubKeyHex()}) })
			case "invalid_reader":
				edit(func(e *nostr.Event) { tag(e, "p", strings.Repeat("0", 64)) })
			case "wrong_server":
				edit(func(e *nostr.Event) { tag(e, "server", "elsewhere.invalid") })
			case "invalid_server":
				edit(func(e *nostr.Event) { tag(e, "server", "http://127.0.0.1") })
			case "oversized_auth":
				h = "Nostr " + strings.Repeat("A", 12000)
			case "oversized_body":
				b = bytes.Repeat([]byte("a"), 1025)
				h = l.auth(l.writer, "upload", Hash(b))
				want = 413
			case "excess_lifetime":
				edit(func(e *nostr.Event) { tag(e, "expiration", "801") })
			case "empty_content":
				edit(func(e *nostr.Event) { e.Content = "" })
			case "bad_base64":
				h = "Nostr !"
			case "duplicate_x":
				edit(func(e *nostr.Event) { e.Tags = append(e.Tags, []string{"x", Hash(b)}) })
			}
			status, _, _ := l.do("PUT", "/upload", h, b)
			if status != want {
				t.Fatalf("rejection status=%d want=%d", status, want)
			}
			if len(l.s.blobs) != 0 || l.s.total != 0 {
				t.Fatal("rejected upload published state")
			}
			hash := l.put("valid", l.reader.PubKeyHex())
			l.read(l.reader, hash, "valid")
		})
	}
}

// Missing and forbidden blobs have identical public errors. Reader membership
// applies to each blob; only its putter can delete it or list the putter's data.
func TestReadersAndPrivateExistence(t *testing.T) {
	l := newLab(t)
	a := l.put("alpha", l.reader.PubKeyHex())
	b := l.put("beta", l.other.PubKeyHex())
	missing := Hash([]byte("absent"))
	for _, k := range []*nostr.PrivKey{nil, l.outsider} {
		var prior string
		for _, h := range []string{a, b, missing} {
			auth := ""
			want := 401
			if k != nil {
				auth = l.auth(k, "get", h)
				want = 403
			}
			status, raw, headers := l.do("GET", "/"+h, auth, nil)
			if status != want || headers.Get("Cache-Control") != "no-store" {
				t.Fatalf("private GET status=%d", status)
			}
			if prior != "" && prior != string(raw) {
				t.Fatal("existence disclosed")
			}
			prior = string(raw)
		}
	}
	status, _, _ := l.do("GET", "/"+b, l.auth(l.reader, "get", b), nil)
	if status != 403 {
		t.Fatalf("cross-blob reader status=%d", status)
	}
	l.read(l.reader, a, "alpha")
	l.read(l.writer, a, "alpha")
	l.read(l.other, b, "beta")
	for _, k := range []*nostr.PrivKey{l.reader, l.outsider} {
		status, _, _ := l.do("DELETE", "/"+a, l.auth(k, "delete", a), nil)
		if status != 403 {
			t.Fatalf("non-owner delete=%d", status)
		}
		status, _, _ = l.do("GET", "/list/"+l.writer.PubKeyHex(), l.auth(k, "list", ""), nil)
		if status != 403 {
			t.Fatalf("non-owner list=%d", status)
		}
	}
	list, e := l.client(l.writer).List(context.Background(), l.http.URL)
	if e != nil || len(list) != 2 {
		t.Fatal("owner list failed")
	}
	if e = l.client(l.writer).Delete(context.Background(), l.http.URL, a); e != nil {
		t.Fatal(e)
	}
	status, _, _ = l.do("GET", "/"+a, l.auth(l.reader, "get", a), nil)
	if status != 403 {
		t.Fatal("deleted blob remains visible")
	}
	l.read(l.other, b, "beta")
}

// Consumed upload/get/list/delete IDs remain unusable, including after opening
// the same private root again. Fresh signed requests retain blob and ACL access.
func TestReplayAndRestart(t *testing.T) {
	l := newLab(t)
	b := []byte("restart")
	hash := Hash(b)
	put := l.auth(l.writer, "upload", hash, l.reader.PubKeyHex())
	status, _, _ := l.do("PUT", "/upload", put, b)
	if status != 201 {
		t.Fatal(status)
	}
	status, _, _ = l.do("PUT", "/upload", put, b)
	if status != 401 {
		t.Fatal("upload replay accepted")
	}
	get := l.auth(l.reader, "get", hash)
	status, _, _ = l.do("GET", "/"+hash, get, nil)
	if status != 200 {
		t.Fatal(status)
	}
	l.reopen()
	status, _, _ = l.do("GET", "/"+hash, get, nil)
	if status != 401 {
		t.Fatal("GET replay accepted after restart")
	}
	status, _, _ = l.do("PUT", "/upload", put, b)
	if status != 401 {
		t.Fatal("PUT replay accepted after restart")
	}
	l.read(l.reader, hash, "restart")
	for _, v := range []struct {
		method, path, action string
		want                 int
	}{{"GET", "/list/" + l.writer.PubKeyHex(), "list", 200}, {"DELETE", "/" + hash, "delete", 204}} {
		h := ""
		if v.action == "delete" {
			h = hash
		}
		auth := l.auth(l.writer, v.action, h)
		status, _, _ = l.do(v.method, v.path, auth, nil)
		if status != v.want {
			t.Fatal(status)
		}
		l.reopen()
		status, _, _ = l.do(v.method, v.path, auth, nil)
		want := 401
		if v.action == "delete" {
			want = 403 // No current putter authorization for a missing blob.
		}
		if status != want {
			t.Fatalf("%s replay accepted", v.action)
		}
		if v.action == "delete" {
			l.put("restart", l.reader.PubKeyHex())
			status, _, _ = l.do(v.method, v.path, auth, nil)
			if status != 401 {
				t.Fatal("delete replay accepted after recreation")
			}
			l.read(l.reader, hash, "restart")
		}
	}
}

// Concurrent identical puts publish one object; a competing allowed writer or
// an ACL change cannot take over that object. Original readers remain valid.
func TestConcurrentPutsAndOwnership(t *testing.T) {
	l := newLab(t)
	b := []byte("concurrent")
	hash := Hash(b)
	headers := []string{}
	for i := 0; i < 12; i++ {
		headers = append(headers, l.auth(l.writer, "upload", hash, l.reader.PubKeyHex(), l.other.PubKeyHex()))
	}
	results := make(chan int, 12)
	var wg sync.WaitGroup
	for _, h := range headers {
		wg.Add(1)
		go func(auth string) { defer wg.Done(); s, _, _ := l.do("PUT", "/upload", auth, b); results <- s }(h)
	}
	wg.Wait()
	close(results)
	created := 0
	for s := range results {
		if s == 201 {
			created++
		} else if s != 200 {
			t.Fatalf("concurrent status=%d", s)
		}
	}
	if created != 1 || len(l.s.blobs) != 1 || l.s.total != int64(len(b)) {
		t.Fatal("duplicate publication")
	}
	for _, h := range []string{l.auth(l.other, "upload", hash, l.reader.PubKeyHex(), l.writer.PubKeyHex()), l.auth(l.writer, "upload", hash, l.outsider.PubKeyHex())} {
		s, _, _ := l.do("PUT", "/upload", h, b)
		if s != 409 {
			t.Fatalf("ownership/ACL mutation=%d", s)
		}
	}
	l.read(l.reader, hash, "concurrent")
	s, _, _ := l.do("GET", "/"+hash, l.auth(l.outsider, "get", hash), nil)
	if s != 403 {
		t.Fatal("ACL was widened")
	}
}

// Injected failures straddle publication: restart exposes either no object or
// a complete object, while the reserved event is burned in either case.
func TestStorageFailureBoundaries(t *testing.T) {
	for _, stage := range []string{"reserved", "blob_synced", "before_publish", "published"} {
		t.Run(stage, func(t *testing.T) {
			l := newLab(t)
			b := []byte("interrupted")
			hash := Hash(b)
			h := l.auth(l.writer, "upload", hash, l.reader.PubKeyHex())
			l.s.hook = func(s string) error {
				if s == stage {
					return errors.New("injected")
				}
				return nil
			}
			s, _, _ := l.do("PUT", "/upload", h, b)
			if s != 503 {
				t.Fatalf("injected error status=%d", s)
			}
			l.reopen()
			s, _, _ = l.do("PUT", "/upload", h, b)
			if s != 401 {
				t.Fatal("reserved event reused")
			}
			if stage == "published" {
				l.read(l.reader, hash, "interrupted")
			} else {
				s, _, _ = l.do("GET", "/"+hash, l.auth(l.reader, "get", hash), nil)
				if s != 403 {
					t.Fatal("partial blob visible")
				}
			}
			valid := l.put("valid")
			l.read(l.writer, valid, "valid")
		})
	}
}

// Delete failures preserve either the original complete blob or its absence;
// neither stage allows the already reserved deletion event to run twice.
func TestDeleteFailureBoundaries(t *testing.T) {
	for _, stage := range []string{"before_delete", "deleted"} {
		t.Run(stage, func(t *testing.T) {
			l := newLab(t)
			hash := l.put("delete-me", l.reader.PubKeyHex())
			h := l.auth(l.writer, "delete", hash)
			l.s.hook = func(s string) error {
				if s == stage {
					return errors.New("injected")
				}
				return nil
			}
			s, _, _ := l.do("DELETE", "/"+hash, h, nil)
			if s != 503 {
				t.Fatal(s)
			}
			l.reopen()
			s, _, _ = l.do("DELETE", "/"+hash, h, nil)
			want := 401
			if stage == "deleted" {
				want = 403
			}
			if s != want {
				t.Fatal("delete replay")
			}
			if stage == "before_delete" {
				l.read(l.reader, hash, "delete-me")
			} else {
				s, _, _ = l.do("GET", "/"+hash, l.auth(l.reader, "get", hash), nil)
				if s != 403 {
					t.Fatal("deleted content returned")
				}
				l.put("delete-me", l.reader.PubKeyHex())
				s, _, _ = l.do("DELETE", "/"+hash, h, nil)
				if s != 401 {
					t.Fatal("delete replay after recreation")
				}
				l.read(l.reader, hash, "delete-me")
			}
			valid := l.put("valid")
			l.read(l.writer, valid, "valid")
		})
	}
}

// Capacity failures leave existing data intact; expiry frees replay slots, but
// rolling the clock behind the durable high-water cannot resurrect old IDs.
func TestCapsAndClock(t *testing.T) {
	for _, cap := range []string{"count", "bytes", "replay"} {
		t.Run(cap, func(t *testing.T) {
			l := newLab(t)
			switch cap {
			case "count":
				l.s.cfg.MaxBlobs = 1
			case "bytes":
				l.s.cfg.MaxTotalBytes = 3
			case "replay":
				l.s.cfg.MaxReplay = 1
			}
			h := l.put("one")
			s, _, _ := l.do("PUT", "/upload", l.auth(l.writer, "upload", Hash([]byte("two"))), []byte("two"))
			if s != 429 || len(l.s.blobs) != 1 || l.s.total != 3 {
				t.Fatal("capacity did not reject without effects")
			}
			if cap == "replay" {
				l.now = 801
			}
			l.read(l.writer, h, "one")
		})
	}
	t.Run("clock_rollback", func(t *testing.T) {
		l := newLab(t)
		h := l.put("time")
		l.now = 801
		l.read(l.writer, h, "time")
		l.reopen()
		l.now = 500
		s, _, _ := l.do("GET", "/"+h, l.auth(l.writer, "get", h), nil)
		if s != 503 {
			t.Fatal("clock rollback accepted")
		}
		l.now = 802
		l.read(l.writer, h, "time")
	})
}

// Startup refuses corrupt or linked data/journals instead of resetting access
// state. A second process cannot share the root; valid state survives restart.
func TestStorageCorruption(t *testing.T) {
	for _, kind := range []string{"blob", "metadata", "symlink", "journal", "missing_journal", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			h := l.put("intact")
			cfg := l.s.cfg
			l.s.Close()
			p := filepath.Join(cfg.Root, h, "blob")
			var e error
			switch kind {
			case "blob":
				e = os.WriteFile(p, []byte("broken"), 0600)
			case "metadata":
				e = os.WriteFile(filepath.Join(cfg.Root, h, "metadata.json"), []byte(`{}`), 0600)
			case "symlink":
				if e = os.Remove(p); e == nil {
					e = os.Symlink(filepath.Join(cfg.Root, "replay.json"), p)
				}
			case "journal":
				e = os.WriteFile(filepath.Join(cfg.Root, "replay.json"), []byte(`{}`), 0600)
			case "missing_journal":
				e = os.Remove(filepath.Join(cfg.Root, "replay.json"))
			case "permissions":
				e = os.Chmod(p, 0644)
			}
			if e != nil {
				t.Fatal(e)
			}
			if s, e := Open(cfg); e == nil {
				s.Close()
				t.Fatal("corrupt store opened")
			}
		})
	}
	t.Run("exclusive_lock_and_valid_restart", func(t *testing.T) {
		l := newLab(t)
		h := l.put("intact")
		if s, e := Open(l.s.cfg); e == nil {
			s.Close()
			t.Fatal("second opener acquired lock")
		}
		l.reopen()
		l.read(l.writer, h, "intact")
	})
}

// Wire compatibility includes legacy auth encoding, extensions, HEAD, ranges,
// empty blobs and private cursor pagination. OPTIONS reveals only capabilities.
func TestBlossomWire(t *testing.T) {
	l := newLab(t)
	b := []byte("abcdef")
	hash := Hash(b)
	h := l.auth(l.writer, "upload", hash)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(h, "Nostr "))
	s, _, _ := l.do("PUT", "/upload", "Nostr "+base64.StdEncoding.EncodeToString(raw), b)
	if s != 201 {
		t.Fatal(s)
	}
	for _, method := range []string{"GET", "HEAD"} {
		s, b, h := l.do(method, "/"+hash+".txt", l.auth(l.writer, "get", hash), nil)
		if s != 200 || h.Get("Content-Length") != "6" || h.Get("Content-Type") != "application/octet-stream" {
			t.Fatal("HEAD/extension contract")
		}
		if method == "HEAD" && len(b) != 0 {
			t.Fatal("HEAD returned body")
		}
	}
	req, _ := http.NewRequest("GET", l.http.URL+"/"+hash, nil)
	req.Header.Set("Authorization", l.auth(l.writer, "get", hash))
	req.Header.Set("Range", "bytes=1-2")
	resp, e := l.http.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || string(got) != "bc" {
		t.Fatal("range retrieval")
	}
	empty := l.put("")
	l.read(l.writer, empty, "")
	l.put("third")
	s, b, _ = l.do("GET", "/list/"+l.writer.PubKeyHex()+"?limit=2", l.auth(l.writer, "list", ""), nil)
	var first []Descriptor
	if s != 200 || json.Unmarshal(b, &first) != nil || len(first) != 2 {
		t.Fatal("list page one")
	}
	s, b, _ = l.do("GET", "/list/"+l.writer.PubKeyHex()+"?limit=2&cursor="+first[1].SHA256, l.auth(l.writer, "list", ""), nil)
	var next []Descriptor
	if s != 200 || json.Unmarshal(b, &next) != nil || len(next) != 1 || next[0].SHA256 == first[0].SHA256 || next[0].SHA256 == first[1].SHA256 {
		t.Fatal("list page two")
	}
	s, _, headers := l.do("OPTIONS", "/upload", "", nil)
	if s != 204 || headers.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("preflight")
	}
}

// A hostile server cannot make the client return corrupt/oversized bytes or
// forward signed credentials through a redirect; a valid hash still succeeds.
func TestClientHostileResponses(t *testing.T) {
	for _, kind := range []string{"hash", "oversize", "redirect", "descriptor"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			calls := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte("good")) }))
			defer target.Close()
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "hash":
					w.Write([]byte("evil"))
				case "oversize":
					w.Write(bytes.Repeat([]byte("a"), 1025))
				case "redirect":
					http.Redirect(w, r, target.URL, 307)
				case "descriptor":
					json.NewEncoder(w).Encode(Descriptor{SHA256: Hash([]byte("evil")), Size: 4, Type: "application/octet-stream"})
				}
			}))
			defer bad.Close()
			var e error
			if kind == "descriptor" {
				_, e = l.client(l.writer).Put(context.Background(), bad.URL, []byte("good"), nil)
			} else {
				_, e = l.client(l.writer).Get(context.Background(), bad.URL, Hash([]byte("good")))
			}
			if e == nil {
				t.Fatal("hostile response accepted")
			}
			if calls != 0 {
				t.Fatal("redirect forwarded authorization")
			}
			h := l.put("good")
			l.read(l.writer, h, "good")
		})
	}
}

// Changing the advertised endpoint on restart updates returned descriptors,
// while content, owner, readers and consumed authorization remain durable.
func TestRestartEndpoint(t *testing.T) {
	l := newLab(t)
	hash := l.put("moved", l.reader.PubKeyHex())
	l.http.Close()
	cfg := l.s.cfg
	l.s.Close()
	next := httptest.NewUnstartedServer(nil)
	cfg.PublicURL = "http://" + next.Listener.Addr().String()
	s, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	l.s = s
	s.now = func() time.Time { return time.Unix(l.now, 0) }
	next.Config.Handler = s
	next.Start()
	defer next.Close()
	d, e := l.client(l.writer).Put(context.Background(), next.URL, []byte("moved"), []string{l.reader.PubKeyHex()})
	if e != nil || d.URL != next.URL+"/"+hash+".bin" {
		t.Fatalf("restart descriptor: %v", e)
	}
	b, e := l.client(l.reader).Get(context.Background(), next.URL, hash)
	if e != nil || string(b) != "moved" {
		t.Fatalf("restart reader: %v", e)
	}
}

// Reusing one signed event concurrently yields one effect; competing writers
// with fresh events cannot replace the winner. Count caps hold during races.
func TestConcurrentReplayAndCap(t *testing.T) {
	for _, kind := range []string{"replay", "writers", "cap"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			if kind == "cap" {
				l.s.cfg.MaxBlobs = 1
			}
			data := [][]byte{[]byte("one"), []byte("one")}
			headers := []string{l.auth(l.writer, "upload", Hash(data[0])), l.auth(l.other, "upload", Hash(data[1]))}
			want := 409
			if kind == "replay" {
				headers[1] = headers[0]
				want = 401
			}
			if kind == "cap" {
				data[1] = []byte("two")
				headers[1] = l.auth(l.writer, "upload", Hash(data[1]))
				want = 429
			}
			start := make(chan struct{})
			out := make(chan int, 2)
			var wg sync.WaitGroup
			for i := range headers {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					s, _, _ := l.do("PUT", "/upload", headers[i], data[i])
					out <- s
				}(i)
			}
			close(start)
			wg.Wait()
			close(out)
			counts := map[int]int{}
			for s := range out {
				counts[s]++
			}
			if counts[201] != 1 || counts[want] != 1 || len(l.s.blobs) != 1 || l.s.total != 3 {
				t.Fatalf("concurrent %s verdicts=%v", kind, counts)
			}
			for h, m := range l.s.blobs {
				k := l.writer
				if m.Owner == l.other.PubKeyHex() {
					k = l.other
				}
				want := "one"
				if h == Hash([]byte("two")) {
					want = "two"
				}
				l.read(k, h, want)
			}
		})
	}
}

// The requested body cap also applies to unknown-length uploads; signed hash
// and header uniqueness checks reject neighboring malformed wire requests.
func TestWireRejections(t *testing.T) {
	for _, kind := range []string{"chunked_body", "duplicate_auth", "header_hash", "invalid_path", "list_limit", "list_cursor"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			hash := l.put("neighbor")
			method, path := "PUT", "/upload"
			data := []byte("wire")
			action, authHash := "upload", Hash(data)
			want := 401
			if kind == "chunked_body" {
				data = bytes.Repeat([]byte("x"), 1025)
				authHash = Hash(data)
				want = 413
			}
			if kind == "header_hash" {
				want = 409
			}
			if kind == "invalid_path" {
				method, path, action, authHash, want = "GET", "/"+hash+".bad/ext", "get", hash, 400
			}
			if strings.HasPrefix(kind, "list_") {
				method, path, action, authHash, want = "GET", "/list/"+l.writer.PubKeyHex(), "list", "", 400
				if kind == "list_limit" {
					path += "?limit=101"
				} else {
					path += "?cursor=" + Hash([]byte("absent"))
				}
			}
			r, e := http.NewRequest(method, l.http.URL+path, bytes.NewReader(data))
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("Authorization", l.auth(l.writer, action, authHash))
			switch kind {
			case "duplicate_auth":
				r.Header.Add("Authorization", l.auth(l.writer, action, authHash))
			case "chunked_body":
				r.ContentLength = -1
			case "header_hash":
				r.Header.Set("X-SHA-256", hash)
			}
			resp, e := l.http.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != want {
				t.Fatalf("wire %s status=%d want=%d", kind, resp.StatusCode, want)
			}
			if len(l.s.blobs) != 1 {
				t.Fatal("rejected request changed blob count")
			}
			l.read(l.writer, hash, "neighbor")
		})
	}
}

// Host scoping accepts a bare IPv6 hostname (no port) and rejects another host;
// this parsing control does not depend on the CI runner having IPv6 enabled.
func TestIPv6AuthScope(t *testing.T) {
	l := newLab(t)
	hash := Hash([]byte("ipv6"))
	h, e := AuthHeader(l.writer, "get", hash, "::1", nil, time.Unix(500, 0))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = parseAuth(h, "get", hash, "::1", 500, 30); e != nil {
		t.Fatal("IPv6 hostname refused")
	}
	if _, e = parseAuth(h, "get", hash, "::2", 500, 30); e == nil {
		t.Fatal("wrong IPv6 host accepted")
	}
	h = editAuth(t, h, l.writer, func(ev *nostr.Event) { tag(ev, "server", "localhost:1234") })
	if _, e = parseAuth(h, "get", hash, "localhost", 500, 30); e == nil {
		t.Fatal("server scope included a port")
	}
}

// Invalid bounds, insecure remote URLs and writer sets fail during Open; each
// isolated configuration also opens with the valid default neighbor.
func TestConfigBounds(t *testing.T) {
	for _, kind := range []string{"negative_blob", "excess_blob", "excess_count", "small_total", "excess_total", "excess_replay", "excess_skew", "no_writer", "duplicate_writer", "invalid_writer", "remote_http", "url_path"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			cfg := l.s.cfg
			l.s.Close()
			bad := cfg
			switch kind {
			case "negative_blob":
				bad.MaxBlobBytes = -1
			case "excess_blob":
				bad.MaxBlobBytes = 65 << 20
			case "excess_count":
				bad.MaxBlobs = 4097
			case "small_total":
				bad.MaxTotalBytes = 1
			case "excess_total":
				bad.MaxTotalBytes = (1 << 30) + 1
			case "excess_replay":
				bad.MaxReplay = 513
			case "excess_skew":
				bad.SkewSeconds = 61
			case "no_writer":
				bad.Writers = nil
			case "duplicate_writer":
				bad.Writers = []string{l.writer.PubKeyHex(), l.writer.PubKeyHex()}
			case "invalid_writer":
				bad.Writers = []string{strings.Repeat("0", 64)}
			case "remote_http":
				bad.PublicURL = "http://example.invalid"
			case "url_path":
				bad.PublicURL = l.http.URL + "/subpath"
			}
			if s, e := Open(bad); e == nil {
				s.Close()
				t.Fatal("invalid configuration opened")
			}
			s, e := Open(cfg)
			if e != nil {
				t.Fatal("valid config refused")
			}
			l.s = s
			s.now = func() time.Time { return time.Unix(l.now, 0) }
			h := l.put("valid")
			l.read(l.writer, h, "valid")
		})
	}
}
