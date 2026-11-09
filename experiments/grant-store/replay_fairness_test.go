package grantstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func replayBytes(t *testing.T, l *lab) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(l.s.cfg.Root, "replay.json"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// A stranger flood at the reviewer's global capacity of four cannot alter the
// durable journal or starve an authorized reader. Every operation checks ACLs.
func TestUnauthorizedDoesNotReserve(t *testing.T) {
	for _, kind := range []string{"upload", "get", "head", "missing_get", "cross_blob", "delete", "missing_delete", "list", "own_empty_list"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			configureReplay(l, 4, 0)
			hash := l.put("allowed", l.reader.PubKeyHex())
			method, path, action := "GET", "/"+hash, "get"
			k := l.outsider
			var body []byte
			switch kind {
			case "upload":
				method, path, action = "PUT", "/upload", "upload"
				body = []byte("denied")
				hash = Hash(body)
			case "head":
				method = "HEAD"
			case "missing_get":
				hash = Hash([]byte("absent"))
				path = "/" + hash
			case "cross_blob":
				hash = l.put("other", l.other.PubKeyHex())
				path = "/" + hash
				k = l.reader
			case "delete":
				method, action = "DELETE", "delete"
				k = l.reader
			case "missing_delete":
				method, action = "DELETE", "delete"
				hash = Hash([]byte("absent"))
				path = "/" + hash
			case "own_empty_list":
				path, action, hash = "/list/"+k.PubKeyHex(), "list", ""
			case "list":
				path, action, hash = "/list/"+l.writer.PubKeyHex(), "list", ""
			}
			before := replayBytes(t, l)
			count := len(l.s.blobs)
			for i := 0; i < 8; i++ {
				s, _, _ := l.do(method, path, l.auth(k, action, hash), body)
				if s != 403 {
					t.Fatalf("unauthorized refusal=%d want403", s)
				}
				if !bytes.Equal(before, replayBytes(t, l)) {
					t.Fatal("unauthorized request changed replay journal")
				}
				if len(l.s.blobs) != count {
					t.Fatal("unauthorized request changed blobs")
				}
			}
			l.read(l.reader, Hash([]byte("allowed")), "allowed")
		})
	}
}

func configureReplay(l *lab, global, perKey int) {
	l.t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	cfg := l.s.cfg
	cfg.MaxReplay = global
	cfg.MaxReplayPerKey = perKey
	l.s.Close()
	s, e := Open(cfg)
	if e != nil {
		l.t.Fatal(e)
	}
	l.s = s
	s.now = func() time.Time { return time.Unix(l.now, 0) }
}

// A key reaching its quota does not spend another slot. Quotas survive restart,
// another authorized reader still succeeds, and expiry permits the refused
// event's first use. A consumed event is rejected even while the journal is full.
func TestPerKeyQuota(t *testing.T) {
	l := newLab(t)
	configureReplay(l, 4, 0)
	if l.s.cfg.MaxReplayPerKey != 2 {
		t.Fatal("small global cap lacks fair default")
	}
	hash := l.put("quota", l.reader.PubKeyHex(), l.other.PubKeyHex())
	short := editAuth(t, l.auth(l.reader, "get", hash), l.reader, func(e *nostr.Event) { tag(e, "expiration", "501") })
	first, _, _ := l.do("GET", "/"+hash, short, nil)
	if first != 200 {
		t.Fatal(first)
	}
	live := l.auth(l.reader, "get", hash)
	s, _, _ := l.do("GET", "/"+hash, live, nil)
	if s != 200 {
		t.Fatal(s)
	}
	l.reopen()
	denied := l.auth(l.reader, "get", hash)
	before := replayBytes(t, l)
	s, _, _ = l.do("GET", "/"+hash, denied, nil)
	if s != 429 {
		t.Fatalf("per-key cap status=%d want429", s)
	}
	if !bytes.Equal(before, replayBytes(t, l)) {
		t.Fatal("quota denial consumed event")
	}
	l.read(l.other, hash, "quota")
	s, _, _ = l.do("GET", "/"+hash, live, nil)
	if s != 401 {
		t.Fatal("replay lost behind full quota")
	}
	l.now = 502
	s, body, _ := l.do("GET", "/"+hash, denied, nil)
	if s != 200 || string(body) != "quota" {
		t.Fatal("quota denial burned token or expiry did not reclaim slots")
	}
	s, _, _ = l.do("GET", "/"+hash, denied, nil)
	if s != 401 {
		t.Fatal("recovered event reused")
	}
}

// A writer spends one budget across upload, retrieval and list; crossing that
// budget cannot publish or delete. A separate putter and reader retain access.
func TestPerKeyQuotaAcrossOperations(t *testing.T) {
	l := newLab(t)
	configureReplay(l, 8, 2)
	hash := l.put("owned", l.reader.PubKeyHex())
	s, _, _ := l.do("GET", "/list/"+l.writer.PubKeyHex(), l.auth(l.writer, "list", ""), nil)
	if s != 200 {
		t.Fatal(s)
	}
	before := replayBytes(t, l)
	for _, v := range []struct {
		method, path, action, hash string
		data                       []byte
	}{{"PUT", "/upload", "upload", Hash([]byte("second")), []byte("second")}, {"DELETE", "/" + hash, "delete", hash, nil}, {"GET", "/" + hash, "get", hash, nil}, {"GET", "/list/" + l.writer.PubKeyHex(), "list", "", nil}} {
		s, _, _ := l.do(v.method, v.path, l.auth(l.writer, v.action, v.hash), v.data)
		if s != 429 {
			t.Fatalf("cross-operation quota bypass: %s=%d", v.action, s)
		}
		if !bytes.Equal(before, replayBytes(t, l)) || len(l.s.blobs) != 1 {
			t.Fatal("quota denial changed state")
		}
	}
	l.read(l.reader, hash, "owned")
	body := []byte("another owner")
	s, _, _ = l.do("PUT", "/upload", l.auth(l.other, "upload", Hash(body)), body)
	if s != 201 {
		t.Fatalf("other writer starved: %d", s)
	}
	l.read(l.other, Hash(body), string(body))
}

// Even a completely full journal, or a journal that cannot be safely written,
// does not alter missing/non-reader denials or charge those requests to anyone.
func TestDeniedWithFullOrUnavailableJournal(t *testing.T) {
	for _, state := range []string{"full", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			l := newLab(t)
			configureReplay(l, 4, 2)
			hash := l.put("private", l.reader.PubKeyHex(), l.other.PubKeyHex())
			if state == "full" {
				l.read(l.reader, hash, "private")
				l.read(l.reader, hash, "private")
				l.read(l.other, hash, "private")
			} else {
				if e := os.Chmod(filepath.Join(l.s.cfg.Root, "replay.json"), 0400); e != nil {
					t.Fatal(e)
				}
			}
			before := replayBytes(t, l)
			var prior string
			for _, h := range []string{hash, Hash([]byte("missing"))} {
				s, b, _ := l.do("GET", "/"+h, l.auth(l.outsider, "get", h), nil)
				if s != 403 {
					t.Fatalf("denial depended on journal: %d", s)
				}
				if prior != "" && prior != string(b) {
					t.Fatal("denial disclosed existence")
				}
				prior = string(b)
				if !bytes.Equal(before, replayBytes(t, l)) {
					t.Fatal("denial wrote unavailable/full journal")
				}
			}
			if state == "unavailable" {
				if e := os.Chmod(filepath.Join(l.s.cfg.Root, "replay.json"), 0600); e != nil {
					t.Fatal(e)
				}
				l.read(l.reader, hash, "private")
			} else {
				l.now = 801
				l.read(l.reader, hash, "private")
			}
		})
	}
}

// Serialized authorization/reservation admits exactly the key budget despite
// concurrent fresh signatures and leaves a different reader a positive slot.
func TestConcurrentPerKeyQuota(t *testing.T) {
	l := newLab(t)
	configureReplay(l, 4, 2)
	hash := l.put("parallel", l.reader.PubKeyHex(), l.other.PubKeyHex())
	headers := []string{}
	for i := 0; i < 8; i++ {
		headers = append(headers, l.auth(l.reader, "get", hash))
	}
	out := make(chan int, len(headers))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, h := range headers {
		wg.Add(1)
		go func(h string) { defer wg.Done(); <-start; s, _, _ := l.do("GET", "/"+hash, h, nil); out <- s }(h)
	}
	close(start)
	wg.Wait()
	close(out)
	counts := map[int]int{}
	for s := range out {
		counts[s]++
	}
	if counts[200] != 2 || counts[429] != 6 || len(l.s.replay.Entries) != 3 {
		t.Fatalf("concurrent key quota: %v", counts)
	}
	l.read(l.other, hash, "parallel")
}

// Migration preserves every legacy consumed ID and the clock high-water. Old
// entries cannot be attributed to keys, so they retain only their global charge
// until expiry; fresh v2 entries retain signer accounting over another restart.
func TestLegacyReplayMigration(t *testing.T) {
	l := newLab(t)
	configureReplay(l, 4, 2)
	hash := l.put("legacy", l.reader.PubKeyHex())
	h := l.auth(l.reader, "get", hash)
	s, _, _ := l.do("GET", "/"+hash, h, nil)
	if s != 200 {
		t.Fatal(s)
	}
	legacy := l.s.replay
	legacy.Version = 1
	legacy.Entries = append([]replayEntry{}, legacy.Entries...)
	for i := range legacy.Entries {
		legacy.Entries[i].PubKey = ""
	}
	raw, e := json.Marshal(legacy)
	if e != nil {
		t.Fatal(e)
	}
	l.s.Close()
	if e = os.WriteFile(filepath.Join(l.s.cfg.Root, "replay.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	l.reopen()
	before := replayBytes(t, l)
	s, _, _ = l.do("GET", "/"+hash, h, nil)
	if s != 401 {
		t.Fatal("legacy consumed ID reset")
	}
	if !bytes.Equal(before, replayBytes(t, l)) {
		t.Fatal("legacy replay rewrote journal")
	}
	l.read(l.reader, hash, "legacy")
	var disk replayDisk
	if !canonical(replayBytes(t, l), &disk) || disk.Version != 2 {
		t.Fatal("successful admission did not persist v2")
	}
	l.reopen()
	l.read(l.reader, hash, "legacy")
	s, _, _ = l.do("GET", "/"+hash, l.auth(l.writer, "get", hash), nil)
	if s != 429 {
		t.Fatal("legacy global slots discarded")
	}
	l.now = 801
	l.read(l.reader, hash, "legacy")
	l.reopen()
	l.now = 500
	s, _, _ = l.do("GET", "/"+hash, l.auth(l.reader, "get", hash), nil)
	if s != 503 {
		t.Fatal("migration lost clock high-water")
	}
	l.now = 802
	l.read(l.writer, hash, "legacy")
}

// Compact v2 records retain 512 worst-width entries within the existing 64 KiB
// writer, including distinct signers. Noncanonical or malformed signer records
// fail closed on restart; neighboring valid records open and retain content.
func TestReplayEncodingBounds(t *testing.T) {
	s := replayState{Version: 2, LastTime: math.MaxInt64, Entries: []replayEntry{}}
	for i := 0; i < 512; i++ {
		id := Hash([]byte(fmt.Sprintf("event-%d", i)))
		pub := Hash([]byte(fmt.Sprintf("key-shape-%d", i)))
		s.Entries = append(s.Entries, replayEntry{ID: id, Expiry: math.MaxInt64, PubKey: pub})
	}
	raw, e := encodeReplay(s)
	if e != nil || len(raw) > 65536 {
		t.Fatalf("maximum replay encoding exceeds writer: %d %v", len(raw), e)
	}
	got, e := decodeReplay(raw)
	if e != nil || !reflect.DeepEqual(got, s) {
		t.Fatal("replay encoding lost entries")
	}
	s.Entries = append(s.Entries, s.Entries[0])
	if _, e = encodeReplay(s); e == nil {
		t.Fatal("oversized replay encoded")
	}
	for _, kind := range []string{"bad_key", "bad_id", "duplicate_id", "bad_expiry", "extra_tuple", "bad_version"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			hash := l.put("valid")
			raw := replayBytes(t, l)
			var d replayDisk
			if e := json.Unmarshal(raw, &d); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "bad_key":
				d.Entries[0][2] = "invalid"
			case "bad_id":
				d.Entries[0][0] = "invalid"
			case "duplicate_id":
				d.Entries = append(d.Entries, d.Entries[0])
			case "bad_expiry":
				d.Entries[0][1] = "0800"
			case "bad_version":
				d.Version = 3
			}
			bad, _ := json.Marshal(d)
			if kind == "extra_tuple" {
				bad = bytes.Replace(bad, []byte(`]]}`), []byte(`,"extra"]]}`), 1)
			}
			cfg := l.s.cfg
			l.s.Close()
			p := filepath.Join(cfg.Root, "replay.json")
			if e := os.WriteFile(p, bad, 0600); e != nil {
				t.Fatal(e)
			}
			if s, e := Open(cfg); e == nil {
				s.Close()
				t.Fatal("malformed signer journal opened")
			}
			if e := os.WriteFile(p, raw, 0600); e != nil {
				t.Fatal(e)
			}
			l.reopen()
			l.read(l.writer, hash, "valid")
		})
	}
}

// Configuration cannot let one key occupy the entire global journal; defaults
// adapt to small journals, and the ordinary 512-slot store defaults to 32/key.
func TestReplayQuotaConfig(t *testing.T) {
	for _, v := range []struct {
		global, per int
		valid       bool
		want        int
	}{{512, 0, true, 32}, {4, 0, true, 2}, {2, 0, true, 1}, {4, 1, true, 1}, {4, 3, true, 3}, {1, 0, false, 0}, {4, 4, false, 0}, {4, 5, false, 0}, {4, -1, false, 0}} {
		t.Run(fmt.Sprintf("%d_%d", v.global, v.per), func(t *testing.T) {
			l := newLab(t)
			cfg := l.s.cfg
			cfg.MaxReplay = v.global
			cfg.MaxReplayPerKey = v.per
			l.s.Close()
			s, e := Open(cfg)
			if !v.valid {
				if e == nil {
					s.Close()
					t.Fatal("unfair quota config accepted")
				}
				l.reopen()
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			l.s = s
			s.now = func() time.Time { return time.Unix(l.now, 0) }
			if s.cfg.MaxReplayPerKey != v.want {
				t.Fatal("unexpected default key budget")
			}
			hash := l.put("valid", l.reader.PubKeyHex())
			l.read(l.reader, hash, "valid")
		})
	}
}

// An unauthorized but correctly signed token is not burned: after the owner
// deliberately grants access by delete/reupload, that same token works once.
func TestDeniedTokenAfterReaderGrant(t *testing.T) {
	l := newLab(t)
	hash := l.put("grant-later")
	h := l.auth(l.outsider, "get", hash)
	before := replayBytes(t, l)
	s, _, _ := l.do("GET", "/"+hash, h, nil)
	if s != 403 || !bytes.Equal(before, replayBytes(t, l)) {
		t.Fatal("denied token changed replay state")
	}
	s, _, _ = l.do("DELETE", "/"+hash, l.auth(l.writer, "delete", hash), nil)
	if s != 204 {
		t.Fatal(s)
	}
	l.put("grant-later", l.outsider.PubKeyHex())
	s, b, _ := l.do("GET", "/"+hash, h, nil)
	if s != 200 || string(b) != "grant-later" {
		t.Fatal("denied token burned before access was granted")
	}
	s, _, _ = l.do("GET", "/"+hash, h, nil)
	if s != 401 {
		t.Fatal("authorized token reused")
	}
}
