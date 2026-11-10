package rehearsal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/websocket"
	store "github.com/relux-works/swarma-chain-lab/experiments/grant-store"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// The relay enforces signed event kinds, not rental grant action scope. A
// cryptographically valid unsupported kind must refuse and stay absent from
// replay; an allowed kind must store and replay through the same connection.
func (l *lab) relayBoundary(origin string, key *nostr.PrivKey) {
	t := l.t
	c, _, e := websocket.DefaultDialer.Dial(origin, nil)
	checked(t, e, "relay probe connection")
	defer c.Close()
	checked(t, c.SetReadDeadline(time.Now().Add(5*time.Second)), "relay probe bound")
	next := func() []json.RawMessage {
		for i := 0; i < 8; i++ {
			var frame []json.RawMessage
			checked(t, c.ReadJSON(&frame), "relay probe frame")
			if len(frame) == 0 {
				t.Fatal("relay empty frame")
			}
			if string(frame[0]) == `"AUTH"` {
				continue
			}
			return frame
		}
		t.Fatal("relay probe frame bound")
		return nil
	}
	var ids []string
	for _, kind := range []int{1, 8181} {
		event := &nostr.Event{Kind: kind, CreatedAt: time.Now().Unix(), Tags: [][]string{}, Content: "canonical relay boundary fixture"}
		checked(t, key.SignEvent(event), "relay probe signature")
		checked(t, c.WriteJSON([]any{"EVENT", event}), "relay probe publish")
		frame := next()
		if len(frame) != 4 || string(frame[0]) != `"OK"` || string(frame[1]) != string(encoded(event.ID)) || string(frame[2]) != map[bool]string{true: "true", false: "false"}[kind == 8181] {
			t.Fatal("relay event-kind result")
		}
		if kind == 1 && string(frame[3]) != `"invalid: event"` {
			t.Fatal("relay wrong refusal boundary")
		}
		ids = append(ids, event.ID)
	}
	checked(t, c.WriteJSON([]any{"REQ", "canonical-probe", map[string]any{"ids": ids, "limit": 2}}), "relay probe replay")
	frame := next()
	if len(frame) != 3 || string(frame[0]) != `"EVENT"` {
		t.Fatal("relay allowed event absent")
	}
	var got nostr.Event
	checked(t, json.Unmarshal(frame[2], &got), "relay replay shape")
	if got.ID != ids[1] {
		t.Fatal("relay replayed refused event")
	}
	frame = next()
	if len(frame) != 2 || string(frame[0]) != `"EOSE"` {
		t.Fatal("relay extra refused replay")
	}
	l.evidence["relay_boundary"] = map[string]any{"boundary": "signed-event-kind", "unsupported_kind": "invalid: event", "rejected_not_replayed": true, "allowed_stored_and_replayed": true}
}

// A signed outsider cannot upload or delete, and refusals cannot consume replay
// capacity. The configured writer and reader are adjacent successful controls;
// the owned probe blob is deleted by its owner after these checks.
func (l *lab) storeBoundary(origin string, writer, reader, outsider *nostr.PrivKey) {
	t := l.t
	blob := []byte("canonical ACL fixture, not a rental grant")
	hash := store.Hash(blob)
	client := http.Client{Timeout: 3 * time.Second}
	request := func(method, path, action string, key *nostr.PrivKey, body []byte) (int, []byte) {
		auth, e := store.AuthHeader(key, action, hash, "127.0.0.1", []string{reader.PubKeyHex()}, time.Now())
		checked(t, e, "store probe authorization")
		req, e := http.NewRequest(method, origin+path, bytes.NewReader(body))
		checked(t, e, "store probe request")
		req.Header.Set("Authorization", auth)
		res, e := client.Do(req)
		checked(t, e, "store probe response")
		defer res.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(res.Body, 16384))
		checked(t, e, "store probe body")
		return res.StatusCode, raw
	}
	replay := func() []byte {
		raw, e := os.ReadFile(filepath.Join(l.private, "store/replay.json"))
		if e != nil && !os.IsNotExist(e) {
			t.Fatal("store replay read")
		}
		return raw
	}
	before := replay()
	status, _ := request("PUT", "/upload", "upload", outsider, blob)
	if status != 403 || !bytes.Equal(before, replay()) {
		t.Fatal("store outsider upload wrote replay or wrong refusal")
	}
	if _, e := os.Stat(filepath.Join(l.private, "store", hash)); !os.IsNotExist(e) {
		t.Fatal("store outsider upload wrote blob")
	}
	status, _ = request("PUT", "/upload", "upload", writer, blob)
	if status != 201 {
		t.Fatal("store configured writer refused")
	}
	status, raw := request("GET", "/"+hash, "get", reader, nil)
	if status != 200 || !bytes.Equal(raw, blob) {
		t.Fatal("store permitted reader refused")
	}
	before = replay()
	status, _ = request("DELETE", "/"+hash, "delete", reader, nil)
	if status != 403 || !bytes.Equal(before, replay()) {
		t.Fatal("store reader delete changed journal")
	}
	status, raw = request("GET", "/"+hash, "get", reader, nil)
	if status != 200 || !bytes.Equal(raw, blob) {
		t.Fatal("store refusal changed object")
	}
	status, _ = request("DELETE", "/"+hash, "delete", writer, nil)
	if status != 204 {
		t.Fatal("store owner cleanup refused")
	}
	l.evidence["store_boundary"] = map[string]any{"boundary": "writer-reader-owner ACL", "outsider_upload_status": 403, "reader_delete_status": 403, "refusal_replay_unchanged": true, "writer_upload_reader_get": true, "refused_delete_preserved_blob": true, "owner_delete": true}
}
