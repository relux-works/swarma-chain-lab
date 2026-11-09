// Package testrelay is an in-process, localhost-only Nostr relay for
// tests. It speaks the subset the gateway needs (EVENT/REQ/CLOSE ->
// EVENT/EOSE/OK/NOTICE), verifies event ids and signatures exactly
// like a real relay, keeps events in memory, and binds 127.0.0.1
// only. It exists so gateway tests never touch a real relay.
package testrelay

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// Filter is the NIP-01 subscription filter subset we support.
type Filter struct {
	Kinds   []int    `json:"kinds,omitempty"`
	Authors []string `json:"authors,omitempty"`
	PTags   []string `json:"#p,omitempty"`
	Since   *int64   `json:"since,omitempty"`
	Until   *int64   `json:"until,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

// Match reports whether an event passes the filter.
func (f *Filter) Match(e *nostr.Event) bool {
	if len(f.Kinds) > 0 && !containsInt(f.Kinds, e.Kind) {
		return false
	}
	if len(f.Authors) > 0 && !containsStr(f.Authors, e.PubKey) {
		return false
	}
	if len(f.PTags) > 0 {
		p, ok := e.TagFirst("p")
		if !ok || !containsStr(f.PTags, p) {
			return false
		}
	}
	if f.Since != nil && e.CreatedAt < *f.Since {
		return false
	}
	if f.Until != nil && e.CreatedAt > *f.Until {
		return false
	}
	return true
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// Relay is the test relay server.
type Relay struct {
	URL string // ws://127.0.0.1:<port>

	ln     net.Listener
	server *http.Server

	mu     sync.Mutex
	events []*nostr.Event
	seen   map[string]bool
	subs   map[*conn]map[string][]*Filter
}

type conn struct {
	ws *websocket.Conn
	mu sync.Mutex
}

func (c *conn) sendJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.WriteJSON(v)
}

// Start binds the relay on a random 127.0.0.1 port and serves.
func Start() (*Relay, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &Relay{
		URL:  fmt.Sprintf("ws://%s", ln.Addr().String()),
		ln:   ln,
		seen: map[string]bool{},
		subs: map[*conn]map[string][]*Filter{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.handle)
	r.server = &http.Server{Handler: mux}
	go func() { _ = r.server.Serve(ln) }()
	return r, nil
}

// Close shuts the relay down.
func (r *Relay) Close() {
	if r.server != nil {
		_ = r.server.Close()
	}
	_ = r.ln.Close()
}

// Events returns a copy of stored events (oldest first) for asserts.
func (r *Relay) Events() []*nostr.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*nostr.Event(nil), r.events...)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func (r *Relay) handle(w http.ResponseWriter, req *http.Request) {
	ws, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	c := &conn{ws: ws}
	r.mu.Lock()
	r.subs[c] = map[string][]*Filter{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.subs, c)
		r.mu.Unlock()
		_ = ws.Close()
	}()
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			return
		}
		r.dispatch(c, raw)
	}
}

func (r *Relay) dispatch(c *conn, raw []byte) {
	var msg []json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil || len(msg) == 0 {
		_ = c.sendJSON([]any{"NOTICE", "invalid message"})
		return
	}
	var typ string
	_ = json.Unmarshal(msg[0], &typ)
	switch typ {
	case "EVENT":
		if len(msg) != 2 {
			_ = c.sendJSON([]any{"NOTICE", "EVENT wants one event"})
			return
		}
		ev, err := nostr.ParseEvent(msg[1])
		if err != nil {
			_ = c.sendJSON([]any{"OK", "", false, "invalid: " + err.Error()})
			return
		}
		if err := nostr.VerifySignature(ev); err != nil {
			_ = c.sendJSON([]any{"OK", ev.ID, false, "invalid: " + err.Error()})
			return
		}
		r.mu.Lock()
		if r.seen[ev.ID] {
			r.mu.Unlock()
			_ = c.sendJSON([]any{"OK", ev.ID, true, "duplicate: already have this event"})
			return
		}
		r.seen[ev.ID] = true
		r.events = append(r.events, ev)
		targets := r.matchingSubsLocked(ev)
		r.mu.Unlock()
		_ = c.sendJSON([]any{"OK", ev.ID, true, ""})
		for _, t := range targets {
			_ = t.c.sendJSON([]any{"EVENT", t.subID, ev})
		}
	case "REQ":
		if len(msg) < 3 {
			_ = c.sendJSON([]any{"NOTICE", "REQ wants id and filters"})
			return
		}
		var subID string
		_ = json.Unmarshal(msg[1], &subID)
		var filters []*Filter
		for _, fr := range msg[2:] {
			var f Filter
			if err := json.Unmarshal(fr, &f); err == nil {
				filters = append(filters, &f)
			}
		}
		r.mu.Lock()
		r.subs[c][subID] = filters
		stored := append([]*nostr.Event(nil), r.events...)
		r.mu.Unlock()
		for _, ev := range stored {
			if matchAny(filters, ev) {
				_ = c.sendJSON([]any{"EVENT", subID, ev})
			}
		}
		_ = c.sendJSON([]any{"EOSE", subID})
	case "CLOSE":
		if len(msg) == 2 {
			var subID string
			_ = json.Unmarshal(msg[1], &subID)
			r.mu.Lock()
			delete(r.subs[c], subID)
			r.mu.Unlock()
		}
	default:
		_ = c.sendJSON([]any{"NOTICE", "unknown message type"})
	}
}

type subTarget struct {
	c     *conn
	subID string
}

func (r *Relay) matchingSubsLocked(ev *nostr.Event) []subTarget {
	var out []subTarget
	for c, subs := range r.subs {
		for subID, filters := range subs {
			if matchAny(filters, ev) {
				out = append(out, subTarget{c, subID})
			}
		}
	}
	return out
}

func matchAny(filters []*Filter, ev *nostr.Event) bool {
	for _, f := range filters {
		if f.Match(ev) {
			return true
		}
	}
	return false
}
