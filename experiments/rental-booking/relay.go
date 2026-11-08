package booking

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

func LoopbackAddress(address string) bool {
	host, port, e := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	return e == nil && ip != nil && ip.IsLoopback() && port != ""
}

type RelayPublisher struct{ url string }

func NewRelayPublisher(raw string) (*RelayPublisher, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "ws" || !LoopbackAddress(u.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, refuse("RELAY_ROUTE")
	}
	return &RelayPublisher{raw}, nil
}
func (r *RelayPublisher) Publish(ctx context.Context, event Event) error {
	if event.Verify() != nil || event.Kind != PackageKind {
		return refuse("RELAY_EVENT")
	}
	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second, Proxy: nil}
	conn, _, e := dialer.DialContext(ctx, r.url, nil)
	if e != nil {
		return refuse("RELAY_CONNECT")
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetWriteDeadline(deadline)
	conn.SetReadDeadline(deadline)
	conn.SetReadLimit(4096)
	if e = conn.WriteJSON([]any{"EVENT", event}); e != nil {
		return refuse("RELAY_WRITE")
	}
	_, raw, e := conn.ReadMessage()
	if e != nil {
		return refuse("RELAY_READ")
	}
	var frame []json.RawMessage
	if json.Unmarshal(raw, &frame) != nil || len(frame) != 4 {
		return refuse("RELAY_ACK")
	}
	var kind, id string
	var accepted bool
	if json.Unmarshal(frame[0], &kind) != nil || json.Unmarshal(frame[1], &id) != nil || json.Unmarshal(frame[2], &accepted) != nil || kind != "OK" || id != event.ID || !accepted {
		return refuse("RELAY_ACK")
	}
	return nil
}

type LocalRelay struct {
	mu    sync.Mutex
	store *fileStore
}

func NewLocalRelay(root string) (*LocalRelay, error) {
	s, e := openStore(root)
	if e != nil {
		return nil, e
	}
	return &LocalRelay{store: s}, nil
}
func (r *LocalRelay) Close() { r.mu.Lock(); defer r.mu.Unlock(); r.store.close() }
func (r *LocalRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host, _, e := net.SplitHostPort(req.RemoteAddr)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || !LoopbackAddress(req.Host) {
		http.Error(w, "LOOPBACK_REQUIRED", 403)
		return
	}
	upgrade := websocket.Upgrader{CheckOrigin: func(q *http.Request) bool {
		return q.Header.Get("Origin") == "" || q.Header.Get("Origin") == "http://"+q.Host
	}}
	conn, e := upgrade.Upgrade(w, req, nil)
	if e != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(128 << 10)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, raw, e := conn.ReadMessage()
		if e != nil {
			return
		}
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		var frame []json.RawMessage
		if json.Unmarshal(raw, &frame) != nil || len(frame) < 2 {
			return
		}
		var cmd string
		if json.Unmarshal(frame[0], &cmd) != nil {
			return
		}
		switch cmd {
		case "EVENT":
			if len(frame) != 2 {
				return
			}
			var event Event
			if Strict(frame[1], &event) != nil || event.Verify() != nil || event.Kind != PackageKind {
				_ = conn.WriteJSON([]any{"OK", "", false, "invalid: event"})
				continue
			}
			r.mu.Lock()
			err := r.store.write(event.ID+".json", canonical(event), true)
			r.mu.Unlock()
			message := ""
			if err != nil {
				message = "error: storage"
			}
			if conn.WriteJSON([]any{"OK", event.ID, err == nil, message}) != nil {
				return
			}
		case "REQ":
			if len(frame) != 3 {
				return
			}
			var sub string
			var filter struct {
				IDs []string `json:"ids"`
			}
			if json.Unmarshal(frame[1], &sub) != nil || len(sub) > 64 || strings.ContainsAny(sub, "\r\n") || Strict(frame[2], &filter) != nil || len(filter.IDs) > 20 {
				return
			}
			for _, id := range filter.IDs {
				if !hexSize(id, 32) {
					return
				}
				r.mu.Lock()
				b, err := r.store.read(id+".json", 128<<10)
				r.mu.Unlock()
				if err != nil {
					return
				}
				if b != nil {
					var event Event
					if Strict(b, &event) != nil || event.Verify() != nil {
						return
					}
					if conn.WriteJSON([]any{"EVENT", sub, event}) != nil {
						return
					}
				}
			}
			if conn.WriteJSON([]any{"EOSE", sub}) != nil {
				return
			}
		case "CLOSE":
			return
		default:
			return
		}
	}
}
