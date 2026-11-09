package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

const (
	RelayAuthOff            = "off"
	RelayAuthWhenChallenged = "when_challenged"
	RelayAuthRequired       = "required"
	relayTimeout            = 10 * time.Second
)

var (
	ErrRelayConfig       = errors.New("RELAY_CONFIG")
	ErrRelayClosed       = errors.New("RELAY_CLOSED")
	ErrRelayRejected     = errors.New("RELAY_REJECTED")
	ErrRelayAuthKey      = errors.New("RELAY_AUTH_KEY")
	ErrRelayAuthRequired = errors.New("RELAY_AUTH_REQUIRED")
	ErrRelayAuthRejected = errors.New("RELAY_AUTH_REJECTED")
	ErrRelayAuthTimeout  = errors.New("RELAY_AUTH_TIMEOUT")
	ErrRelayProtocol     = errors.New("RELAY_PROTOCOL")
	ErrRelayBusy         = errors.New("RELAY_BUSY")
)

func ValidRelayAuth(mode string) bool {
	return mode == "" || mode == RelayAuthOff || mode == RelayAuthWhenChallenged || mode == RelayAuthRequired
}

// RelayClient owns one connection at a time. Configuration is immutable after
// first use. Callers reconnect by calling SubscribeGiftWraps/Publish again after
// failure; no subscription or authentication state survives a disconnect.
// Empty Auth is the legacy off mode. AgentKey is never sent as key material.
type RelayClient struct {
	URL      string
	Auth     string
	AgentKey *nostr.PrivKey
	// Zero selects90s/30s liveness,100ms..5s reconnect and32-event pages.
	ReadTimeout, PingInterval  time.Duration
	ReconnectMin, ReconnectMax time.Duration
	ReplayLimit                int
	OnStatus                   func(RelayStatus)
	mu                         sync.Mutex
	session                    *relaySession
	running                    bool
	reconnects                 atomic.Uint64
	replayOverflows            atomic.Uint64
}

// All state except writeMu is guarded by RelayClient.mu. Completion channels
// belong to the connection, so an old pump cannot fail a replacement's waiters.
type relaySession struct {
	conn              *websocket.Conn
	writeMu           sync.Mutex
	done              chan struct{}
	changed           chan struct{}
	err               error
	waiters           map[string]chan error
	handler           func(context.Context, *nostr.Event)
	hctx              context.Context
	closed            chan error
	authSeq, accepted uint64
	authID            string
	replay            map[string]*relayPage
	pages             chan relayPage
}

func (c *RelayClient) enabled() bool {
	return c.Auth == RelayAuthRequired || c.Auth == RelayAuthWhenChallenged
}
func (c *RelayClient) Dial(ctx context.Context) error {
	if !ValidRelayAuth(c.Auth) || c.validateLiveness() != nil {
		return ErrRelayConfig
	}
	if c.Auth == RelayAuthRequired && c.AgentKey == nil {
		return ErrRelayAuthKey
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return nil
	}
	d := websocket.Dialer{HandshakeTimeout: relayTimeout}
	conn, _, err := d.DialContext(ctx, c.URL, nil)
	if err != nil {
		return ErrRelayClosed
	}
	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(c.readTimeout()))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(c.readTimeout())) })
	s := &relaySession{conn: conn, done: make(chan struct{}), changed: make(chan struct{}), waiters: map[string]chan error{}, closed: make(chan error, 1)}
	c.session = s
	go c.pump(s)
	go c.heartbeat(s)
	return nil
}
func (c *RelayClient) Close() {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s != nil {
		c.stop(s, ErrRelayClosed)
	}
}
func (c *RelayClient) stop(s *relaySession, err error) {
	c.mu.Lock()
	c.failLocked(s, err)
	c.mu.Unlock()
	_ = s.conn.Close()
}
func (c *RelayClient) failLocked(s *relaySession, err error) {
	if s.err == nil {
		s.err = err
		close(s.done)
		if c.session == s {
			c.session = nil
		}
	}
}
func (c *RelayClient) write(s *relaySession, v any) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.done:
		return ErrRelayClosed
	default:
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(relayTimeout))
	if s.conn.WriteJSON(v) != nil {
		c.stop(s, ErrRelayClosed)
		return ErrRelayClosed
	}
	return nil
}
func (c *RelayClient) signal(s *relaySession) { close(s.changed); s.changed = make(chan struct{}) }
func (c *RelayClient) authChallenge(s *relaySession, challenge string) error {
	if !c.enabled() {
		return nil
	}
	if c.AgentKey == nil {
		return ErrRelayAuthKey
	}
	if len(challenge) == 0 || len(challenge) > 4096 {
		return ErrRelayProtocol
	}
	ev := &nostr.Event{Kind: 22242, CreatedAt: time.Now().Unix(), Tags: [][]string{{"relay", c.URL}, {"challenge", challenge}}}
	if c.AgentKey.SignEvent(ev) != nil {
		return ErrRelayAuthKey
	}
	c.mu.Lock()
	// Bound challenge/signature work per connection. Reconnect starts a new budget.
	if s.authSeq >= 32 {
		c.mu.Unlock()
		return ErrRelayProtocol
	}
	s.authSeq++
	s.authID = ev.ID
	c.signal(s)
	seq := s.authSeq
	c.mu.Unlock()
	// A challenged but unacknowledged connection cannot remain silently usable.
	time.AfterFunc(relayTimeout, func() {
		c.mu.Lock()
		expired := s.err == nil && s.authSeq == seq && s.accepted != seq
		if expired {
			c.failLocked(s, ErrRelayAuthTimeout)
		}
		c.mu.Unlock()
		if expired {
			_ = s.conn.Close()
		}
	})
	return c.write(s, []any{"AUTH", ev})
}
func relayRefusal(reason string) error {
	if strings.HasPrefix(reason, "auth-required:") {
		return ErrRelayAuthRequired
	}
	return ErrRelayRejected
}
func (c *RelayClient) pump(s *relaySession) {
	defer c.stop(s, ErrRelayClosed)
	for {
		_, raw, err := s.conn.ReadMessage()
		if err != nil {
			return
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(c.readTimeout()))
		var m []json.RawMessage
		var typ string
		if json.Unmarshal(raw, &m) != nil || len(m) < 2 || json.Unmarshal(m[0], &typ) != nil {
			continue
		}
		switch typ {
		case "AUTH":
			var challenge string
			if len(m) != 2 || json.Unmarshal(m[1], &challenge) != nil {
				c.stop(s, ErrRelayProtocol)
				return
			}
			if e := c.authChallenge(s, challenge); e != nil {
				c.stop(s, e)
				return
			}
		case "OK":
			var id, reason string
			var ok bool
			if len(m) != 4 || json.Unmarshal(m[1], &id) != nil || json.Unmarshal(m[2], &ok) != nil || json.Unmarshal(m[3], &reason) != nil {
				continue
			}
			c.mu.Lock()
			if id == s.authID && s.authID != "" {
				if !ok {
					c.mu.Unlock()
					c.stop(s, ErrRelayAuthRejected)
					return
				}
				s.accepted = s.authSeq
				c.signal(s)
				c.mu.Unlock()
				continue
			}
			ch := s.waiters[id]
			delete(s.waiters, id)
			c.mu.Unlock()
			if ch != nil {
				if ok {
					ch <- nil
				} else {
					ch <- relayRefusal(reason)
				}
			}
		case "CLOSED":
			var id, reason string
			if len(m) != 3 || json.Unmarshal(m[1], &id) != nil || json.Unmarshal(m[2], &reason) != nil || (id != "gw-inbox" && id != "gw-catchup") {
				continue
			}
			select {
			case s.closed <- relayRefusal(reason):
			default:
				c.stop(s, ErrRelayProtocol)
				return
			}
		case "EVENT":
			var sub string
			if len(m) != 3 || json.Unmarshal(m[1], &sub) != nil || (sub != "gw-inbox" && sub != "gw-catchup") {
				continue
			}
			ev, e := nostr.ParseEvent(m[2])
			if e != nil {
				continue
			}
			c.mu.Lock()
			h, hctx := s.handler, s.hctx
			allowed := (c.Auth != RelayAuthRequired || s.accepted > 0) && s.accepted == s.authSeq && s.err == nil
			if sub == "gw-catchup" && s.replay[sub] == nil {
				allowed = false
			}
			if allowed {
				if p := s.replay[sub]; p != nil && !p.done {
					p.observe(ev.CreatedAt)
				}
			}
			c.mu.Unlock()
			if h != nil && allowed {
				h(hctx, ev)
			}
		case "EOSE":
			var sub string
			if len(m) != 2 || json.Unmarshal(m[1], &sub) != nil {
				continue
			}
			c.mu.Lock()
			p := s.replay[sub]
			var page *relayPage
			if p != nil && !p.done {
				p.done = true
				copy := *p
				page = &copy
			}
			c.mu.Unlock()
			if page != nil {
				select {
				case s.pages <- *page:
				default:
					c.stop(s, ErrRelayProtocol)
					return
				}
			}
		}
	}
}

// awaitAuth requires a positive acknowledgement for the current challenge. A
// retry after auth-required needs a newer authentication than the rejected send.
func (c *RelayClient) awaitAuth(ctx context.Context, s *relaySession, after uint64, force bool) error {
	if force && !c.enabled() {
		return ErrRelayAuthRequired
	}
	wait, cancel := context.WithTimeout(ctx, relayTimeout)
	defer cancel()
	for {
		c.mu.Lock()
		seq, accepted, ch, err := s.authSeq, s.accepted, s.changed, s.err
		c.mu.Unlock()
		if err != nil {
			return err
		}
		if accepted == seq && (!force || accepted > after) {
			return nil
		}
		select {
		case <-s.done:
		case <-ch:
		case <-wait.Done():
			if ctx.Err() == context.Canceled {
				return ctx.Err()
			}
			return ErrRelayAuthTimeout
		}
	}
}
func (c *RelayClient) connected(ctx context.Context) (*relaySession, error) {
	if e := c.Dial(ctx); e != nil {
		return nil, e
	}
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s == nil {
		return nil, ErrRelayClosed
	}
	if e := c.awaitAuth(ctx, s, 0, c.Auth == RelayAuthRequired); e != nil {
		c.stop(s, e)
		return nil, e
	}
	return s, nil
}
func (c *RelayClient) Publish(ctx context.Context, ev *nostr.Event) error {
	if ev == nil || ev.Kind == 22242 {
		return ErrRelayProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, relayTimeout)
	defer cancel()
	s, e := c.connected(ctx)
	if e != nil {
		return e
	}
	for attempt := 0; attempt < 2; attempt++ {
		ch := make(chan error, 1)
		c.mu.Lock()
		if _, busy := s.waiters[ev.ID]; busy {
			c.mu.Unlock()
			return ErrRelayBusy
		}
		s.waiters[ev.ID] = ch
		sentAuth := s.accepted
		c.mu.Unlock()
		e = c.write(s, []any{"EVENT", ev})
		if e == nil {
			select {
			case e = <-ch:
			case <-s.done:
				c.mu.Lock()
				e = s.err
				c.mu.Unlock()
			case <-ctx.Done():
				e = ctx.Err()
			}
		}
		c.mu.Lock()
		if s.waiters[ev.ID] == ch {
			delete(s.waiters, ev.ID)
		}
		c.mu.Unlock()
		if e != ErrRelayAuthRequired || attempt == 1 {
			return e
		}
		if e = c.awaitAuth(ctx, s, sentAuth, true); e != nil {
			return e
		}
	}
	return ErrRelayAuthRequired
}
func (c *RelayClient) SubscribeGiftWraps(ctx context.Context, pubkey string, handler func(context.Context, *nostr.Event)) error {
	s, e := c.connected(ctx)
	if e != nil {
		return e
	}
	c.mu.Lock()
	if s.handler != nil {
		c.mu.Unlock()
		return ErrRelayBusy
	}
	s.handler = handler
	s.hctx = ctx
	c.mu.Unlock()
	defer c.stop(s, ErrRelayClosed)
	for attempt := 0; attempt < 2; attempt++ {
		c.mu.Lock()
		sentAuth := s.accepted
		c.mu.Unlock()
		if e = c.write(s, []any{"REQ", "gw-inbox", map[string]any{"kinds": []int{nostr.KindGiftWrap}, "#p": []string{pubkey}}}); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.mu.Lock()
			e = s.err
			c.mu.Unlock()
			return e
		case e = <-s.closed:
			if e != ErrRelayAuthRequired || attempt == 1 {
				return e
			}
			if e = c.awaitAuth(ctx, s, sentAuth, true); e != nil {
				return e
			}
		}
	}
	return ErrRelayAuthRequired
}
