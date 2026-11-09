package gateway

import (
	"context"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

const replayJitter = 48 * time.Hour
const maxReplayPages = 128

type RelayStatus struct {
	Kind            string `json:"kind"`
	Reason          string `json:"reason"`
	Reconnects      uint64 `json:"reconnects"`
	ReplayOverflows uint64 `json:"replay_overflows"`
}

func (c *RelayClient) Status() RelayStatus {
	return RelayStatus{Kind: "relay_status", Reconnects: c.reconnects.Load(), ReplayOverflows: c.replayOverflows.Load()}
}
func (c *RelayClient) status(reason string) {
	if c.OnStatus != nil {
		s := c.Status()
		s.Reason = reason
		c.OnStatus(s)
	}
}
func (c *RelayClient) readTimeout() time.Duration {
	if c.ReadTimeout == 0 {
		return 90 * time.Second
	}
	return c.ReadTimeout
}
func (c *RelayClient) pingInterval() time.Duration {
	if c.PingInterval == 0 {
		return 30 * time.Second
	}
	return c.PingInterval
}
func (c *RelayClient) backoffBounds() (time.Duration, time.Duration) {
	a, b := c.ReconnectMin, c.ReconnectMax
	if a == 0 {
		a = 100 * time.Millisecond
	}
	if b == 0 {
		b = 5 * time.Second
	}
	return a, b
}
func (c *RelayClient) replayLimit() int {
	if c.ReplayLimit == 0 {
		return 32
	}
	return c.ReplayLimit
}
func (c *RelayClient) validateLiveness() error {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return ErrRelayConfig
	}
	a, b := c.backoffBounds()
	if c.readTimeout() < 100*time.Millisecond || c.readTimeout() > 5*time.Minute || c.pingInterval() < 10*time.Millisecond || c.pingInterval() >= c.readTimeout() || a < time.Millisecond || b < a || b > time.Minute || c.replayLimit() < 2 || c.replayLimit() > 4096 {
		return ErrRelayConfig
	}
	return nil
}
func (c *RelayClient) heartbeat(s *relaySession) {
	tick := time.NewTicker(c.pingInterval())
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			if s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.pingInterval())) != nil {
				c.stop(s, ErrRelayClosed)
				return
			}
		}
	}
}

type relayPage struct {
	id             string
	count          int
	oldest, newest int64
	done           bool
}

func (p *relayPage) observe(at int64) {
	if p.count == 0 || at < p.oldest {
		p.oldest = at
	}
	if p.count == 0 || at > p.newest {
		p.newest = at
	}
	if p.count < 4097 {
		p.count++
	}
}

// RunGiftWraps keeps transport failures from ending the gateway's expiry worker.
// Policy/auth/protocol errors remain fatal. Publish retains its explicit ACK
// contract: this loop never retries publications. Application handlers retain
// responsibility for durable rumor/exchange dedup across inclusive replay.
func (c *RelayClient) RunGiftWraps(ctx context.Context, pubkey string, handler func(context.Context, *nostr.Event)) error {
	if c.validateLiveness() != nil || handler == nil {
		return ErrRelayConfig
	}
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return ErrRelayBusy
	}
	c.running = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.running = false; c.mu.Unlock() }()
	minimum, maximum := c.backoffBounds()
	delay := minimum
	lastConnected := time.Now()
	floor := lastConnected.Add(-replayJitter - time.Minute).Unix()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Include the full outage and NIP59's backdating. Never advance an uncertain
		// replay floor after a partial page, or trust an outer event as an ACK cursor.
		bound := lastConnected.Add(-replayJitter - time.Since(lastConnected) - time.Minute).Unix()
		if bound < floor {
			floor = bound
		}
		if floor < 0 {
			floor = 0
		}
		started := time.Now()
		err := c.subscribeReplay(ctx, pubkey, handler, floor, &lastConnected)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != ErrRelayClosed {
			return err
		}
		c.reconnects.Add(1)
		c.status("RELAY_RECONNECT")
		if time.Since(started) >= c.readTimeout() {
			delay = minimum
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if delay < maximum {
			delay *= 2
			if delay > maximum {
				delay = maximum
			}
		}
	}
}

func (c *RelayClient) subscribeReplay(ctx context.Context, pubkey string, handler func(context.Context, *nostr.Event), since int64, connectedAt *time.Time) error {
	s, err := c.connected(ctx)
	if err != nil {
		return err
	}
	*connectedAt = time.Now()
	c.mu.Lock()
	if s.handler != nil {
		c.mu.Unlock()
		return ErrRelayBusy
	}
	s.handler = handler
	s.hctx = ctx
	s.replay = map[string]*relayPage{}
	s.pages = make(chan relayPage, 2)
	c.mu.Unlock()
	defer c.stop(s, ErrRelayClosed)
	limit := c.replayLimit()
	id := "gw-inbox"
	var until *int64
	var sentAuth uint64
	request := func() error {
		// A fresh challenge blocks every REQ, including catchup pages.
		if e := c.awaitAuth(ctx, s, 0, c.Auth == RelayAuthRequired); e != nil {
			return e
		}
		c.mu.Lock()
		s.replay[id] = &relayPage{id: id}
		sentAuth = s.accepted
		c.mu.Unlock()
		filter := map[string]any{"kinds": []int{nostr.KindGiftWrap}, "#p": []string{pubkey}, "since": since, "limit": limit}
		if until != nil {
			filter["until"] = *until
		}
		return c.write(s, []any{"REQ", id, filter})
	}
	if err = request(); err != nil {
		return err
	}
	deadline := time.NewTimer(relayTimeout)
	defer deadline.Stop()
	pages, authRetries := 0, 0
	finish := func() error {
		deadline.Stop()
		if id == "gw-catchup" {
			if e := c.write(s, []any{"CLOSE", id}); e != nil {
				return e
			}
			c.mu.Lock()
			delete(s.replay, id)
			c.mu.Unlock()
		}
		c.status("RELAY_LIVE")
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			c.mu.Lock()
			err = s.err
			c.mu.Unlock()
			return err
		case err = <-s.closed:
			if err != ErrRelayAuthRequired || authRetries >= 1 {
				return err
			}
			authRetries++
			if err = c.awaitAuth(ctx, s, sentAuth, true); err != nil {
				return err
			}
			// Either subscription may have been closed by a new challenge. Restart
			// catchup from the unchanged floor, rather than restoring only a page
			// while accidentally leaving the broad live inbox unsubscribed.
			if err = c.write(s, []any{"CLOSE", "gw-catchup"}); err != nil {
				return err
			}
			c.mu.Lock()
			s.replay = map[string]*relayPage{}
			c.mu.Unlock()
			for len(s.pages) > 0 {
				<-s.pages
			}
			id, until, pages = "gw-inbox", nil, 0
			if err = request(); err != nil {
				return err
			}
			deadline.Reset(relayTimeout)
		case <-deadline.C:
			return ErrRelayProtocol // no EOSE is not evidence of complete replay
		case page := <-s.pages:
			pages++
			authRetries = 0
			if page.count < limit {
				if err = finish(); err != nil {
					return err
				}
				continue
			}
			// Equal-timestamp pages cannot advance using standard inclusive NIP01 until.
			// Report uncertainty, stop paging, and preserve the independent live inbox.
			if page.oldest == page.newest || page.oldest <= since || (until != nil && page.oldest >= *until) || pages >= maxReplayPages {
				c.replayOverflows.Add(1)
				c.status("REPLAY_OVERFLOW")
				if err = finish(); err != nil {
					return err
				}
				continue
			}
			next := page.oldest
			until = &next
			id = "gw-catchup"
			if err = request(); err != nil {
				return err
			}
			deadline.Reset(relayTimeout)
		}
	}
}
