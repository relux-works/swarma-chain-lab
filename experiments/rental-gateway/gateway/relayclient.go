package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// RelayClient is the gateway's websocket client to one relay (the
// Nostr implementation of the renter Transport). A single read pump
// (started at Dial) dispatches subscription EVENTs to the handler
// and OK replies to waiting Publish calls: Publish returns only
// after the relay accepted the event (RM2 M7).
type RelayClient struct {
	URL string

	mu      sync.Mutex
	conn    *websocket.Conn
	handler func(ctx context.Context, ev *nostr.Event)
	hctx    context.Context
	waiters map[string]chan error
	pumpErr chan error
}

// Dial connects and starts the read pump (idempotent).
func (c *RelayClient) Dial(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := d.DialContext(ctx, c.URL, nil)
	if err != nil {
		return err
	}
	c.conn = conn
	c.waiters = map[string]chan error{}
	c.pumpErr = make(chan error, 1)
	go c.pump(conn)
	return nil
}

// Close closes the websocket; pending publishers fail.
func (c *RelayClient) Close() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (c *RelayClient) pump(conn *websocket.Conn) {
	var pumpErr error
	defer func() {
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		waiters := c.waiters
		c.waiters = map[string]chan error{}
		errCh := c.pumpErr
		c.mu.Unlock()
		for _, ch := range waiters {
			if pumpErr == nil {
				pumpErr = fmt.Errorf("relay client: connection closed")
			}
			ch <- pumpErr
		}
		if errCh != nil {
			errCh <- pumpErr
		}
	}()
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			pumpErr = err
			return
		}
		var msg []json.RawMessage
		if json.Unmarshal(raw, &msg) != nil || len(msg) < 2 {
			continue
		}
		var typ string
		_ = json.Unmarshal(msg[0], &typ)
		switch typ {
		case "OK":
			if len(msg) < 4 {
				continue
			}
			var id string
			var accepted bool
			var reason string
			_ = json.Unmarshal(msg[1], &id)
			_ = json.Unmarshal(msg[2], &accepted)
			_ = json.Unmarshal(msg[3], &reason)
			c.mu.Lock()
			ch := c.waiters[id]
			delete(c.waiters, id)
			c.mu.Unlock()
			if ch != nil {
				if accepted {
					ch <- nil
				} else {
					ch <- fmt.Errorf("relay rejected event %s: %s", id, reason)
				}
			}
		case "EVENT":
			if len(msg) != 3 {
				continue
			}
			ev, err := nostr.ParseEvent(msg[2])
			if err != nil {
				continue
			}
			c.mu.Lock()
			h, hctx := c.handler, c.hctx
			c.mu.Unlock()
			if h != nil {
				h(hctx, ev)
			}
		}
	}
}

func (c *RelayClient) writeJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("relay client: not connected")
	}
	return c.conn.WriteJSON(v)
}

// Publish implements Publisher: write ["EVENT", ev] and await the
// relay's OK for that event id. A rejection, disconnect or context
// expiry is an error: callers never mistake "written" for "sent".
func (c *RelayClient) Publish(ctx context.Context, ev *nostr.Event) error {
	if err := c.Dial(ctx); err != nil {
		return err
	}
	ch := make(chan error, 1)
	c.mu.Lock()
	if c.waiters == nil {
		c.waiters = map[string]chan error{}
	}
	c.waiters[ev.ID] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, ev.ID)
		c.mu.Unlock()
	}()
	if err := c.writeJSON([]any{"EVENT", ev}); err != nil {
		return err
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SubscribeGiftWraps sends a REQ for kind-1059 events p-tagged to
// the given pubkey and blocks until ctx ends or the pump dies.
// Events reach handler through the pump started at Dial.
func (c *RelayClient) SubscribeGiftWraps(ctx context.Context, pubkey string,
	handler func(ctx context.Context, ev *nostr.Event)) error {
	if err := c.Dial(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.handler = handler
	c.hctx = ctx
	errCh := c.pumpErr
	c.mu.Unlock()
	subID := "gw-inbox"
	filter := map[string]any{"kinds": []int{nostr.KindGiftWrap}, "#p": []string{pubkey}}
	if err := c.writeJSON([]any{"REQ", subID, filter}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		c.Close()
		return ctx.Err()
	case err := <-errCh:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
}
