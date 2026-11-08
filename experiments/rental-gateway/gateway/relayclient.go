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

// RelayClient is the gateway's websocket client to one relay. It
// publishes signed events and streams gift wraps addressed to the
// agent key. In tests it talks to testrelay on 127.0.0.1.
type RelayClient struct {
	URL string

	mu   sync.Mutex
	conn *websocket.Conn
}

// Dial connects (idempotent while connected).
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
	return nil
}

// Close closes the websocket.
func (c *RelayClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
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

// Publish implements Publisher: send ["EVENT", ev] (the relay's OK is
// consumed by the subscription read loop when one runs; without a
// read loop, callers that need OK should use PublishAndWait).
func (c *RelayClient) Publish(ctx context.Context, ev *nostr.Event) error {
	if err := c.Dial(ctx); err != nil {
		return err
	}
	return c.writeJSON([]any{"EVENT", ev})
}

// SubscribeGiftWraps sends a REQ for kind-1059 events p-tagged to the
// agent and invokes handler for each event until the connection or
// ctx ends. It also drains OK/NOTICE frames. Run at most one per
// client (it owns the read side).
func (c *RelayClient) SubscribeGiftWraps(ctx context.Context, agentPubKey string,
	handler func(ctx context.Context, ev *nostr.Event)) error {
	if err := c.Dial(ctx); err != nil {
		return err
	}
	subID := "gw-inbox"
	filter := map[string]any{"kinds": []int{nostr.KindGiftWrap}, "#p": []string{agentPubKey}}
	if err := c.writeJSON([]any{"REQ", subID, filter}); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	for {
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			return ctx.Err()
		}
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		var msg []json.RawMessage
		if json.Unmarshal(raw, &msg) != nil || len(msg) < 2 {
			continue
		}
		var typ string
		_ = json.Unmarshal(msg[0], &typ)
		if typ != "EVENT" || len(msg) != 3 {
			continue // OK / EOSE / NOTICE drained here
		}
		ev, err := nostr.ParseEvent(msg[2])
		if err != nil {
			continue // malformed relay traffic never reaches the pipeline
		}
		handler(ctx, ev)
	}
}
