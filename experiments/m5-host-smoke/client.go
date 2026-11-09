package smoke

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type received struct {
	content string
	at      int64
}

type conversation struct {
	peer          *gateway.RelayClient
	key           *nostr.PrivKey
	agent         string
	inbox         chan received
	fault         chan error
	done          chan struct{}
	cancel        context.CancelFunc
	started       int64
	lastSend      time.Time
	lastReply     time.Time
	lastRequestAt int64
	restartAt     int64
	notices       []string
	seen          map[string]bool
	mu            sync.Mutex
}

func connect(ctx context.Context, url, agent string) (*conversation, error) {
	key, e := nostr.GeneratePrivKey()
	if e != nil {
		return nil, refuse("RENTER_KEY")
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &conversation{key: key, agent: agent, inbox: make(chan received, 256), fault: make(chan error, 1), done: make(chan struct{}), cancel: cancel, started: time.Now().Unix(), seen: map[string]bool{}}
	live := make(chan struct{}, 1)
	c.peer = &gateway.RelayClient{URL: url, Auth: gateway.RelayAuthWhenChallenged, AgentKey: key, OnStatus: func(s gateway.RelayStatus) {
		if s.Reason == "RELAY_LIVE" {
			select {
			case live <- struct{}{}:
			default:
			}
		} else {
			c.fail("RELAY_LIVENESS")
		}
	}}
	go func() {
		defer close(c.done)
		e := c.peer.RunGiftWraps(ctx, key.PubKeyHex(), func(_ context.Context, ev *nostr.Event) {
			if e := c.accept(ev); e != nil {
				c.fail(code(e))
			}
		})
		if ctx.Err() == nil && e != nil {
			c.fail("RELAY_SUBSCRIPTION")
		}
	}()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-live:
		return c, nil
	case e := <-c.fault:
		c.close()
		return nil, e
	case <-ctx.Done():
		c.close()
		return nil, refuse("CANCELLED")
	case <-timer.C:
		c.close()
		return nil, refuse("RELAY_START")
	}
}
func (c *conversation) fail(s string) {
	select {
	case c.fault <- refuse(s):
	default:
	}
	c.cancel()
}
func (c *conversation) close() { c.cancel(); c.peer.Close(); <-c.done }
func (c *conversation) healthy() error {
	select {
	case e := <-c.fault:
		return e
	default:
		return nil
	}
}
func pause(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return refuse("CANCELLED")
	}
}
func (c *conversation) send(ctx context.Context, text string, work int, pace time.Duration, tags ...[]string) error {
	if e := c.healthy(); e != nil {
		return e
	}
	// Native replies carry second-resolution timestamps and no request nonce.
	// Separate replies in time so distinct equal-content replies have distinct
	// rumor IDs; do not weaken replay suppression to count them twice.
	next := c.lastSend.Add(pace)
	if replyFloor := c.lastReply.Add(1100 * time.Millisecond); replyFloor.After(next) {
		next = replyFloor
	}
	if e := pause(ctx, time.Until(next)); e != nil {
		return e
	}
	r := &nostr.Event{PubKey: c.key.PubKeyHex(), CreatedAt: time.Now().Unix(), Kind: nostr.KindRumor, Content: text, Tags: append([][]string{{"p", c.agent}}, tags...)}
	if work > 0 {
		r.Tags = append(r.Tags, []string{"nonce", "0", strconv.Itoa(work)})
		for n := 0; ; n++ {
			if n%1024 == 0 && ctx.Err() != nil {
				return refuse("CANCELLED")
			}
			r.Tags[len(r.Tags)-1][1] = strconv.Itoa(n)
			r.ID = r.ComputeID()
			if exchange.CheckWork(r, work) {
				break
			}
		}
	} else {
		r.ID = r.ComputeID()
	}
	c.lastRequestAt = r.CreatedAt
	ev, e := nostr.GiftWrap(r, c.key, c.agent, time.Now().Unix())
	if e != nil {
		return refuse("WRAP")
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e = c.peer.Publish(bounded, ev); e != nil {
		return refuse("PUBLISH")
	}
	c.lastSend = time.Now()
	return nil
}
func (c *conversation) receive(ctx context.Context, timeout time.Duration) (string, error) {
	if e := c.healthy(); e != nil {
		return "", e
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case s := <-c.inbox:
		c.lastReply = time.Now()
		return s.content, nil
	case e := <-c.fault:
		return "", e
	case <-ctx.Done():
		return "", refuse("CANCELLED")
	case <-t.C:
		return "", refuse("REPLY_TIMEOUT")
	}
}
func (c *conversation) expect(ctx context.Context, want string, timeout time.Duration) error {
	s, e := c.receive(ctx, timeout)
	if e != nil {
		return e
	}
	if s != want {
		return refuse("REPLY_EXACT")
	}
	return nil
}
func (c *conversation) object(ctx context.Context, prefix string, v any, timeout time.Duration) error {
	s, e := c.receive(ctx, timeout)
	if e != nil {
		return e
	}
	if !strings.HasPrefix(s, prefix+"\n") {
		return refuse("REPLY_KIND")
	}
	return Strict([]byte(strings.TrimPrefix(s, prefix+"\n")), v)
}
func get(ctx context.Context, origin, path string, v any) error {
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(origin, "/")+path, nil)
	if e != nil {
		return refuse("HTTP_REQUEST")
	}
	tr := &http.Transport{Proxy: nil}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return refuse("HTTP_REDIRECT") }}
	res, e := client.Do(req)
	if e != nil {
		return refuse("HTTP_TRANSPORT")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return refuse("HTTP_STATUS")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, (256<<10)+1))
	if e != nil {
		return refuse("HTTP_BODY")
	}
	return Strict(raw, v)
}

func (c *conversation) accept(ev *nostr.Event) error {
	u, e := nostr.UnwrapDM(ev, c.key)
	if e != nil || u.SenderHex != c.agent || u.Rumor == nil || u.Rumor.CreatedAt < c.started || u.Rumor.CreatedAt > time.Now().Add(5*time.Second).Unix() {
		return refuse("REPLY_AUTH")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[u.Rumor.ID] {
		return nil
	}
	if len(c.seen) >= 1024 {
		return refuse("REPLY_LIMIT")
	}
	c.seen[u.Rumor.ID] = true
	select {
	case c.inbox <- received{u.Rumor.Content, u.Rumor.CreatedAt}:
		return nil
	default:
		return refuse("REPLY_OVERFLOW")
	}
}

// No unsolicited payload text may be hidden in the inbox during closure.
func (c *conversation) quiet(scenario string, notAfter int64) error {
	for {
		select {
		case s := <-c.inbox:
			kind := ""
			switch {
			case c.restartAt > 0 && s.at >= c.restartAt && (s.content == exchange.Help || s.content == exchange.NotLive):
				kind = "restart_exchange_refusal"
			case scenario == "revoke" && s.at >= c.lastRequestAt:
				if s.content == exchange.Help {
					kind = "revoke_exchange_help"
				} else if s.content == exchange.NotLive {
					kind = "revoke_not_live"
				}
			case scenario == "expiry" && s.content == "slot ended" && s.at >= notAfter && time.Now().Unix() >= notAfter:
				kind = "expiry_slot_ended"
			}
			if kind == "" {
				return refuse("UNEXPECTED_CLOSED_REPLY")
			}
			c.notices = append(c.notices, kind)
		default:
			return c.healthy()
		}
	}
}
