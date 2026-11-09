package gateway

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The relay sends CLOSED then closes; the consumer waits for terminal publication.
// A permanent refusal must remain the terminal cause, including for later writes;
// an ordinary EOF remains transport loss. No scheduler sleep selects the outcome.
func TestRelayRefusalBeforeConsumer(t *testing.T) {
	for _, id := range []string{"gw-inbox", "gw-catchup"} {
		for _, tc := range []struct {
			name, reason string
			want         error
		}{
			{"restricted", "restricted: denied", ErrRelayRejected},
			{"other_policy", "error: unavailable", ErrRelayRejected},
			{"auth_disabled", "auth-required: denied", ErrRelayAuthRequired},
			{"transport", "", ErrRelayClosed},
		} {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				url := authFixture(t, func(conn *websocket.Conn, _ string) {
					typ, m := authRead(conn)
					var gotID string
					if len(m) > 1 {
						_ = json.Unmarshal(m[1], &gotID)
					}
					if typ != "REQ" || gotID != id {
						t.Error("fixture did not receive the subscription")
						return
					}
					if tc.reason != "" {
						if err := conn.WriteJSON([]any{"CLOSED", id, tc.reason}); err != nil {
							t.Error("fixture refusal write failed", err)
						}
					}
					// authFixture closes the socket as soon as this handler returns.
				})
				c := &RelayClient{URL: url}
				defer c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				s, err := c.connected(ctx)
				if err != nil {
					t.Fatal("connect", err)
				}
				if err = c.write(s, []any{"REQ", id, map[string]any{"kinds": []int{1059}, "#p": []string{strings.Repeat("a", 64)}}}); err != nil {
					t.Fatal("initial subscription", err)
				}
				// Neither s.closed nor the subscription's select is consumed until
				// terminal publication. The old implementation deterministically
				// records EOF here even though CLOSED was decoded first.
				select {
				case <-s.done:
				case <-ctx.Done():
					t.Fatal("reader did not terminate")
				}
				c.mu.Lock()
				got := s.err
				retired := c.session == nil
				c.mu.Unlock()
				if got != tc.want || !retired {
					t.Errorf("terminal refusal lost: got=%v want=%v retired=%v", got, tc.want, retired)
				}
				if got = c.write(s, []any{"CLOSE", id}); got != tc.want {
					t.Errorf("write reclassified terminal refusal: got=%v want=%v", got, tc.want)
				}
			})
		}
	}
}

type relayBlockedWriteConn struct {
	net.Conn
	block            bool
	entered, release chan struct{}
}

func (c *relayBlockedWriteConn) Write(b []byte) (int, error) {
	if !c.block {
		return c.Conn.Write(b)
	}
	close(c.entered)
	<-c.release
	return 0, net.ErrClosed
}

// Inject a write error after the live-session check but after another goroutine
// has recorded the terminal cause. The writer must retain that cause; ordinary
// transport failure remains retryable. The WebSocket handshake is real.
func TestRelayWritePreservesTerminalCause(t *testing.T) {
	for _, want := range []error{ErrRelayRejected, ErrRelayAuthRejected, ErrRelayProtocol, ErrRelayClosed} {
		t.Run(want.Error(), func(t *testing.T) {
			url := authFixture(t, func(conn *websocket.Conn, _ string) {
				_, _ = authRead(conn)
			})
			var gate *relayBlockedWriteConn
			dialer := websocket.Dialer{NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				gate = &relayBlockedWriteConn{Conn: conn, entered: make(chan struct{}), release: make(chan struct{})}
				return gate, nil
			}}
			conn, _, err := dialer.Dial(url, nil)
			if err != nil {
				t.Fatal("fixture handshake", err)
			}
			defer conn.Close()
			s := &relaySession{conn: conn, done: make(chan struct{})}
			c := &RelayClient{session: s}
			gate.block = true // Before starting the only post-handshake writer.
			result := make(chan error, 1)
			go func() { result <- c.write(s, []any{"CLOSE", "gw-inbox"}) }()
			defer func() {
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
			}()
			select {
			case <-gate.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("writer did not reach injected interleaving")
			}
			c.stop(s, want)
			close(gate.release)
			select {
			case got := <-result:
				if got != want {
					t.Fatalf("failed write lost terminal cause: got=%v want=%v", got, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("writer did not finish")
			}
			if got := c.sessionError(s); got != want {
				t.Fatalf("failed write changed session cause: got=%v want=%v", got, want)
			}
		})
	}
}
