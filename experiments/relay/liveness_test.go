package relay

import (
	"github.com/gorilla/websocket"
	"sync/atomic"
	"testing"
	"time"
)

// Real idle WebSockets survive more than three policy deadlines only when the
// peer answers admitted server pings; an unresponsive neighbor is still cut.
func TestRelayIdleLiveness(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.ReadTimeoutMilliseconds = 300
	cfg.PingIntervalMilliseconds = 60
	_, url := serve(t, cfg)
	for _, respond := range []bool{true, false} {
		t.Run(map[bool]string{true: "pong", false: "silent"}[respond], func(t *testing.T) {
			c, _, err := websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var pings atomic.Int32
			c.SetPingHandler(func(s string) error {
				pings.Add(1)
				if !respond {
					return nil
				}
				return c.WriteControl(websocket.PongMessage, []byte(s), time.Now().Add(time.Second))
			})
			done := make(chan error, 1)
			go func() {
				for {
					_, _, e := c.ReadMessage()
					if e != nil {
						done <- e
						return
					}
				}
			}()
			defer func() {
				c.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("idle reader leaked")
				}
			}()
			if respond {
				select {
				case e := <-done:
					done <- e
					t.Fatal("keepalive did not survive three deadlines")
				case <-time.After(4 * cfg.readTimeout()):
				}
				if pings.Load() < 10 {
					t.Fatal("server heartbeat absent")
				}
			} else {
				select {
				case e := <-done:
					done <- e
					if e == nil {
						t.Fatal("silent peer was not refused")
					}
				case <-time.After(3 * cfg.readTimeout()):
					t.Fatal("silent peer was not refused")
				}
			}
		})
	}
}

// Both incoming control kinds share the normal per-peer frame budget. Exhaustion
// closes that peer; a different peer below the IP budget can still exchange ping.
func TestControlFrameQuota(t *testing.T) {
	for _, kind := range []int{websocket.PingMessage, websocket.PongMessage} {
		t.Run(map[int]string{websocket.PingMessage: "ping", websocket.PongMessage: "pong"}[kind], func(t *testing.T) {
			cfg := fixtureConfig(t)
			cfg.FramesPerMinute = 3
			cfg.FramesPerIPMinute = 100
			_, url := serve(t, cfg)
			c, _, e := websocket.DefaultDialer.Dial(url, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			for range 4 {
				_ = c.WriteControl(kind, nil, time.Now().Add(time.Second))
			}
			done := make(chan error, 1)
			go func() { _, _, e := c.ReadMessage(); done <- e }()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("control quota bypass")
				}
			case <-time.After(time.Second):
				c.Close()
				<-done
				t.Fatal("control quota bypass")
			}
			healthy, _, e := websocket.DefaultDialer.Dial(url, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer healthy.Close()
			pong := make(chan struct{}, 1)
			healthy.SetPongHandler(func(string) error { pong <- struct{}{}; return nil })
			ended := make(chan struct{})
			go func() { defer close(ended); _, _, _ = healthy.ReadMessage() }()
			if e = healthy.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			select {
			case <-pong:
			case <-time.After(time.Second):
				t.Error("healthy control neighbor refused")
			}
			healthy.Close()
			<-ended
		})
	}
}

// Invalid heartbeat/deadline pairs fail before opening state; legacy zeros keep
// the old90s idle policy with30s pings, and a short valid test policy is accepted.
func TestLivenessConfig(t *testing.T) {
	c := fixtureConfig(t)
	if c.Validate() != nil || c.readTimeout() != 90*time.Second || c.pingInterval() != 30*time.Second {
		t.Fatal("legacy liveness defaults")
	}
	for _, v := range [][2]int{{-1, 30}, {300, 300}, {300, 301}, {99, 10}, {300, 9}, {300001, 30}, {300, -1}} {
		c.ReadTimeoutMilliseconds = v[0]
		c.PingIntervalMilliseconds = v[1]
		if e := c.Validate(); e == nil || e.Error() != "CONFIG_LIVENESS" {
			t.Fatal("invalid liveness accepted")
		}
	}
	c.ReadTimeoutMilliseconds = 300
	c.PingIntervalMilliseconds = 60
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}
