package payload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxy "relux.works/swarma-chain-lab/experiments/model-proxy"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// The station uses real TLS and the actual stationlink HMAC protocol; the
// gateway frame source is scripted here. V2 ordinary delivery reaches the real
// proxy; v1/extend/end never call the model. Full gateway/Core is a separate run.
func TestScriptedSession(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(map[int]string{1: "v1", 2: "v2"}[version], func(t *testing.T) {
			f := newFixture(t)
			b := f.doc
			if version == 1 {
				b.V = 1
				b.ModelBearer = ""
				b.ModelEndpoint = ""
				b.ModelCertSHA256 = ""
			}
			c, e := New(encoded(t, b), Options{Model: modelID, MaxTokens: 10, Roots: f.roots})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			ln, e := tls.Listen("tcp", "127.0.0.1:0", f.front.TLS.Clone())
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				conn, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				fail := func() { done <- ErrChannel }
				hello, e := stationlink.ReadFrame(conn)
				if e != nil || hello.Type != stationlink.TypeHello || hello.SlotID != b.BookingID || hello.StationName != b.StationName {
					fail()
					return
				}
				nonce := strings.Repeat("a", 64)
				stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeChallenge, Nonce: nonce})
				auth, e := stationlink.ReadFrame(conn)
				if e != nil || auth.Type != stationlink.TypeAuth || !stationlink.VerifyResponse(b.ChannelSecret, nonce, b.BookingID, b.StationName, auth.Response) {
					fail()
					return
				}
				stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeSystem, SlotID: b.BookingID})
				for _, text := range []string{prompt, "__extend__", "__end_early__"} {
					pull, e := stationlink.ReadFrame(conn)
					if e != nil || pull.Type != stationlink.TypePull {
						fail()
						return
					}
					stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeDeliver, Content: text})
					reply, e := stationlink.ReadFrame(conn)
					if e != nil {
						fail()
						return
					}
					if text == "__end_early__" {
						if reply.Type != stationlink.TypeEndEarly {
							fail()
							return
						}
						stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeEnd})
						break
					}
					want := answer
					if version == 1 {
						want = "echo: " + prompt
					}
					if text == "__extend__" {
						if reply.Type != stationlink.TypeExtend {
							fail()
							return
						}
						stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeError})
						reply, e = stationlink.ReadFrame(conn)
						if e != nil {
							fail()
							return
						}
						want = "extend answered: error"
					}
					if reply.Type != stationlink.TypeReply || reply.Content != want {
						fail()
						return
					}
					stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeAck})
				}
				done <- nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if e = c.Run(ctx, ln.Addr().String(), pin(f.front.Certificate()), f.roots); e != nil {
				t.Fatal("scripted channel", e)
			}
			if e = <-done; e != nil {
				t.Fatal("stationlink script", e)
			}
			want := int32(version - 1)
			if f.upstream.Load() != want {
				t.Fatal("scripted control unexpectedly called model")
			}
		})
	}
}

// Each nonterminal caller attempt hits the source once. Redirects, malformed/oversized
// errors and interrupted responses cannot cause automatic retries, bearer forwarding, or
// reflection of attacker-controlled diagnostics. Only exact CAP/AUTH latch;
// other failures allow a later caller request. No environment proxy is used.
func TestHTTPFailures(t *testing.T) {
	for _, mode := range []string{"redirect", "malformed", "oversize", "truncated", "cap", "auth", "bad-status", "bad-success"} {
		t.Run(mode, func(t *testing.T) {
			var hits, forwarded, proxied atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Add(1) }))
			defer target.Close()
			envProxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied.Add(1) }))
			defer envProxy.Close()
			t.Setenv("HTTPS_PROXY", envProxy.URL)
			t.Setenv("HTTP_PROXY", envProxy.URL)
			t.Setenv("NO_PROXY", "")
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				switch mode {
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
				case "malformed":
					w.WriteHeader(403)
					io.WriteString(w, `{"error":"private-remote-marker"}`)
				case "oversize":
					w.WriteHeader(403)
					io.WriteString(w, strings.Repeat("x", 257))
				case "truncated":
					conn, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						conn.Close()
					}
				case "cap":
					w.WriteHeader(403)
					io.WriteString(w, `{"error":"CAP"}`)
				case "auth":
					w.WriteHeader(401)
					io.WriteString(w, `{"error":"AUTH"}`)
				case "bad-status":
					w.WriteHeader(404)
					io.WriteString(w, `{"error":"CAP"}`)
				case "bad-success":
					io.WriteString(w, `{"content":[{"type":"text","text":"private-remote-marker"}]}`)
				}
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			f := newFixture(t)
			b := f.doc
			b.ModelEndpoint = server.URL
			b.ModelCertSHA256 = pin(server.Certificate())
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			c, e := New(encoded(t, b), Options{Model: modelID, MaxTokens: 10, Roots: roots})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			want := error(ErrResponse)
			if mode == "redirect" || mode == "truncated" {
				want = ErrTransport
			}
			if mode == "cap" {
				want = Code("MODEL_CAP")
			}
			if mode == "auth" {
				want = Code("MODEL_AUTH")
			}
			for i := 0; i < 2; i++ {
				out, e := c.Respond(context.Background(), prompt)
				if e != want || out != "" {
					t.Fatal("HTTP failure not fixed/terminal")
				}
			}
			wantHits := int32(2)
			if mode == "cap" || mode == "auth" {
				wantHits = 1
			}
			if hits.Load() != wantHits || forwarded.Load() != 0 || proxied.Load() != 0 {
				t.Fatal("request retried, redirected or used env proxy")
			}
		})
	}
}

// A reserved, non-loopback hostname would use HTTPS_PROXY if enabled. Failure
// must happen without contacting that proxy; a valid real-proxy neighbor proves
// this is not a client that rejects every request. No production DNS is used.
func TestEnvironmentProxy(t *testing.T) {
	var hits atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer trap.Close()
	t.Setenv("HTTPS_PROXY", trap.URL)
	t.Setenv("NO_PROXY", "")
	// Set the trap before any request: net/http caches environment proxy config
	// on first use, including a loopback request which ultimately bypasses it.
	f := newFixture(t)
	if _, e := f.client(t).Respond(context.Background(), prompt); e != nil {
		t.Fatal("proxy environment positive neighbor", e)
	}
	b := f.doc
	b.ModelEndpoint = "https://model.invalid"
	c, e := New(encoded(t, b), Options{Model: modelID, MaxTokens: 10, Roots: f.roots})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if out, e := c.Respond(ctx, prompt); e != ErrTransport || out != "" || hits.Load() != 0 {
		t.Fatal("environment proxy contacted or failure escaped")
	}
}

// Positive response schema is parsed through the same reviewed Messages dialect;
// tool blocks, bad usage and output exceeding the channel bound never escape.
func TestResponseBounds(t *testing.T) {
	for _, mode := range []string{"valid", "tool", "usage", "large-text", "large-body"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "large-body" {
					io.WriteString(w, strings.Repeat("x", proxy.MaxResponse+1))
					return
				}
				text := answer
				if mode == "large-text" {
					text = strings.Repeat("x", MaxText+1)
				}
				b, _ := json.Marshal(text)
				block := `{"type":"text","text":` + string(b) + `}`
				if mode == "tool" {
					block = `{"type":"tool_use","id":"x","name":"x","input":{}}`
				}
				usage := `{"input_tokens":7,"output_tokens":3}`
				if mode == "usage" {
					usage = `{"input_tokens":7}`
				}
				io.WriteString(w, `{"id":"fixture","type":"message","role":"assistant","model":"`+modelID+`","content":[`+block+`],"stop_reason":"end_turn","usage":`+usage+`}`)
			}))
			defer server.Close()
			b := f.doc
			b.ModelEndpoint = server.URL
			b.ModelCertSHA256 = pin(server.Certificate())
			c, e := New(encoded(t, b), Options{Model: modelID, MaxTokens: 10, Roots: f.roots})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			out, e := c.Respond(context.Background(), prompt)
			if mode == "valid" {
				if e != nil || out != answer {
					t.Fatal("response neighbor refused")
				}
			} else if e != ErrResponse || out != "" {
				t.Fatal("invalid model response escaped")
			}
		})
	}
}

// A cancelled station run closes the actual blocked TLS channel. A wrong server
// pin cannot send hello even when the certificate chain itself is trusted.
func TestChannelBounds(t *testing.T) {
	for _, mode := range []string{"cancel", "wrong-pin"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			b := f.doc
			b.V = 1
			b.ModelBearer = ""
			b.ModelEndpoint = ""
			b.ModelCertSHA256 = ""
			c, e := New(encoded(t, b), Options{})
			if e != nil {
				t.Fatal(e)
			}
			ln, e := tls.Listen("tcp", "127.0.0.1:0", f.front.TLS.Clone())
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			read := make(chan bool, 1)
			closed := make(chan bool, 1)
			go func() {
				conn, e := ln.Accept()
				if e != nil {
					read <- false
					closed <- false
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				frame, e := stationlink.ReadFrame(conn)
				read <- e == nil && frame.Type == stationlink.TypeHello
				if e == nil {
					_, e = stationlink.ReadFrame(conn)
				}
				closed <- e != nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			p := pin(f.front.Certificate())
			if mode == "wrong-pin" {
				p = strings.Repeat("a", 64)
			}
			if e = c.Run(ctx, ln.Addr().String(), p, f.roots); e != ErrChannel {
				t.Fatal("invalid channel accepted")
			}
			if got := <-read; got != (mode == "cancel") {
				t.Fatal("TLS handshake boundary")
			}
			if !<-closed || mode == "cancel" && ctx.Err() != context.DeadlineExceeded {
				t.Fatal("cancel did not close blocked channel")
			}
		})
	}
}

// A lost response after a real proxy generation does not trigger an automatic
// replay. A later caller request is charged separately; neither it nor another
// attempt can bypass the same slot cap or reset the terminal CAP latch.
func TestResponseLossAccounting(t *testing.T) {
	f := newFixture(t)
	c := f.client(t)
	transport := c.http.Transport
	calls := 0
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		res, e := transport.RoundTrip(r)
		calls++
		if e == nil && calls == 1 {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			res.Body = io.NopCloser(strings.NewReader("{"))
		}
		return res, e
	})
	if out, e := c.Respond(context.Background(), prompt); out != "" || e != ErrResponse {
		t.Fatal("lost response escaped", e)
	}
	st, e := f.s.Status(f.b.SlotID)
	if e != nil || st.Exposure.Requests != 1 || f.requests.Load() != 1 || f.upstream.Load() != 1 {
		t.Fatal("lost response retried or uncharged")
	}
	if out, e := c.Respond(context.Background(), prompt); e != nil || out != answer {
		t.Fatal("nonterminal response failure latched", e)
	}
	for i := 0; i < 2; i++ {
		if out, e := c.Respond(context.Background(), prompt); out != "" || e != Code("MODEL_CAP") {
			t.Fatal("lost response bypassed cap", e)
		}
	}
	st, e = f.s.Status(f.b.SlotID)
	if e != nil || st.Exposure != (proxy.Counts{Input: 14, Output: 6, Requests: 2, Cost: 46}) || f.requests.Load() != 3 || f.upstream.Load() != 2 {
		t.Fatal("response recovery changed accounting")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
