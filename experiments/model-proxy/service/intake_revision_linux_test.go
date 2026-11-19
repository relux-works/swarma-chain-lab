//go:build linux

package service

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Claim: case-insensitive HTTP names cannot smuggle pricing beta flags or
// ambiguous duplicates; the canonical base request still reaches the upstream.
func TestIntakeHeaderCanonicalization(t *testing.T) {
	for _, header := range []string{"control", "beta-control", "Anthropic-Beta", "anthropic-beta", "ANTHROPIC-BETA", "aNtHrOpIc-BeTa", "duplicate", "alias-duplicate", "beta-duplicate", "beta-alias"} {
		t.Run(header, func(t *testing.T) {
			var calls atomic.Int32
			_, source, client, _, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return intakeResponse(200, "{}"), nil
			}, nil)
			request := intakeRequest(t, "POST", "/v1/messages", "{}")
			switch header {
			case "control":
			case "beta-control":
				request.Header["anthropic-beta"] = []string{"oauth-2025-04-20"}
			case "duplicate":
				request.Header["Authorization"] = []string{"Bearer " + Placeholder, "Bearer " + Placeholder}
			case "alias-duplicate":
				request.Header["authorization"] = []string{"Bearer " + Placeholder}
			case "beta-duplicate":
				request.Header["Anthropic-Beta"] = []string{"oauth-2025-04-20", "claude-code-20250219"}
			case "beta-alias":
				request.Header["Anthropic-Beta"] = []string{"oauth-2025-04-20"}
				request.Header["anthropic-beta"] = []string{"claude-code-20250219"}
			default:
				request.Header[header] = []string{"fast-mode-2026-02-01"}
			}
			request.URL.Scheme, request.URL.Host = "", ""
			if (header == "alias-duplicate" || header == "beta-alias") && intakeShape(request) {
				t.Fatal("case-aliased duplicate header accepted")
			}
			request.URL.Scheme, request.URL.Host = "http", "api.anthropic.com"
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("header test transport failed")
			}
			defer response.Body.Close()
			if header == "control" || header == "beta-control" {
				if response.StatusCode != 200 || calls.Load() != 1 {
					t.Fatal("canonical header control refused")
				}
			} else {
				status, leases := 403, int32(1)
				if header == "duplicate" || header == "alias-duplicate" || header == "beta-duplicate" || header == "beta-alias" {
					status, leases = 400, 0
				}
				if response.StatusCode != status || source.calls.Load() != leases || calls.Load() != 0 {
					t.Fatal("ambiguous or unpriced header reached upstream")
				}
			}
		})
	}
}

// Claim: the measured OAuth launch profile and its subsets remain admissible;
// unknown, fast/context-extension and duplicate beta flags do not gain pricing.
func TestIntakeBetaProfile(t *testing.T) {
	profile := "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,tool-provenance-2026-10-26,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07"
	for _, value := range []string{"", "oauth-2025-04-20", profile} {
		if !pricedBetaProfile(value) {
			t.Fatal("measured OAuth profile refused")
		}
	}
	for _, value := range []string{"fast-mode-2026-02-01", "context-1m-future", "unknown", "oauth-2025-04-20,oauth-2025-04-20", "oauth-2025-04-20,"} {
		if pricedBetaProfile(value) {
			t.Fatal("unpriced or duplicate beta profile admitted")
		}
	}
}

// Claim: header silence is allowed beyond the body idle interval, up to the
// injected generation-header budget; exceeding that budget cancels the call.
func TestIntakeHeaderStallBoundary(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "stalled"}[stalled], func(t *testing.T) {
			cancelled := make(chan struct{})
			gateway, _, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
				select {
				case <-time.After(240 * time.Millisecond):
					if !stalled {
						return intakeResponse(201, "{}"), nil
					}
				case <-request.Context().Done():
				}
				<-request.Context().Done()
				close(cancelled)
				return nil, request.Context().Err()
			}, nil)
			gateway.idleTimeout = 30 * time.Millisecond
			gateway.headerTimeout = 350 * time.Millisecond
			started := time.Now()
			response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", "{}"))
			if err != nil {
				t.Fatal("header budget did not return a bounded response")
			}
			defer response.Body.Close()
			if !stalled {
				if response.StatusCode != 201 {
					t.Fatal("valid delayed non-streaming response refused")
				}
			} else {
				if response.StatusCode != 502 || time.Since(started) > time.Second {
					t.Fatal("header stall did not end at its generation budget")
				}
				select {
				case <-cancelled:
				default:
					t.Fatal("header stall left upstream alive")
				}
			}
		})
	}
}

// Claim: the production default permits a non-streaming answer after 31 s,
// longer than both the former 30 s cap and this test's body idle interval.
func TestIntakeNonStreamingHeaderDelay(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		select {
		case <-time.After(31 * time.Second):
			_, _ = io.WriteString(writer, "delayed-control")
		case <-request.Context().Done():
		}
	}))
	defer upstream.Close()
	gateway, _, client, _, _ := intakeFixture(t, false, nil, nil)
	transport := gateway.transport.(*http.Transport)
	transport.TLSClientConfig = upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	gateway.idleTimeout = 100 * time.Millisecond
	client.Timeout = 35 * time.Second
	if gateway.headerTimeout < 10*time.Minute {
		t.Fatal("non-streaming header budget regressed below ten minutes")
	}
	response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", "{}"))
	if err != nil {
		t.Fatal("long non-streaming control transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("long non-streaming response cut at a short fixed cap")
	}
}

// Claim: a request body making progress just inside the injected read budget
// works; a silent partial body is refused before reservation, lease or I/O.
func TestIntakeRequestReadBudget(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "stalled"}[stalled], func(t *testing.T) {
			var calls atomic.Int32
			gateway, source, _, socket, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return intakeResponse(200, "{}"), nil
			}, nil)
			gateway.readTimeout = 200 * time.Millisecond
			conn, err := net.Dial("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer ssh-placeholder\r\nContent-Length: 2\r\n\r\n{")
			if !stalled {
				time.Sleep(80 * time.Millisecond)
				_, _ = io.WriteString(conn, "}")
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal("body read budget failed to return a refusal")
			}
			defer response.Body.Close()
			if !stalled {
				if response.StatusCode != 200 || calls.Load() != 1 {
					t.Fatal("progressing request control refused")
				}
			} else if response.StatusCode != 400 || source.calls.Load() != 0 || calls.Load() != 0 {
				t.Fatal("stalled request reached upstream")
			}
		})
	}
}

// Claim: a complete declared body is served; an early write-half close is a
// 400 with no lease/provider call, never a silently truncated upstream request.
func TestIntakeTruncatedRequestBody(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "truncated"}[truncated], func(t *testing.T) {
			var calls atomic.Int32
			_, source, _, socket, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return intakeResponse(200, "{}"), nil
			}, nil)
			conn, err := net.Dial("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			body := "{}"
			if truncated {
				body = "{"
			}
			_, _ = io.WriteString(conn, "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer ssh-placeholder\r\nContent-Length: 2\r\n\r\n"+body)
			if truncated {
				_ = conn.(*net.UnixConn).CloseWrite()
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal("truncated-body refusal unavailable")
			}
			defer response.Body.Close()
			if truncated {
				if response.StatusCode != 400 || calls.Load() != 0 || source.calls.Load() != 0 {
					t.Fatal("truncated body reached the provider")
				}
			} else if response.StatusCode != 200 || calls.Load() != 1 {
				t.Fatal("complete body control refused")
			}
		})
	}
}

// Claim: a worker that stops reading cannot pin the handler in Write or Flush;
// a slow reader progressing inside the idle interval receives the whole body.
func TestIntakeWriteStall(t *testing.T) {
	for _, scenario := range []struct {
		name                       string
		stalled, buffered, revoked bool
	}{
		{"progress", false, false, false},
		{"stalled", true, false, false},
		{"flush-progress", false, true, false},
		{"flush-stalled", true, true, false},
		{"revoked", true, false, true},
	} {
		stalled := scenario.stalled
		t.Run(scenario.name, func(t *testing.T) {
			cancelled := make(chan struct{})
			gateway, _, _, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
				context.AfterFunc(request.Context(), func() { close(cancelled) })
				reader, writer := io.Pipe()
				go func() {
					defer writer.Close()
					for range 128 {
						if _, err := io.WriteString(writer, strings.Repeat("x", 8192)); err != nil {
							return
						}
					}
				}()
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: reader}, nil
			}, nil)
			gateway.idleTimeout = 150 * time.Millisecond
			if scenario.revoked {
				gateway.idleTimeout = 5 * time.Second
			}
			serverConn, workerConn := net.Pipe()
			defer serverConn.Close()
			defer workerConn.Close()
			writer := &deadlineResponse{conn: serverConn, buffered: scenario.buffered, blocked: make(chan struct{})}
			request := intakeRequest(t, "POST", "/v1/messages", "{}")
			request.URL.Scheme, request.URL.Host = "", ""
			request = request.WithContext(context.WithValue(request.Context(), gatewayPeerKey{}, gatewayPeer{uid: gateway.mapping.Caller.UID}))
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
						panic(recovered)
					}
				}()
				gateway.ServeHTTP(writer, request)
			}()
			if stalled {
				if _, err := workerConn.Read(make([]byte, 8192)); err != nil {
					t.Fatal("mid-stream control did not start")
				}
				select {
				case <-writer.blocked:
				case <-time.After(time.Second):
					t.Fatal("worker write did not enter its stalled path")
				}
				if scenario.revoked {
					gateway.Close()
				}
			}
			if !stalled {
				go func() {
					buffer := make([]byte, 8192)
					for {
						if _, err := workerConn.Read(buffer); err != nil {
							return
						}
						time.Sleep(3 * time.Millisecond)
					}
				}()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("downstream write stall pinned the handler")
			}
			if stalled && writer.written != 8192 || !stalled && writer.written != 128*8192 {
				t.Fatalf("write-stall result did not match reader progress: bytes=%d", writer.written)
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("write completion left upstream authority alive")
			}
		})
	}
}

type deadlineResponse struct {
	conn     net.Conn
	written  int
	buffered bool
	pending  []byte
	blocked  chan struct{}
	attempts int
}

func (*deadlineResponse) Header() http.Header { return http.Header{} }
func (*deadlineResponse) WriteHeader(int)     {}
func (writer *deadlineResponse) FlushError() error {
	if !writer.buffered {
		return nil
	}
	count, err := writer.write(writer.pending)
	writer.written += count
	writer.pending = nil
	return err
}
func (writer *deadlineResponse) SetWriteDeadline(deadline time.Time) error {
	return writer.conn.SetWriteDeadline(deadline)
}
func (writer *deadlineResponse) Write(body []byte) (int, error) {
	if writer.buffered {
		writer.pending = append(writer.pending, body...)
		return len(body), nil
	}
	count, err := writer.write(body)
	writer.written += count
	return count, err
}

func (writer *deadlineResponse) write(body []byte) (int, error) {
	writer.attempts++
	if writer.attempts == 2 {
		close(writer.blocked)
	}
	return writer.conn.Write(body)
}

type repeatedBody struct{}

// Claim: eight simultaneous small requests are valid; a ninth refuses before
// leasing even when their byte windows would fit, and all eight controls finish.
func TestIntakeConcurrentCallLimit(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	arrived := make(chan struct{}, 9)
	_, source, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, request.Body)
		arrived <- struct{}{}
		<-release
		return intakeResponse(200, "{}"), nil
	}, nil)
	statuses := make(chan int, 8)
	for range 8 {
		go func() {
			response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", "{}"))
			if err != nil {
				statuses <- 0
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	for range 8 {
		select {
		case <-arrived:
		case <-time.After(time.Second):
			t.Fatal("eight-call positive control did not arrive")
		}
	}
	response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", "{}"))
	if err != nil {
		t.Fatal("call-limit refusal unavailable")
	}
	_ = response.Body.Close()
	if response.StatusCode != 503 || source.calls.Load() != 8 {
		t.Fatal("ninth body-owning request exceeded the call limit")
	}
	releaseOnce.Do(func() { close(release) })
	for range 8 {
		if <-statuses != 200 {
			t.Fatal("valid call-limit control failed")
		}
	}
}

func (repeatedBody) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}

// Claim: two concurrent 64 MiB windows fit, but another large or unknown-length
// body gets 503 before reading or leasing; released capacity admits a retry.
// The heap bound measures raw intake buffers, not the parent JSON parser.
func TestIntakeConcurrentBodyMemory(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	arrived := make(chan struct{}, 8)
	gateway, _, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, request.Body)
		arrived <- struct{}{}
		<-release
		return intakeResponse(200, "{}"), nil
	}, nil)
	client.Timeout = 10 * time.Second
	runtime.GC()
	var before, held runtime.MemStats
	runtime.ReadMemStats(&before)
	statuses := make(chan int, 2)
	for range 2 {
		go func() {
			request := intakeRequest(t, "POST", "/v1/messages", "")
			request.Body = io.NopCloser(io.LimitReader(repeatedBody{}, (64<<20)-1))
			request.ContentLength = (64 << 20) - 1
			response, err := client.Do(request)
			if err != nil {
				statuses <- 0
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent large-body controls failed")
		}
	}
	runtime.ReadMemStats(&held)
	if held.HeapAlloc > before.HeapAlloc+2*MaxIntakeMemory+(32<<20) {
		t.Fatal("concurrent body buffers exceeded their measured memory bound")
	}
	for _, length := range []int64{64 << 20, -1} {
		request := intakeRequest(t, "POST", "/v1/messages", "x")
		if length > 0 {
			request.Body = io.NopCloser(io.LimitReader(repeatedBody{}, length))
		}
		request.ContentLength = length
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("over-budget body did not get a closed refusal")
		}
		_ = response.Body.Close()
		if response.StatusCode != 503 {
			t.Fatal("aggregate body admission exceeded its memory window")
		}
	}
	releaseOnce.Do(func() { close(release) })
	for range 2 {
		if <-statuses != 200 {
			t.Fatal("admitted concurrent control failed")
		}
	}
	gateway.mu.Lock()
	remaining := gateway.bodyBytes
	gateway.mu.Unlock()
	if remaining != 0 {
		t.Fatal("body memory reservation leaked after completion")
	}
	response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", "{}"))
	if err != nil {
		t.Fatal("body capacity was not reusable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("released capacity refused a valid retry")
	}
}
