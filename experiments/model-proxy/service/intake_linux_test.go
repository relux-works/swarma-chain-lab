//go:build linux

package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const intakeCanary = "canary-intake-material-not-for-worker-729146"

type intakeSource struct {
	binding    Mapping
	calls      atomic.Int32
	err        error
	scheme     string
	material   string
	cancelled  bool
	serial     bool
	reserveErr error
}

func (source *intakeSource) GatewayBinding() (Caller, string) {
	return source.binding.Caller, source.binding.ServiceGeneration
}

func (source *intakeSource) CredentialValue(context.Context) (string, []byte, string, error) {
	sequence := source.calls.Add(1)
	if source.serial {
		return source.scheme, []byte(fmt.Sprintf("inventory-material-%03d", sequence)), "session-1/lease-1", source.err
	}
	return source.scheme, []byte(source.material), "session-1/lease-1", source.err
}

func (source *intakeSource) ReserveGeneration([]byte) error {
	return source.reserveErr
}

func (source *intakeSource) CredentialContext(ctx context.Context, _ string) (context.Context, context.CancelFunc) {
	call, cancel := context.WithCancel(ctx)
	if source.cancelled {
		cancel()
	}
	return call, cancel
}

type intakeTransport func(*http.Request) (*http.Response, error)

func (transport intakeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func intakeFixture(t *testing.T, unauthorized bool, transport intakeTransport, configure func(*intakeSource)) (*Gateway, *intakeSource, *http.Client, string, *bytes.Buffer) {
	t.Helper()
	mapping := mapping()
	mapping.Caller.UID = uint32(os.Geteuid())
	if unauthorized {
		mapping.Caller.UID++
	}
	source := &intakeSource{binding: mapping, scheme: "oauth-bearer", material: intakeCanary}
	if configure != nil {
		configure(source)
	}
	gateway, err := NewGateway(source, mapping)
	if err != nil {
		t.Fatal("fixture intake refused")
	}
	if transport != nil {
		gateway.transport = transport
	}
	t.Cleanup(gateway.Close)
	root, err := os.MkdirTemp(os.TempDir(), "gi-")
	if err != nil {
		t.Fatal("fixture scratch unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socket := filepath.Join(root, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal("fixture socket unavailable")
	}
	logs := new(bytes.Buffer)
	server := &http.Server{Handler: gateway, ConnContext: gateway.ConnContext, ErrorLog: log.New(logs, "", 0)}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	clientTransport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: clientTransport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { clientTransport.CloseIdleConnections(); _ = server.Close(); <-done })
	return gateway, source, client, socket, logs
}

func intakeResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func intakeRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, "http://api.anthropic.com"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal("fixture request unavailable")
	}
	request.Header.Set("Content-Type", "application/json")
	if method == http.MethodPost {
		request.Header.Set("Authorization", "Bearer ssh-placeholder")
	}
	return request
}

// Claim: both measured request shapes use the pinned origin, preserve protocol
// bytes, and inject only the holder credential without modifying worker headers.
func TestIntakeAdmission(t *testing.T) {
	for _, shape := range []struct{ name, method, path, body string }{
		{"messages", "POST", "/v1/messages?beta=true&fixture=a%2Fb", `{"model":"qualified-model","stream":true,"messages":[]}`},
		{"policy", "GET", "/api/claude_code/policy_limits", ""},
	} {
		t.Run(shape.name, func(t *testing.T) {
			var calls atomic.Int32
			_, source, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				body, _ := io.ReadAll(request.Body)
				if request.Method != shape.method || request.URL.String() != upstreamOrigin+shape.path || request.Host != "api.anthropic.com" || string(body) != shape.body || request.Header.Get("Authorization") != "Bearer "+intakeCanary || request.Header.Get("X-Api-Key") != "" || request.Header.Get("Anthropic-Beta") != "oauth-2025-04-20" || request.Header.Get("Anthropic-Version") != "2023-06-01" {
					t.Error("upstream recipient, protocol or injection changed")
				}
				return intakeResponse(200, `{"accepted":true}`), nil
			}, nil)
			request := intakeRequest(t, shape.method, shape.path, shape.body)
			request.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
			request.Header.Set("Anthropic-Version", "2023-06-01")
			before := request.Header.Clone()
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("admitted shape failed")
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || string(body) != `{"accepted":true}` || calls.Load() != 1 || source.calls.Load() != 1 || fmt.Sprint(before) != fmt.Sprint(request.Header) {
				t.Fatal("admitted request or worker boundary changed")
			}
		})
	}
}

// Claim: neighbouring paths, methods and credential forms, including an
// unauthorized Unix peer, refuse before material acquisition or upstream I/O.
func TestIntakeRefusals(t *testing.T) {
	for _, test := range []struct {
		name, method, path string
		change             func(*http.Request)
		unauthorized       bool
	}{
		{"wrong-path", "POST", "/v1/complete", nil, false},
		{"wrong-method", "PUT", "/v1/messages", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ssh-placeholder") }, false},
		{"messages-get", "GET", "/v1/messages", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ssh-placeholder") }, false},
		{"wrong-placeholder", "POST", "/v1/messages", func(r *http.Request) { r.Header.Set("Authorization", "Bearer other-placeholder") }, false},
		{"real-credential", "POST", "/v1/messages", func(r *http.Request) { r.Header.Set("Authorization", "Bearer sk-ant-untrusted-fixture") }, false},
		{"missing-placeholder", "POST", "/v1/messages", func(r *http.Request) { r.Header.Del("Authorization") }, false},
		{"duplicate-authorization", "POST", "/v1/messages", func(r *http.Request) { r.Header.Add("Authorization", "Bearer ssh-placeholder") }, false},
		{"api-key", "POST", "/v1/messages", func(r *http.Request) { r.Header.Set("X-Api-Key", "untrusted-fixture") }, false},
		{"empty-api-key", "POST", "/v1/messages", func(r *http.Request) { r.Header.Set("X-Api-Key", "") }, false},
		{"proxy-auth", "POST", "/v1/messages", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer untrusted-fixture") }, false},
		{"encoded-path", "POST", "/v1/%6dessages", nil, false},
		{"policy-method", "POST", "/api/claude_code/policy_limits", func(r *http.Request) { r.Header.Del("Authorization") }, false},
		{"policy-wrong-path", "GET", "/api/claude_code/settings", nil, false},
		{"policy-authorization", "GET", "/api/claude_code/policy_limits", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ssh-placeholder") }, false},
		{"policy-empty-authorization", "GET", "/api/claude_code/policy_limits", func(r *http.Request) { r.Header.Set("Authorization", "") }, false},
		{"policy-api-key", "GET", "/api/claude_code/policy_limits", func(r *http.Request) { r.Header.Set("X-Api-Key", "") }, false},
		{"policy-query", "GET", "/api/claude_code/policy_limits?fixture=true", nil, false},
		{"policy-unauthorized-peer", "GET", "/api/claude_code/policy_limits", nil, true},
		{"messages-unauthorized-peer", "POST", "/v1/messages", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			_, source, client, _, _ := intakeFixture(t, test.unauthorized, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return intakeResponse(200, "unexpected"), nil
			}, nil)
			request := intakeRequest(t, test.method, test.path, "")
			if test.change != nil {
				test.change(request)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("refusal response unavailable")
			}
			defer response.Body.Close()
			expected := 400
			if test.unauthorized {
				expected = 403
			}
			if response.StatusCode != expected || calls.Load() != 0 || source.calls.Load() != 0 {
				t.Fatal("forbidden request acquired material or reached upstream")
			}
		})
	}
}

// Claim: the plaintext socket rejects HTTP/1.0 and credential trailers, while
// direct handler invocation cannot supply the unexported kernel-peer context.
func TestIntakeTransport(t *testing.T) {
	gateway, source, _, socket, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
		t.Error("forbidden transport reached upstream")
		return intakeResponse(200, "unexpected"), nil
	}, nil)
	for _, wire := range []string{
		"GET /api/claude_code/policy_limits HTTP/1.0\r\nHost: api.anthropic.com\r\n\r\n",
		"GET /api/claude_code/policy_limits HTTP/1.1\r\nHost: api.anthropic.com\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization\r\n\r\n0\r\nAuthorization: Bearer ssh-placeholder\r\n\r\n",
	} {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal("fixture connect failed")
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, wire)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || response.StatusCode != 400 {
			t.Fatal("forbidden HTTP framing admitted")
		}
		_ = response.Body.Close()
		_ = conn.Close()
	}
	writer := httptest.NewRecorder()
	gateway.ServeHTTP(writer, httptest.NewRequest("GET", "/api/claude_code/policy_limits", nil))
	if writer.Code != 403 || source.calls.Load() != 0 {
		t.Fatal("placeholder or handler access supplied peer authority")
	}
}

// Claim: a first SSE frame is observable before the upstream is allowed to
// finish; event bytes and the upstream status are preserved without aggregation.
func TestIntakeSSEIncremental(t *testing.T) {
	first := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
	last := "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	_, _, client, _, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 202, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader}, nil
	}, nil)
	observed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.WriteString(writer, first)
		select {
		case <-observed:
		case <-time.After(2 * time.Second):
			_ = writer.CloseWithError(errors.New("first frame was buffered"))
			return
		}
		_, _ = io.WriteString(writer, last)
		_ = writer.Close()
	}()
	response, err := client.Do(intakeRequest(t, "POST", "/v1/messages?beta=true", `{"stream":true}`))
	if err != nil {
		t.Fatal("stream response unavailable before upstream completion")
	}
	defer response.Body.Close()
	frame := make([]byte, len(first))
	if _, err := io.ReadFull(response.Body, frame); err != nil || string(frame) != first || response.StatusCode != 202 {
		t.Fatal("first SSE frame was buffered or changed")
	}
	close(observed)
	rest, err := io.ReadAll(response.Body)
	<-done
	if err != nil || string(rest) != last {
		t.Fatal("terminal SSE frame changed")
	}
}

// Claim: upstream refusals remain their real status, body and retry metadata;
// even a redirect is returned rather than followed to another credential sink.
func TestIntakeUpstreamErrors(t *testing.T) {
	for _, status := range []int{400, 401, 429, 503, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			_, _, client, _, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				response := intakeResponse(status, `{"error":{"message":"upstream-refusal"}}`)
				response.Header.Set("Retry-After", "7")
				response.Header.Set("X-Request-ID", "request-fixture")
				response.Header.Set("Location", "https://untrusted.invalid/collect")
				return response, nil
			}, nil)
			response, err := client.Do(intakeRequest(t, "GET", "/api/claude_code/policy_limits", ""))
			if err != nil {
				t.Fatal("upstream refusal unavailable")
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != status || string(body) != `{"error":{"message":"upstream-refusal"}}` || response.Header.Get("Retry-After") != "7" || response.Header.Get("X-Request-ID") != "request-fixture" || calls.Load() != 1 {
				t.Fatal("upstream error or status was replaced")
			}
		})
	}
}

type intakePieces struct{ pieces []string }

func (pieces *intakePieces) Read(buffer []byte) (int, error) {
	if len(pieces.pieces) == 0 {
		return 0, io.EOF
	}
	count := copy(buffer, pieces.pieces[0])
	pieces.pieces[0] = pieces.pieces[0][count:]
	if pieces.pieces[0] == "" {
		pieces.pieces = pieces.pieces[1:]
	}
	return count, nil
}

// Claim: reflected credentials are removed across every read split, including
// error bodies and headers, and gateway/transport diagnostics never disclose them.
func TestIntakeSecretBoundary(t *testing.T) {
	for split := 1; split < len(intakeCanary); split++ {
		gateway, _, client, _, logs := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
			response := intakeResponse(400, "")
			response.Body = io.NopCloser(&intakePieces{pieces: []string{"before:" + intakeCanary[:split], intakeCanary[split:] + ":after"}})
			response.Header.Set("Authorization", "Bearer "+intakeCanary)
			response.Header.Set("X-Api-Key", intakeCanary)
			response.Header.Set("X-Request-ID", intakeCanary)
			return response, nil
		}, nil)
		response, err := client.Do(intakeRequest(t, "GET", "/api/claude_code/policy_limits", ""))
		if err != nil {
			t.Fatal("reflection response unavailable")
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 400 || string(body) != "before:[redacted]:after" || strings.Contains(fmt.Sprint(response.Header), intakeCanary) || strings.Contains(logs.String()+fmt.Sprintf("%+v %#v", gateway, gateway), intakeCanary) {
			t.Fatal("credential reached worker output or diagnostics")
		}
	}
}

// Claim: source failures, stale authority and unsupported credential schemes
// fail closed with constant diagnostics and no submission.
func TestIntakeAuthorityFailures(t *testing.T) {
	for _, mode := range []string{"source-error", "cancelled", "api-key", "invalid-material", "transport-error"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			_, _, client, _, logs := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New(intakeCanary)
			}, func(source *intakeSource) {
				switch mode {
				case "source-error":
					source.err = errors.New(intakeCanary)
				case "cancelled":
					source.cancelled = true
				case "api-key":
					source.scheme = "api-key"
				case "invalid-material":
					source.material = "invalid\nmaterial"
				}
			})
			response, err := client.Do(intakeRequest(t, "GET", "/api/claude_code/policy_limits", ""))
			if err != nil {
				t.Fatal("source refusal unavailable")
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			expected, expectedCalls := 503, int32(0)
			if mode == "transport-error" {
				expected, expectedCalls = 502, 1
			}
			if err != nil || response.StatusCode != expected || calls.Load() != expectedCalls || strings.Contains(string(body)+logs.String(), intakeCanary) {
				t.Fatal("source failure leaked or submitted without authority")
			}
		})
	}
}

// Claim: the public marker cannot select a different qualified caller or
// generation, and a mapping cannot choose an alternate marker.
func TestIntakeMapping(t *testing.T) {
	for _, mode := range []string{"valid", "placeholder", "caller", "generation"} {
		t.Run(mode, func(t *testing.T) {
			mapping := mapping()
			source := &intakeSource{binding: mapping}
			switch mode {
			case "placeholder":
				mapping.Placeholder = "other-placeholder"
			case "caller":
				mapping.Caller.LaunchID = "other-launch"
			case "generation":
				mapping.ServiceGeneration = "other-generation"
			}
			gateway, err := NewGateway(source, mapping)
			if gateway != nil {
				gateway.Close()
			}
			if (mode == "valid") != (err == nil && gateway != nil) {
				t.Fatal("mapping qualification or literal marker gate changed")
			}
		})
	}
}

type intakeContextBody struct {
	ctx   context.Context
	first bool
}

func (body *intakeContextBody) Read(buffer []byte) (int, error) {
	if !body.first {
		body.first = true
		return copy(buffer, "event: message_start\ndata: {}\n\n"), nil
	}
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (*intakeContextBody) Close() error { return nil }

// Claim: a detected worker leak cancels already registered upstream use, not
// only the next request; a healthy stream first supplies the valid control.
func TestIntakeLeakCancelsUse(t *testing.T) {
	active := make(chan context.Context, 1)
	_, source, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
		active <- request.Context()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: &intakeContextBody{ctx: request.Context()}}, nil
	}, nil)
	response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", "{}"))
	if err != nil {
		t.Fatal("healthy stream did not start")
	}
	defer response.Body.Close()
	ctx := <-active
	reader := bufio.NewReader(response.Body)
	frame := make([]byte, len("event: message_start\ndata: {}\n\n"))
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatal("healthy stream control was buffered")
	}
	leak, err := client.Do(intakeRequest(t, "POST", "/v1/messages", intakeCanary))
	if err != nil {
		t.Fatal("leak refusal unavailable")
	}
	_ = leak.Body.Close()
	if leak.StatusCode != 403 || source.calls.Load() != 1 {
		t.Fatal("known leak acquired another lease")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("worker leak left registered upstream use alive")
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("cancelled upstream stream ended as clean success")
	}
}

// Claim: even the first acquired value is screened against worker bytes before
// injection; detection closes subsequent use rather than forgetting the leak.
func TestIntakeWorkerLeak(t *testing.T) {
	for _, mode := range []string{"body", "header", "query"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			_, source, client, _, logs := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return intakeResponse(200, "unexpected"), nil
			}, nil)
			body, path := "", "/v1/messages"
			if mode == "body" {
				body = intakeCanary
			}
			if mode == "query" {
				path += "?fixture=" + intakeCanary
			}
			request := intakeRequest(t, "POST", path, body)
			if mode == "header" {
				request.Header.Set("Anthropic-Beta", intakeCanary)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if attempt == 1 {
					request = intakeRequest(t, "GET", "/api/claude_code/policy_limits", "")
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal("leak refusal unavailable")
				}
				out, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				expected := 403
				if attempt == 1 {
					expected = 503
				}
				if err != nil || response.StatusCode != expected || calls.Load() != 0 || strings.Contains(string(out)+logs.String(), intakeCanary) {
					t.Fatal("worker leak was forwarded, disclosed or forgotten")
				}
			}
			if source.calls.Load() != 1 {
				t.Fatal("blocked intake reacquired material")
			}
		})
	}
}
