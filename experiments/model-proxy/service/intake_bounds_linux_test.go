//go:build linux

package service

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Claim: the policy positive control works; a one-byte body and each additional
// credential header refuse on both shapes before leasing or upstream I/O.
func TestIntakeRefusalNeighbours(t *testing.T) {
	for _, shape := range []string{"policy", "messages"} {
		for _, neighbour := range []string{"valid", "body", "Cookie", "X-Auth-Token", "Anthropic-Auth-Token", "X-Access-Token"} {
			if shape == "messages" && neighbour == "body" {
				continue
			}
			t.Run(shape+"/"+neighbour, func(t *testing.T) {
				var calls atomic.Int32
				_, source, client, _, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return intakeResponse(200, "{}"), nil
				}, nil)
				method, path, body := "GET", "/api/claude_code/policy_limits", ""
				if shape == "messages" {
					method, path, body = "POST", "/v1/messages", "{}"
				}
				if neighbour == "body" {
					body = "x"
				}
				request := intakeRequest(t, method, path, body)
				if neighbour != "valid" && neighbour != "body" {
					request.Header.Set(neighbour, "untrusted-fixture")
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal("neighbour transport failed")
				}
				defer response.Body.Close()
				if neighbour == "valid" {
					if response.StatusCode != 200 || calls.Load() != 1 || source.calls.Load() != 1 {
						t.Fatal("valid neighbouring control refused")
					}
				} else if response.StatusCode != 400 || calls.Load() != 0 || source.calls.Load() != 0 {
					t.Fatal("refusal neighbour reached authority or upstream")
				}
			})
		}
	}
}

// Claim: the provider-sized bound admits its exact boundary (and ordinary
// requests above 64 KiB); one extra byte is refused without any lease or call.
func TestIntakeBodyBoundary(t *testing.T) {
	for _, size := range []int{70 << 10, MaxIntakeBody, MaxIntakeBody + 1} {
		name := "boundary"
		if size < MaxIntakeBody {
			name = "above-legacy-limit"
		} else if size > MaxIntakeBody {
			name = "over-boundary"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			_, source, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				count, err := io.Copy(io.Discard, request.Body)
				if err != nil || count != int64(size) {
					t.Error("request body was truncated")
				}
				return intakeResponse(200, "{}"), nil
			}, nil)
			client.Timeout = 30 * time.Second
			response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", strings.Repeat("x", size)))
			if err != nil {
				t.Fatal("body boundary transport failed")
			}
			defer response.Body.Close()
			if size <= MaxIntakeBody {
				if response.StatusCode != 200 || calls.Load() != 1 || source.calls.Load() != 1 {
					t.Fatal("in-bound body refused")
				}
			} else if response.StatusCode != 400 || calls.Load() != 0 || source.calls.Load() != 0 {
				t.Fatal("over-bound body reached authority or upstream")
			}
		})
	}
}

// Claim: the 257th distinct issued value refuses, cancels an already registered
// stream, and leaves every later request closed; all 256 prior values work.
func TestIntakeInventoryExhaustion(t *testing.T) {
	var calls atomic.Int32
	cancelled := make(chan struct{})
	_, source, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
		if calls.Add(1) != 1 {
			return intakeResponse(200, "{}"), nil
		}
		reader, writer := io.Pipe()
		go func() {
			defer writer.Close()
			_, _ = io.WriteString(writer, "event: ping\ndata: {}\n\n")
			<-request.Context().Done()
			close(cancelled)
		}()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader}, nil
	}, func(source *intakeSource) { source.serial = true })
	held, err := client.Get("http://api.anthropic.com/api/claude_code/policy_limits")
	if err != nil {
		t.Fatal("registered stream control refused")
	}
	defer held.Body.Close()
	if _, err := bufio.NewReader(held.Body).ReadString('\n'); err != nil {
		t.Fatal("registered stream did not start")
	}
	for sequence := 2; sequence <= 257; sequence++ {
		response, err := client.Get("http://api.anthropic.com/api/claude_code/policy_limits")
		if err != nil {
			t.Fatal("inventory transport failed")
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		expected := 200
		if sequence == 257 {
			expected = 503
		}
		if response.StatusCode != expected {
			t.Fatalf("inventory sequence %d: status %d", sequence, response.StatusCode)
		}
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("inventory exhaustion did not cancel registered use")
	}
	response, err := client.Get("http://api.anthropic.com/api/claude_code/policy_limits")
	if err != nil {
		t.Fatal("post-exhaustion transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 503 || calls.Load() != 256 || source.calls.Load() != 257 {
		t.Fatal("inventory exhaustion did not remain fail-closed")
	}
}

// Claim: a generation metering refusal cannot lease or reach the provider;
// a valid reservation admits the otherwise identical Messages request.
func TestIntakeMetering(t *testing.T) {
	for _, refused := range []bool{false, true} {
		var calls atomic.Int32
		_, source, client, _, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return intakeResponse(200, "{}"), nil
		}, func(source *intakeSource) {
			if refused {
				source.reserveErr = errors.New("DAILY_COST_CEILING")
			}
		})
		response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", "{}"))
		if err != nil {
			t.Fatal("metering transport failed")
		}
		_ = response.Body.Close()
		if refused {
			if response.StatusCode != 403 || source.calls.Load() != 0 || calls.Load() != 0 {
				t.Fatal("unmetered request admitted")
			}
		} else if response.StatusCode != 200 || calls.Load() != 1 {
			t.Fatal("metered control refused")
		}
	}
}

// Claim: repeated progress outlives multiple injected idle intervals; a silent
// upstream instead loses its call and cannot return a clean completed stream.
func TestIntakeStreamIdleBound(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		name := "progress"
		if stalled {
			name = "stalled"
		}
		t.Run(name, func(t *testing.T) {
			cancelled := make(chan struct{})
			gateway, _, client, _, _ := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
				reader, writer := io.Pipe()
				go func() {
					defer writer.Close()
					_, _ = io.WriteString(writer, "event: ping\ndata: {}\n\n")
					if stalled {
						<-request.Context().Done()
						close(cancelled)
						return
					}
					for range 8 {
						select {
						case <-time.After(30 * time.Millisecond):
							_, _ = io.WriteString(writer, "event: ping\ndata: {}\n\n")
						case <-request.Context().Done():
							return
						}
					}
					_, _ = io.WriteString(writer, "event: message_stop\ndata: {}\n\n")
				}()
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader}, nil
			}, nil)
			gateway.idleTimeout = 100 * time.Millisecond
			started := time.Now()
			response, err := client.Get("http://api.anthropic.com/api/claude_code/policy_limits")
			if err != nil {
				t.Fatal("stream control failed")
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if !stalled {
				if readErr != nil || !strings.Contains(string(body), "message_stop") || strings.Count(string(body), "event: ping") != 9 {
					t.Fatal("progressing stream cut at an exchange deadline")
				}
			} else {
				if time.Since(started) > time.Second {
					t.Fatal("idle upstream was not cancelled within its idle bound")
				}
				select {
				case <-cancelled:
				case <-time.After(time.Second):
					t.Fatal("idle upstream was not cancelled")
				}
				if readErr == nil || strings.Contains(string(body), "message_stop") {
					t.Fatal("idle stream fabricated completion")
				}
			}
		})
	}
}

// Claim: unencoded protocol bodies and retry hints survive; a compressed body
// is refused before worker output because this matcher cannot inspect its bytes.
func TestIntakeEncodedResponse(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		name := "identity"
		if encoded {
			name = "encoded"
		}
		t.Run(name, func(t *testing.T) {
			_, _, client, _, _ := intakeFixture(t, false, func(*http.Request) (*http.Response, error) {
				response := intakeResponse(200, "opaque-upstream-bytes")
				response.Header.Set("X-Should-Retry", "true")
				if encoded {
					response.Header.Set("Content-Encoding", "gzip")
				}
				return response, nil
			}, nil)
			response, err := client.Get("http://api.anthropic.com/api/claude_code/policy_limits")
			if err != nil {
				t.Fatal("encoding control transport failed")
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal("encoding verdict unreadable")
			}
			if encoded {
				if response.StatusCode != 502 || string(body) != "GATEWAY_REFUSED\n" || response.Header.Get("Content-Encoding") != "" {
					t.Fatal("encoded response bypassed the output boundary")
				}
			} else if response.StatusCode != 200 || string(body) != "opaque-upstream-bytes" || response.Header.Get("X-Should-Retry") != "true" {
				t.Fatal("unencoded body or retry hint was lost")
			}
		})
	}
}
