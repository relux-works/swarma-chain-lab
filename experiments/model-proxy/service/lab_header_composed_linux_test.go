//go:build linux && gateway_lab

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/labtest"
)

// TestLabBetaCanonicalThroughHTTP proves admitted reordered and SP/HTAB beta spellings emit exactly one canonical upstream value beside the canonical control.
func TestLabBetaCanonicalThroughHTTP(test *testing.T) {
	flags := strings.Split(labBeta, ",")
	reversed := slices.Clone(flags)
	slices.Reverse(reversed)
	for name, beta := range map[string]string{
		"canonical":      labBeta,
		"permuted":       strings.Join(reversed, ","),
		"spaces":         " " + strings.Join(flags, " , ") + " ",
		"tabs":           "\t" + strings.Join(flags, "\t,\t") + "\t",
		"mixed-permuted": " \t" + strings.Join(reversed, "\t , \t") + "\t ",
	} {
		test.Run(name, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			source, _ := labComposedSource(test, fixture)
			gateway, err := newLabIntake(source, func([]byte) error { return nil })
			if err != nil {
				test.Fatal("gateway control refused")
			}
			defer gateway.Close()
			calls := 0
			gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if !slices.Equal(request.Header.Values("Anthropic-Beta"), []string{labBeta}) {
					test.Error("noncanonical or multiple beta values reached upstream")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			request := labComposedRequest(test, source, nil)
			for name := range request.Header {
				if strings.EqualFold(name, "Anthropic-Beta") {
					request.Header[name] = []string{beta}
				}
			}
			response := httptest.NewRecorder()
			labServe(gateway, response, request)
			if response.Code != 200 || calls != 1 {
				test.Fatalf("admitted beta control: status=%d calls=%d", response.Code, calls)
			}
		})
	}
}

// TestLabMultiValueHeadersThroughHTTP proves second-value and separator-free split matches hold before disclosure; clean multi-value response controls pass, while inbound duplicate fields refuse without a hold.
func TestLabMultiValueHeadersThroughHTTP(test *testing.T) {
	for _, direction := range []string{"inbound", "response"} {
		for _, mode := range []string{"clean", "second", "split", "empty-first", "empty-middle"} {
			test.Run(direction+"/"+mode, func(test *testing.T) {
				fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
				source, broker := labComposedSource(test, fixture)
				gateway, err := newLabIntake(source, func([]byte) error { return nil })
				if err != nil {
					test.Fatal("gateway control refused")
				}
				defer gateway.Close()
				calls := 0
				headers := http.Header{}
				gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader("control"))}, nil
				})
				control := httptest.NewRecorder()
				labServe(gateway, control, labComposedRequest(test, source, nil))
				if control.Code != 200 || calls != 1 {
					test.Fatal("clean issued control refused")
				}
				middle := len(labMaterial) / 2
				values := []string{"control", "another-control"}
				switch mode {
				case "second":
					values = []string{"control", labMaterial}
				case "split":
					values = []string{labMaterial[:middle], labMaterial[middle:]}
				case "empty-first":
					values = []string{"", labMaterial}
				case "empty-middle":
					values = []string{labMaterial[:middle], "", labMaterial[middle:]}
				}
				request := labComposedRequest(test, source, nil)
				if direction == "inbound" {
					request.Header["X-Stainless-Diagnostic"] = values
				} else {
					headers["Request-Id"] = values
				}
				response := httptest.NewRecorder()
				labServe(gateway, response, request)
				if bytes.Contains(response.Body.Bytes(), []byte(labMaterial)) || strings.Contains(strings.Join(response.Header().Values("Request-Id"), ""), labMaterial) {
					test.Fatal("header material disclosed to worker")
				}
				wantStatus, wantCalls := 403, 1
				if direction == "response" {
					wantStatus, wantCalls = 502, 2
				}
				if mode == "clean" {
					wantStatus = 400
					if direction == "response" {
						wantStatus = 200
						if !slices.Equal(response.Header().Values("Request-Id"), values) {
							test.Fatal("clean response values changed")
						}
					}
					if broker.Holds.Load() != 0 || source.ctx.Err() != nil {
						test.Fatal("clean multi-value control entered hold")
					}
				} else {
					bounded, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if source.AwaitHold(bounded) != nil || broker.Holds.Load() == 0 || !broker.SameHold() {
						test.Fatal("multi-value match did not commit same-ID hold")
					}
				}
				if response.Code != wantStatus || calls != wantCalls {
					test.Fatalf("header boundary status=%d calls=%d", response.Code, calls)
				}
			})
		}
	}
}

// TestLabEarlyBodyScanThroughHTTP proves known material enters hold before reservation or any broker check, beside an admitted clean control.
func TestLabEarlyBodyScanThroughHTTP(test *testing.T) {
	fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
	source, broker := labComposedSource(test, fixture)
	reservations, calls := 0, 0
	gateway, err := newLabIntake(source, func([]byte) error { reservations++; return nil })
	if err != nil {
		test.Fatal("gateway control refused")
	}
	defer gateway.Close()
	gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
	})
	control := httptest.NewRecorder()
	labServe(gateway, control, labComposedRequest(test, source, nil))
	if control.Code != 200 || calls != 1 || reservations != 1 {
		test.Fatal("issued control refused")
	}
	body := bytes.ReplaceAll(labWireCases(test)[0].Request.Body, []byte("PUBLIC SYNTHETIC PROMPT"), []byte(labMaterial))
	response := httptest.NewRecorder()
	labServe(gateway, response, labComposedRequest(test, source, body))
	if response.Code != 403 || calls != 1 || reservations != 1 {
		test.Fatal("known body material crossed reservation boundary")
	}
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if source.AwaitHold(bounded) != nil || broker.Holds.Load() == 0 {
		test.Fatal("early match not held")
	}
}

// TestLabColdCheckTimeoutThroughHTTP proves the first stalled check is bounded by the 200-ms RPC timeout before a watchdog exists, beside a successful first request.
func TestLabColdCheckTimeoutThroughHTTP(test *testing.T) {
	for _, mode := range []string{"control", "stall"} {
		test.Run(mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			source, broker := labComposedSource(test, fixture)
			if mode == "stall" {
				broker.CheckMode.Store("stall")
			}
			calls := 0
			gateway, err := newLabIntake(source, func([]byte) error { return nil })
			if err != nil {
				test.Fatal("gateway control refused")
			}
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			response := httptest.NewRecorder()
			returned := make(chan struct{})
			request := labComposedRequest(test, source, nil)
			go func() { defer close(returned); labServe(gateway, response, request) }()
			select {
			case <-returned:
			case <-time.After(350 * time.Millisecond):
				source.end()
				<-returned
				test.Fatal("cold check exceeded RPC budget before watchdog initialization")
			}
			wantStatus, wantCalls := 200, 1
			if mode == "stall" {
				wantStatus, wantCalls = 503, 0
			}
			if response.Code != wantStatus || calls != wantCalls {
				test.Fatal("cold check verdict or upstream boundary")
			}
		})
	}
}

// TestLabPinnedDeadlineThroughHTTP proves expired cold intake makes no lease RPC and issued authority retires on the first poll despite a blocked lease mutex, beside a live HTTP control.
func TestLabPinnedDeadlineThroughHTTP(test *testing.T) {
	for _, mode := range []string{"live", "cold-expired", "issued-lock"} {
		test.Run(mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			fixture.Deadline = time.Now().Add(100 * time.Millisecond)
			fixture.Rebuild()
			source, broker := labComposedSource(test, fixture)
			calls := 0
			gateway, err := newLabIntake(source, func([]byte) error { return nil })
			if err != nil {
				test.Fatal("gateway control refused")
			}
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			request := labComposedRequest(test, source, nil)
			if mode == "cold-expired" {
				<-time.NewTimer(time.Until(fixture.Deadline)).C
			}
			response := httptest.NewRecorder()
			labServe(gateway, response, request)
			if mode == "cold-expired" {
				if response.Code != 503 || calls != 0 || broker.Requests.Load() != 0 {
					test.Fatal("expired cold intake attempted a lease RPC")
				}
				return
			}
			if response.Code != 200 || calls != 1 {
				test.Fatal("live pinned-deadline control")
			}
			if mode == "issued-lock" {
				source.lease.mu.Lock()
				defer source.lease.mu.Unlock()
				select {
				case <-source.ctx.Done():
				case <-time.NewTimer(time.Until(fixture.Deadline.Add(300 * time.Millisecond))).C:
					test.Fatal("pinned expiry waited for the blocked lease mutex or watchdog")
				}
			}
		})
	}
}
