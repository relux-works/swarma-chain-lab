//go:build linux

package service

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Claim: after headers, both SSE and JSON bodies can progress beyond the header
// budget; header silence remains bounded by TestIntakeHeaderStallBoundary.
func TestIntakeHeaderTimerScope(t *testing.T) {
	for _, streaming := range []bool{true, false} {
		name, contentType := "non-streaming", "application/json"
		chunk, prefix, suffix := "x", `{"text":"`, `"}`
		if streaming {
			name, contentType = "streaming", "text/event-stream"
			chunk, prefix, suffix = "data: {\"text\":\"x\"}\n\n", "", ""
		}
		t.Run(name, func(t *testing.T) {
			const chunks = 12
			gateway, _, client, _, logs := intakeFixture(t, false, func(request *http.Request) (*http.Response, error) {
				reader, writer := io.Pipe()
				go func() {
					defer writer.Close()
					if _, err := io.WriteString(writer, prefix); err != nil {
						return
					}
					for range chunks {
						select {
						case <-request.Context().Done():
							_ = writer.CloseWithError(request.Context().Err())
							return
						case <-time.After(100 * time.Millisecond):
						}
						if _, err := io.WriteString(writer, chunk); err != nil {
							return
						}
					}
					_, _ = io.WriteString(writer, suffix)
				}()
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {contentType}}, Body: reader}, nil
			}, nil)
			gateway.headerTimeout = 300 * time.Millisecond
			gateway.idleTimeout = 500 * time.Millisecond
			started := time.Now()
			response, err := client.Do(intakeRequest(t, "POST", "/v1/messages", `{"stream":`+map[bool]string{true: "true", false: "false"}[streaming]+`}`))
			if err != nil {
				t.Fatal("header-scope control transport failed")
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode != 200 || readErr != nil || string(body) != prefix+strings.Repeat(chunk, chunks)+suffix {
				t.Fatal("progressing body was cut by the header budget after headers arrived")
			}
			if time.Since(started) < 3*gateway.headerTimeout {
				t.Fatal("body control did not outlive the header budget")
			}
			if strings.Contains(string(body), intakeCanary) || strings.Contains(logs.String(), intakeCanary) {
				t.Fatal("header-scope control crossed the secret boundary")
			}
		})
	}
}
