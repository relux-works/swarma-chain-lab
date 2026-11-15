package singleuse

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Claim: valid RPC application errors retain code/message through observation, regardless of HTTP status; unanswered or malformed failures remain unavailable.
func TestRPCApplicationVersusTransport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		code    int
		message string
		expired bool
	}{
		{"expired500", 500, `{"id":1,"result":null,"error":{"code":-4,"message":"name expired"}}`, -4, "name expired", true},
		{"expiredNamed500", 500, `{"id":1,"result":null,"error":{"code":-4,"message":"name expired: 'id/test'"}}`, -4, "name expired: 'id/test'", true},
		{"wrongCodeExpired", 500, `{"id":1,"result":null,"error":{"code":-8,"message":"name expired"}}`, -8, "name expired", false},
		{"nearExpired", 500, `{"id":1,"result":null,"error":{"code":-4,"message":"name expired unexpectedly"}}`, -4, "name expired unexpectedly", false},
		{"application200", 200, `{"id":1,"result":null,"error":{"code":-8,"message":"invalid parameter"}}`, -8, "invalid parameter", false},
		{"other500", 500, `{"id":1,"result":null,"error":{"code":-4,"message":"name not found"}}`, -4, "name not found", false},
		{"empty500", 500, ``, 0, "", false},
		{"text503", 503, `service unavailable`, 0, "", false},
		{"malformedError500", 500, `{"id":1,"result":null,"error":{"message":"name expired"}}`, 0, "", false},
		{"wrongID500", 500, `{"id":2,"result":null,"error":{"code":-4,"message":"name expired"}}`, 0, "", false},
		{"live200", 200, `{"id":1,"result":"live","error":null}`, 0, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			rpc := &RPC{client: server.Client()}
			rpc.client.Transport = rewriteRPCTransport{server.URL, rpc.client.Transport}
			var result string
			o := NewReadObservation(context.Background(), rpc)
			defer o.Close()
			err := o.Call("name_show", &result, "id/test")
			if tc.name == "live200" {
				if err != nil || result != "live" {
					t.Fatalf("live control: %q %v", result, err)
				}
				return
			}
			var application *RPCError
			if tc.code != 0 {
				if !errors.As(err, &application) || application.Code != tc.code || application.Message != tc.message || application.NameExpired() != tc.expired || err.Error() != "RPC_APPLICATION_ERROR" {
					t.Fatalf("application classification: %v", err)
				}
			} else if err == nil || err.Error() != "NODE_UNAVAILABLE" || errors.As(err, &application) {
				t.Fatalf("transport classification: %v", err)
			}
		})
	}
}

type rewriteRPCTransport struct {
	url  string
	base http.RoundTripper
}

func (r rewriteRPCTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect only the test request to its isolated server, retaining the production decoder.
	clone := req.Clone(req.Context())
	target, _ := http.NewRequest(req.Method, r.url, nil)
	clone.URL = target.URL
	return r.base.RoundTrip(clone)
}

// Claim: connection refusal remains NODE_UNAVAILABLE; pre-call cancellation retains the observation bound.
func TestRPCNoAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	transport := server.Client().Transport
	url := server.URL
	server.Close()
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		}
		rpc := &RPC{client: &http.Client{Transport: rewriteRPCTransport{url, transport}}}
		o := NewReadObservation(ctx, rpc)
		var raw any
		err := o.Call("name_show", &raw, "id/test")
		o.Close()
		cancel()
		// Pre-call cancellation is an observation bound; connection refusal is unavailable.
		want := "NODE_UNAVAILABLE"
		if cancelled {
			want = "OBSERVATION_BOUND"
		}
		if err == nil || err.Error() != want {
			t.Fatalf("cancelled=%v: %v", cancelled, err)
		}
	}
}

// Claim: an HTTP request timing out without an RPC answer remains NODE_UNAVAILABLE.
func TestRPCTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	client := server.Client()
	client.Timeout = 20 * time.Millisecond
	client.Transport = rewriteRPCTransport{server.URL, client.Transport}
	o := NewReadObservation(context.Background(), &RPC{client: client})
	defer o.Close()
	var raw any
	err := o.Call("name_show", &raw, "id/test")
	if err == nil || err.Error() != "NODE_UNAVAILABLE" {
		t.Fatalf("timeout classification: %v", err)
	}
}
