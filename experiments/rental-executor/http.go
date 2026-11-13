package executor

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func readBody(r *http.Request, out any) error {
	raw, e := readPrivateBody(r)
	if e != nil {
		return e
	}
	if Strict(raw, out) != nil {
		return fail("HTTP_SCHEMA")
	}
	return nil
}

func readPrivateBody(r *http.Request) ([]byte, error) {
	if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		return nil, fail("HTTP_REQUEST")
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 2<<20+1))
	if e != nil || len(raw) > 2<<20 {
		return nil, fail("HTTP_SCHEMA")
	}
	return raw, nil
}

// TrackBHandler separates administrative operations from unauthenticated claims.
// Unix socket permissions, not a token supplied by stations, guard admin access.
func TrackBHandler(b *TrackB, admin bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		malformed := func() {
			if e := b.Rejected("http-rejected"); e != nil {
				respond(w, trackBHTTPStatus(e), map[string]string{"status": "refused", "reason": e.Error()})
				return
			}
			respond(w, 400, map[string]string{"status": "refused", "reason": "HTTP_SCHEMA"})
		}
		if !admin && r.URL.Path == "/claim" {
			var q trackBClaimRequest
			raw, e := readPrivateBody(r)
			if e != nil || decodeTrackBClaim(raw, &q) != nil {
				malformed()
				return
			}
			key, e := b.Claim(q.Slot, q.Token)
			if e != nil {
				respond(w, trackBHTTPStatus(e), map[string]string{"status": "refused", "reason": e.Error()})
				return
			}
			respond(w, 200, map[string]string{"status": "ok", "private_key": key})
			return
		}
		if admin && (r.URL.Path == "/mint" || r.URL.Path == "/revoke") {
			var q struct {
				Slot string `json:"slot"`
			}
			if readBody(r, &q) != nil {
				malformed()
				return
			}
			if r.URL.Path == "/mint" {
				token, e := b.Mint(q.Slot)
				if e != nil {
					respond(w, trackBHTTPStatus(e), map[string]string{"status": "refused", "reason": e.Error()})
					return
				}
				writeTrackBMintReply(w, token)
				return
			}
			if e := b.Revoke(q.Slot); e != nil {
				respond(w, trackBHTTPStatus(e), map[string]string{"status": "refused", "reason": e.Error()})
				return
			}
			respond(w, 200, map[string]string{"status": "ok"})
			return
		}
		if admin && r.URL.Path == "/list" {
			var q struct{}
			if readBody(r, &q) != nil {
				malformed()
				return
			}
			v, e := b.List()
			if e != nil {
				respond(w, 503, map[string]string{"status": "refused", "reason": e.Error()})
				return
			}
			respond(w, 200, struct {
				Status string        `json:"status"`
				Tokens []TokenRecord `json:"tokens"`
			}{"ok", v})
			return
		}
		malformed()
	})
}

type trackBClaimRequest struct {
	Slot  string      `json:"slot"`
	Token TrackBToken `json:"token"`
}

// Validate the unchanged private schema before introducing opaque storage.
func decodeTrackBClaim(raw []byte, out *trackBClaimRequest) error {
	*out = trackBClaimRequest{}
	var wire struct {
		Slot  string `json:"slot"`
		Token string `json:"token"`
	}
	if err := Strict(raw, &wire); err != nil {
		return err
	}
	*out = trackBClaimRequest{Slot: wire.Slot, Token: NewTrackBToken(wire.Token)}
	return nil
}

// This explicit private wire boundary preserves the original admin JSON bytes.
// The revealed value never leaves this encoder in a retained printable carrier.
func writeTrackBMintReply(w http.ResponseWriter, token TrackBToken) {
	respond(w, http.StatusOK, map[string]string{"status": "ok", "token": token.Reveal()})
}

// ListenUnix never removes an existing socket or file. The parent is private,
// canonical, and owned by this UID; chmod precedes accepting any connection.
func ListenUnix(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fail("SOCKET_PATH")
	}
	parent := filepath.Dir(path)
	real, e := filepath.EvalSymlinks(parent)
	if e != nil || real != parent {
		return nil, fail("SOCKET_PARENT")
	}
	i, e := os.Lstat(parent)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0700 || !owned(i) {
		return nil, fail("SOCKET_PARENT")
	}
	l, e := net.Listen("unix", path)
	if e != nil {
		return nil, fail("SOCKET_BIND")
	}
	if os.Chmod(path, 0600) != nil {
		l.Close()
		return nil, fail("SOCKET_MODE")
	}
	return l, nil
}
func HTTPServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
}

func trackBHTTPStatus(e error) int {
	if e.Error() == "RATE_LIMITED" {
		return http.StatusTooManyRequests
	}
	if e.Error() == "TRACKB_UNAVAILABLE" || e.Error() == "CLOCK" || len(e.Error()) >= 6 && e.Error()[:6] == "STATE_" {
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}
