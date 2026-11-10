package station_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
)

// TestTrackBAdminWire proves Mint/Revoke hit POST /mint and /revoke
// with {"slot": booking id} and parse the one-time token reply.
func TestTrackBAdminWire(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var paths []string
	var slots []string
	mux := http.NewServeMux()
	handle := func(path string, reply map[string]string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			paths = append(paths, r.Method+" "+r.URL.Path)
			slots = append(slots, body["slot"])
			_ = json.NewEncoder(w).Encode(reply)
		})
	}
	handle("/mint", map[string]string{"token": strings.Repeat("ab", 32), "status": "ok"})
	handle("/revoke", map[string]string{"status": "ok"})
	go func() { _ = http.Serve(ln, mux) }()

	c := &station.TrackBAdminClient{SocketPath: sock}
	ctx := context.Background()
	booking := strings.Repeat("ef", 32)
	tok, err := c.Mint(ctx, booking)
	if err != nil || tok != strings.Repeat("ab", 32) {
		t.Fatalf("Mint = %q, %v", tok, err)
	}
	if err := c.Revoke(ctx, booking); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "POST /mint" || paths[1] != "POST /revoke" ||
		slots[0] != booking || slots[1] != booking {
		t.Fatalf("wire calls = %v slots %v", paths, slots)
	}
}

// Malformed mint replies never expose a local credential. This does not claim
// rollback of the remote mint operation that preceded the reply.
func TestSJ1MintKeys(t *testing.T) {
	for _, field := range []string{`"status":"ok","status":"bad"`, `"status":"bad","status":"ok"`, `"status":"ok","sta\u0074us":"bad"`, `"sta\u0074us":"ok"`, `"status":"ok"`} {
		sock := filepath.Join(t.TempDir(), "s")
		ln, e := net.Listen("unix", sock)
		if e != nil {
			t.Fatal(e)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"token":"`+strings.Repeat("a", 64)+`",`+field+`}`)
		})}
		go server.Serve(ln)
		c := station.TrackBAdminClient{SocketPath: sock}
		token, e := c.Mint(context.Background(), strings.Repeat("b", 64))
		server.Close()
		if field == `"status":"ok"` {
			if e != nil || token != strings.Repeat("a", 64) {
				t.Fatal("valid neighbor refused", e)
			}
		} else if e == nil || token != "" {
			t.Fatal("SJ1 ambiguous mint admitted")
		}
	}
}
