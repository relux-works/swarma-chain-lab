package executor

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"strconv"
	"strings"
	"testing"
)

// Core's success reply contains error:null. Null is accepted there, but an
// error, missing error field, wrong id or wrong result type cannot be success.
func TestBroadcastReply(t *testing.T) {
	reply := `{"id":1,"result":"` + strings.Repeat("a", 64) + `","error":null}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Method != "sendrawtransaction" {
			t.Error("capability")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	p, _ := strconv.Atoi(port)
	b, e := NewBroadcaster(singleuse.Route{Host: host, Port: p, Username: "m4a-broadcast", Password: strings.Repeat("x", 32)})
	if e != nil {
		t.Fatal(e)
	}
	if id, e := b.Broadcast(context.Background(), []byte{1}); e != nil || id != strings.Repeat("a", 64) {
		t.Fatal("valid RPC rejected", e)
	}
	for _, raw := range []string{`{"id":2,"result":"` + strings.Repeat("a", 64) + `","error":null}`, `{"id":1,"result":"` + strings.Repeat("a", 64) + `"}`, `{"id":1,"result":null,"error":{"code":-26}}`, `{"id":1,"result":"wrong","error":null}`} {
		reply = raw
		if _, e := b.Broadcast(context.Background(), []byte{1}); e == nil {
			t.Fatal("invalid RPC admitted")
		}
	}
}
