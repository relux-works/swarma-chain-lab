package chaingateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests consume the contract corpus in place, including each negative's
// named positive. They bind its expected decisions to helper runtime functions.
func TestHelperSharedSnapshotOutcomes(t *testing.T) {
	for _, v := range observations(t) {
		if v.Kind != "bracket" && v.Kind != "snapshot_read_failure" && v.Kind != "snapshot_attempts" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			var c Configuration
			raw := wire(v.Config)
			if e := json.Unmarshal(raw, &c); e != nil {
				t.Fatal(e)
			}
			headers := map[string]map[string]any{}
			waits := []any{}
			code := 0
			for i, a := range v.SnapshotAttempts {
				var failure error
				if a.Failure != "" {
					failure = bad("collection failure")
				}
				e := assessCollection(c, collectionAttempt{Before: a.Before, After: a.After, BeforeReply: a.BeforeReply, AfterReply: a.AfterReply, Requests: a.Requests, Replies: a.Replies, ReplyWires: a.ReplyWires, Bestblocks: a.Bestblocks, Failure: failure}, headers)
				var delay time.Duration
				code, delay = retryOutcome(e, i+1)
				if code >= 0 {
					if i != len(v.SnapshotAttempts)-1 {
						t.Fatal("continued after terminal outcome")
					}
					break
				}
				waits = append(waits, json.Number(fmt.Sprint(delay.Milliseconds())))
			}
			previous := "unchanged"
			if code == 0 {
				previous = "replaced"
			}
			got := map[string]any{"exit": json.Number(fmt.Sprint(code)), "write": code == 0, "previous": previous, "wait_ms": waits}
			if !same(got, v.Expected) {
				t.Fatalf("helper snapshot mismatch: got %s want %s", wire(got), wire(v.Expected))
			}
		})
	}
}

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeReader struct {
	io.Reader
	closed bool
	read   int
}

func (r *closeReader) Read(p []byte) (int, error) { n, e := r.Reader.Read(p); r.read += n; return n, e }
func (r *closeReader) Close() error               { r.closed = true; return nil }

// All shared upstream controls exercise rpcClient.call, including the complete
// HTTP entity, exact matching string id, SJ1, selected types and error mapping.
func TestHelperSharedUpstream(t *testing.T) {
	for _, v := range observations(t) {
		if v.Kind != "upstream" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			u := *v.Upstream
			body := &closeReader{Reader: strings.NewReader(u.Body)}
			r := &rpcClient{endpoint: "http://127.0.0.1:1", client: &http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
				var request map[string]any
				if e := json.NewDecoder(req.Body).Decode(&request); e != nil {
					t.Fatal(e)
				}
				if request["id"] != u.ID {
					t.Fatal("request id profile")
				}
				// The fixture selects the request id; response bytes are untouched.
				return &http.Response{StatusCode: u.Status, Header: http.Header{}, Body: body}, nil
			})}}

			value, e := r.callWithID(context.Background(), u.Method, nil, u.ID)
			got := "ok"
			if e != nil {
				var refusal readFailure
				if errors.As(e, &refusal) {
					got = string(refusal)
				} else {
					got = "unavailable"
				}
			} else if u.Method == "gettxout" && value == nil {
				got = "absent"
			}
			want := str(v.Expected["code"])
			if got != want {
				t.Fatalf("helper upstream class %s want %s", got, want)
			}
			if body.read != min(len(u.Body), upstreamBounds[u.Method].bytes+1) {
				t.Fatal("upstream cap+1 consumption")
			}
			if !body.closed {
				t.Fatal("upstream body not closed")
			}
		})
	}
}

// Whole-value reflection controls traverse the final projection gate and decoded
// name bytes. Ordinary and embedded values remain publishable.
func TestHelperSharedReflection(t *testing.T) {
	for _, v := range observations(t) {
		if v.Kind != "reflection" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			q := v.Reflection
			raw := q.User + ":" + q.Secret
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			r := rpcClient{secrets: []string{raw, encoded, "Basic " + encoded, q.Secret}}
			names := []any{map[string]any{"value_b64": base64.StdEncoding.EncodeToString([]byte(q.Value))}}
			b := wire(map[string]any{"names": names})
			code := "ok"
			if r.leaks(b, names) {
				code = "unavailable"
			}
			if code != str(v.Expected["code"]) {
				t.Fatalf("reflection class %s want %s", code, str(v.Expected["code"]))
			}
		})
	}
}

// Real same-directory publication has explicit rename state: every failed stage
// before rename preserves bytes/inode/mtime; each directory failure retains the
// new complete file and carries durability-unconfirmed evidence.
func TestHelperPublicationStageFailures(t *testing.T) {
	for _, v := range observations(t) {
		if v.Name != "snapshot_complete_control" && (v.Kind != "snapshot_stage" || !strings.Contains("|temp_create|temp_write|temp_validate|temp_metadata|file_sync|file_close|rename|directory_open|directory_sync|directory_close|own_temp_cleanup|", "|"+v.Stage+"|")) {
			continue
		}
		stage := v.Stage
		t.Run(v.Name, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, previous := x.previous(t)
			snapshot := []byte("")
			for _, v := range observations(t) {
				if v.Kind == "label" && v.Name == "fresh" {
					snapshot = []byte(v.Snapshot)
					break
				}
			}
			if validate("snapshot", snapshot) != nil {
				t.Fatal("publication positive fixture")
			}
			failed := false
			step := func(name string, action func() error) error {
				if name == stage || stage == "own_temp_cleanup" && name == "temp_write" {
					failed = true
					return io.ErrClosedPipe
				}
				return action()
			}
			e := publishWith(x.c.Output, snapshot, x.p, step)
			if stage == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || !failed {
				t.Fatal("stage failure not exercised")
			}
			afterRename := v.Renamed != nil && *v.Renamed
			wantExit := int(uintValue(v.Expected["exit"]))
			if publicationExit(e) != wantExit {
				t.Fatalf("publication exit %d want %d", publicationExit(e), wantExit)
			}
			if publicationRenamed(e) != afterRename {
				t.Fatalf("rename fact at %s: %v", stage, e)
			}
			if stage != "" && !afterRename {
				x.unchanged(t, old, previous)
			} else {
				got, _ := os.ReadFile(x.c.Output)
				if !bytes.Equal(got, snapshot) {
					t.Fatal("complete new publication lost")
				}
			}
			entries, _ := filepath.Glob(filepath.Join(x.root, ".snapshot-*"))
			if stage != "own_temp_cleanup" && len(entries) != 0 {
				t.Fatal("owned temp leaked")
			}
		})
	}
}

const loopbackPolicy = "rpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n"

// Each unsafe installed node policy refuses before credential opening or HTTP;
// the genuine loopback policy remains a complete publication control.
func TestHelperNodeIdentityAndLoopback(t *testing.T) {
	for _, kind := range []string{"valid", "server", "allowed", "workload", "shared", "root", "reserved", "bind", "allow", "missing", "namespace-proof"} {
		t.Run(kind, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			switch kind {
			case "server":
				x.c.ServerUID = x.c.NodeUID
			case "allowed":
				x.c.AllowedUIDs = append(x.c.AllowedUIDs, x.c.NodeUID)
			case "workload":
				x.c.WorkloadUIDs = append(x.c.WorkloadUIDs, x.c.NodeUID)
			case "shared":
				x.c.NodeDedicated = false
			case "root":
				x.c.NodeUID = 0
			case "reserved":
				x.c.NodeUID = 65535
			case "bind":
				os.WriteFile(x.c.NodeConfig, []byte("rpcbind=0.0.0.0\nrpcallowip=127.0.0.1\n"), 0600)
			case "allow":
				os.WriteFile(x.c.NodeConfig, []byte("rpcbind=127.0.0.1\nrpcallowip=0.0.0.0/0\n"), 0600)
			case "missing":
				os.WriteFile(x.c.NodeConfig, []byte(""), 0600)
			case "namespace-proof":
				x.p.namespacePID = 2147483647
			}
			x.config(t)
			code, _ := x.execute()
			want := 11
			if kind == "valid" {
				want = 0
			}
			if code != want {
				t.Fatalf("identity/policy %s exit %d want %d", kind, code, want)
			}
			if want != 0 {
				x.unchanged(t, old, b)
				if len(x.rpc.methods) != 0 {
					t.Fatal("HTTP before node policy proof")
				}
			}
		})
	}
}

// Shared two-view positive/transient/absence and inconsistency fixtures exercise
// readSeal's real fixed false/true RPC path, not the projection oracle.
func TestHelperSharedUTXOViews(t *testing.T) {
	for _, v := range observations(t) {
		if v.Kind != "utxo_views" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			calls := 0
			r := rpcClient{endpoint: "http://127.0.0.1:1", client: &http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
				var q struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if e := json.NewDecoder(req.Body).Decode(&q); e != nil {
					t.Fatal(e)
				}
				if q.Method != "gettxout" || len(q.Params) != 3 || string(q.Params[2]) != []string{"false", "true"}[calls] {
					t.Fatal("fixed two-view order")
				}
				var result any = v.Confirmed
				if calls == 1 {
					result = v.Mempool
				}
				calls++
				raw := wire(map[string]any{"id": "snapshot", "error": nil, "result": result})
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}}
			point := v.Config["seals"].([]any)[0].(map[string]any)
			p := Outpoint{str(point["txid"]), uint32(uintValue(point["vout"]))}
			got, e := r.readSeal(context.Background(), p, v.KnownTip)
			if v.Expected["ok"] == true {
				if e != nil || !same(got, v.Expected["result"]) {
					t.Fatalf("two-view projection differs: %v", e)
				}
			} else if e == nil {
				t.Fatal("inconsistent views admitted")
			}
			wantCalls := 2
			if v.Name == "views_missing_script" || v.Name == "views_invalid_script" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("fixed view/terminal refusal order")
			}
		})
	}
}

type shortSnapshotWriter struct{ short bool }

func (w shortSnapshotWriter) Write(b []byte) (int, error) {
	if w.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}

// A nil-error short write is specifically io.ErrShortWrite; full writes remain
// admissible. Publication-stage controls separately check old-file safety.
func TestHelperShortWrite(t *testing.T) {
	if e := writeSnapshot(shortSnapshotWriter{}, []byte("snapshot")); e != nil {
		t.Fatal(e)
	}
	if e := writeSnapshot(shortSnapshotWriter{short: true}, []byte("snapshot")); !errors.Is(e, io.ErrShortWrite) {
		t.Fatalf("short write: %v", e)
	}
}

// Selected secret components cannot hide behind output base64; embedded values
// remain public data. Both credential modes use their own complete fixture.
func TestHelperSelectedCredentialMode(t *testing.T) {
	for _, mode := range []string{"cookie", "rpcauth-user"} {
		t.Run(mode, func(t *testing.T) {
			x := makeFixture(t, mode)
			b, _ := os.ReadFile(x.c.CredentialFile)
			_, secret, _ := strings.Cut(strings.TrimSpace(string(b)), ":")
			x.rpc.reflection = secret
			old, previous := x.previous(t)
			if code, _ := x.execute(); code != 11 {
				t.Fatalf("secret-only reflection exit %d", code)
			}
			x.unchanged(t, old, previous)
			x.rpc.reflection = "prefix-" + secret + "-suffix"
			if code, _ := x.execute(); code != 0 {
				t.Fatalf("embedded positive exit %d", code)
			}
		})
	}
}

// Every shared platform/identity negative and its Linux positive exercise the
// helper's pre-credential admission predicate. Kernel I/O is tested separately.
func TestHelperSharedQualification(t *testing.T) {
	for _, v := range observations(t) {
		if v.Kind != "qualification" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			q := v.Admission
			c := Configuration{NodeUID: q.NodeUID, ServerUID: q.ServerUID, AllowedUIDs: q.AllowedUIDs, WorkloadUIDs: q.WorkloadUIDs, NodeDedicated: q.Dedicated}
			proof := platformEvidence{platform: q.Platform, endpoint: q.EndpointProof, dump: q.DumpProtected, user: q.InitialUser, network: q.InitialNetwork, bind: q.LoopbackBind, allow: q.LoopbackAllow}
			got := admitCredentialHolder(c, proof) == nil
			if got != v.Expected["available"] {
				t.Fatalf("credential-holder admission %t want %v", got, v.Expected["available"])
			}
		})
	}
}

// Structural check only: the unconfigured decoy is unreachable through the single
// credential_file field; this does not test a runtime credential selector.
// The control plant for this detector is the preceding explicit local open.
func TestHelperUnselectedCredentialNotOpened(t *testing.T) {
	for _, mode := range []string{"cookie", "rpcauth-user"} {
		t.Run(mode, func(t *testing.T) {
			x := makeFixture(t, mode)
			decoy := filepath.Join(x.root, "unselected-credential")
			if e := os.WriteFile(decoy, []byte("public-decoy:public-unselected-marker"), 0600); e != nil {
				t.Fatal(e)
			}
			fd, e := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
			if e != nil {
				t.Fatal(e)
			}
			defer syscall.Close(fd)
			if _, e = syscall.InotifyAddWatch(fd, decoy, syscall.IN_OPEN); e != nil {
				t.Fatal(e)
			}
			f, e := os.Open(decoy)
			if e != nil {
				t.Fatal(e)
			}
			f.Close()
			buf := make([]byte, 4096)
			if n, e := syscall.Read(fd, buf); e != nil || n == 0 {
				t.Fatal("open detector positive control")
			}
			if code, _ := x.execute(); code != 0 {
				t.Fatalf("selected credential control exit %d", code)
			}
			if n, e := syscall.Read(fd, buf); n > 0 || e != syscall.EAGAIN {
				t.Fatal("unselected credential opened")
			}
		})
	}
}

// A known different bestblock is movement only if both fixed views are otherwise
// valid. Semantic contradictions still win over movement and preserve old bytes.
func TestHelperMixedMiddleEvidence(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			x.rpc.invalid = "bestblock"
			if invalid {
				x.rpc.state = "unconfirmed"
			}
			// Force a contradictory confirmed count beside the bestblock movement.
			calls := 0
			r, e := newRPC(x.c, x.p)
			if e != nil {
				t.Fatal(e)
			}
			defer r.client.CloseIdleConnections()
			r.client = &http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				confirmations := 1
				if invalid {
					confirmations = 0
				}
				raw := wire(map[string]any{"id": "snapshot", "error": nil, "result": map[string]any{"bestblock": strings.Repeat("f", 64), "confirmations": confirmations, "scriptPubKey": map[string]any{"hex": "51"}}})
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}
			at, _ := parseJSON(wire(tipFixture()), 4096, false, false)
			_, e = r.readSeal(context.Background(), x.c.Seals[0], at)
			want := "tip_moved"
			if invalid {
				want = "unavailable"
			}
			if calls != 2 || failureClass(e) != want {
				t.Fatalf("mixed middle class %s want %s", failureClass(e), want)
			}
			x.unchanged(t, old, b)
		})
	}
}

// An empty reservation honors cancellation, a full reservation admits a read,
// and a long idle period refills only to the fixed 512-token cap. This does not
// qualify elapsed-time scheduling or maximal-set completion under live load.
func TestHelperReservationControls(t *testing.T) {
	p := newPacer()
	if e := p.take(context.Background()); e != nil {
		t.Fatal(e)
	}
	p.tokens = 0
	p.last = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := p.take(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("reservation cancellation: %v", e)
	}
	p.tokens = 0
	p.last = time.Now().Add(-10 * time.Second)
	if e := p.take(context.Background()); e != nil || p.tokens != 511 {
		t.Fatalf("reservation cap/refill: %v tokens %v", e, p.tokens)
	}
}
