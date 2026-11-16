package chaingateway

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeRPC struct {
	flexible          bool
	nameBytes         []byte
	expired           bool
	scriptHex         string
	delay             time.Duration
	failView          string
	active, maxActive int
	mu                sync.Mutex
	tips              []map[string]any
	tipCalls          int
	methods           []string
	auth              string
	fail              string
	reflection        string
	state             string
	probeAllowed      bool
	absent            bool
	invalid           string
	entered           chan struct{}
	release           chan struct{}
}

func tipFixture() map[string]any {
	return map[string]any{"hash": strings.Repeat("1", 64), "height": 100, "time": 1699999990}
}
func (f *fakeRPC) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string            `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	f.mu.Lock()
	f.active++
	if f.active > f.maxActive {
		f.maxActive = f.active
	}
	defer func() { f.mu.Lock(); f.active--; f.mu.Unlock() }()
	f.methods = append(f.methods, req.Method)
	auth := r.Header.Get("Authorization")
	fail := f.fail
	reflection := f.reflection
	invalid := f.invalid
	if auth != f.auth {
		f.mu.Unlock()
		http.Error(w, "not authenticated", 401)
		return
	}
	var result any
	at := tipFixture()
	if f.tipCalls > 0 && len(f.tips) > 0 {
		at = f.tips[(f.tipCalls-1)%len(f.tips)]
	}
	switch req.Method {
	case "getrpcinfo":
		if !f.probeAllowed {
			f.mu.Unlock()
			http.Error(w, "denied", 403)
			return
		}
		result = map[string]any{}
	case "getblockchaininfo":
		at = tipFixture()
		if len(f.tips) > 0 {
			at = f.tips[f.tipCalls%len(f.tips)]
		}
		f.tipCalls++
		result = map[string]any{"chain": "regtest", "blocks": at["height"], "bestblockhash": at["hash"], "initialblockdownload": false}
		if invalid == "network" {
			result.(map[string]any)["chain"] = "main"
		}
		if invalid == "ibd" {
			result.(map[string]any)["initialblockdownload"] = true
		}
	case "getblockheader":
		var h string
		json.Unmarshal(req.Params[0], &h)
		if h != at["hash"] {
			f.mu.Unlock()
			http.Error(w, "header binding", 400)
			return
		}
		result = at
	case "getblockhash":
		if string(req.Params[0]) == "0" {
			result = strings.Repeat("0", 64)
			if invalid == "genesis" {
				result = strings.Repeat("f", 64)
			}
		} else {
			result = strings.Repeat("2", 64)
		}
	case "name_show":
		if len(req.Params) != 2 || (!f.flexible && string(req.Params[0]) != `"69642f6578616d706c65"`) || string(req.Params[1]) != `{"allowExpired":true,"nameEncoding":"hex","valueEncoding":"hex"}` {
			f.mu.Unlock()
			http.Error(w, "name options", 400)
			return
		}
		value := []byte(`{"public":"pin"}`)
		if f.nameBytes != nil {
			value = f.nameBytes
		}
		if reflection != "" {
			value = []byte(reflection)
		}
		result = map[string]any{"name": "69642f6578616d706c65", "name_encoding": "hex", "value_encoding": "hex", "expired": false, "height": 90, "txid": strings.Repeat("a", 64), "vout": 0, "value": hex.EncodeToString(value)}
		if f.flexible {
			var requested string
			json.Unmarshal(req.Params[0], &requested)
			result.(map[string]any)["name"] = requested
		}
		if f.expired {
			result.(map[string]any)["expired"] = true
		}
		if invalid == "encoding" {
			result.(map[string]any)["value_encoding"] = "ascii"
		}
		if invalid == "name" {
			result.(map[string]any)["name"] = "id/foreign"
		}
	case "gettxout":
		if len(req.Params) != 3 || string(req.Params[0]) != `"`+strings.Repeat("a", 64)+`"` || (!f.flexible && string(req.Params[1]) != "2") || (string(req.Params[2]) != "true" && string(req.Params[2]) != "false") {
			f.mu.Unlock()
			http.Error(w, "outpoint parameters", 400)
			return
		}
		if !f.absent {
			mempool := string(req.Params[2]) == "true"
			if !(f.state == "unconfirmed" && !mempool) && !(f.state == "spend_pending" && mempool) {
				confirmations := 1
				if f.state == "unconfirmed" {
					confirmations = 0
				}
				result = map[string]any{"bestblock": at["hash"], "confirmations": confirmations, "scriptPubKey": map[string]any{"hex": "51"}}
				if f.scriptHex != "" {
					result.(map[string]any)["scriptPubKey"] = map[string]any{"hex": f.scriptHex}
				}
				if invalid == "count_disagrees" && mempool {
					result.(map[string]any)["confirmations"] = 2
				}
				if invalid == "confirmed_missing" && !mempool {
					result = nil
				}
				if invalid == "bestblock" {
					result.(map[string]any)["bestblock"] = strings.Repeat("f", 64)
				}
				if invalid == "script_disagrees" && mempool {
					result.(map[string]any)["scriptPubKey"] = map[string]any{"hex": "52"}
				}
				if invalid == "zero_confirmed" {
					result.(map[string]any)["confirmations"] = 0
				}
			}
		}
	default:
		f.mu.Unlock()
		http.Error(w, "forbidden method", 400)
		return
	}
	entered, release := f.entered, f.release
	delay := f.delay
	if req.Method == "gettxout" && len(req.Params) == 3 && string(req.Params[2]) == f.failView {
		fail = "gettxout"
	}
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if req.Method == "name_show" && entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	if fail == req.Method {
		fmt.Fprintf(w, `{"result":null,"error":{"code":-1,"message":%q},"id":"snapshot"}`, reflection)
		return
	}
	if invalid == "duplicate" {
		io.WriteString(w, `{"result":null,"result":{},"error":null,"id":"snapshot"}`)
		return
	}
	if invalid == "alias" {
		io.WriteString(w, `{"result":{},"Result":{},"error":null,"id":"snapshot"}`)
		return
	}
	if invalid == "oversize" {
		io.WriteString(w, strings.Repeat("x", 65537))
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"result": result, "error": nil, "id": req.ID})
}

type fixture struct {
	root, path string
	c          Configuration
	p          custody
	rpc        *fakeRPC
}

func makeFixture(t *testing.T, mode string) *fixture {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	secret := "synthetic-cookie-password"
	user := "__cookie__"
	if mode == "rpcauth-user" {
		user = "snapshot-observer"
		secret = "synthetic-user-password"
	}
	f := &fakeRPC{auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	c := Configuration{ServerUID: 2001, AllowedUIDs: []uint32{0, 2002}, WorkloadUIDs: []uint32{0, 2003}, NodeDedicated: true, GatewayVerifierUser: "gateway-observer", NodeUID: uint32(os.Getuid()), Profile: "cg1-v1", NodeConfig: filepath.Join(root, "node.conf"), VerifierUser: "snapshot-observer", CookieSource: "live", RPCURL: srv.URL, Network: "regtest", Genesis: strings.Repeat("0", 64), CredentialMode: mode, CredentialFile: filepath.Join(root, "credential"), CredentialGroup: uint32(os.Getgid()), Output: filepath.Join(root, "snapshot.json"), Lock: filepath.Join(root, "writer.lock"), Names: []string{"id/example"}, Seals: []Outpoint{{strings.Repeat("a", 64), 2}}}
	if e := os.WriteFile(c.CredentialFile, []byte(user+":"+secret+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	x := &fixture{root: root, path: filepath.Join(root, "config.json"), c: c, p: custody{uid: uint32(os.Getuid()), anchor: root, namespacePID: os.Getpid()}, rpc: f}
	if mode == "rpcauth-user" {
		x.c.CookieSource = "none"
	}
	if e := os.WriteFile(c.NodeConfig, []byte(loopbackPolicy+"rpcwhitelistdefault=1\nrpcwhitelist=snapshot-observer:"+verifierMethods+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	x.config(t)
	return x
}
func (x *fixture) config(t *testing.T) {
	t.Helper()
	b, _ := json.Marshal(x.c)
	if e := os.WriteFile(x.path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func (x *fixture) execute() (int, string) {
	var out bytes.Buffer
	code := runReport(x.path, x.p, &out)
	return code, out.String()
}
func (x *fixture) previous(t *testing.T) (os.FileInfo, []byte) {
	t.Helper()
	b := []byte("previous complete snapshot")
	if e := os.WriteFile(x.c.Output, b, 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(x.c.Output, 0644); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(x.c.Output)
	if e != nil {
		t.Fatal(e)
	}
	return st, b
}
func (x *fixture) unchanged(t *testing.T, old os.FileInfo, b []byte) {
	t.Helper()
	got, e := os.ReadFile(x.c.Output)
	if e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(x.c.Output)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, b) || !os.SameFile(st, old) || !st.ModTime().Equal(old.ModTime()) {
		t.Fatal("previous snapshot touched")
	}
}

// Equal complete brackets publish canonical, closed v1 bytes with exact watch
// bindings; absence remains an observation rather than an invented spend proof.
func TestBracketEqualWrites(t *testing.T) {
	for _, absent := range []bool{false, true} {
		t.Run(fmt.Sprint(absent), func(t *testing.T) {
			x := makeFixture(t, "cookie")
			x.rpc.absent = absent
			if code, out := x.execute(); code != 0 {
				t.Fatalf("code=%d output=%s", code, out)
			}
			b, e := os.ReadFile(x.c.Output)
			if e != nil {
				t.Fatal(e)
			}
			if e = validate("snapshot", b); e != nil {
				t.Fatal(e)
			}
			m, _ := parse(b, 65536)
			if m["consistency"] != "bracketed" || m["mode"] != "observe_only" || m["network"] != "regtest" {
				t.Fatal("snapshot claims")
			}
			if m["names"].([]any)[0].(map[string]any)["name"] != "id/example" {
				t.Fatal("watch name")
			}
			state := m["seals"].([]any)[0].(map[string]any)["state"]
			if (state == "not_in_utxo_set") != absent {
				t.Fatal("absence mapping")
			}
			methods := x.rpc.methods
			want := []string{"getblockhash", "getblockchaininfo", "getblockheader"}
			if len(methods) != 9 || !reflect.DeepEqual(methods[:3], want) || !reflect.DeepEqual(methods[7:], []string{"getblockchaininfo", "getblockheader"}) {
				t.Fatalf("read bracket order %v", methods)
			}
			counts := map[string]int{}
			for _, method := range methods {
				counts[method]++
			}
			if counts["name_show"] != 1 || counts["gettxout"] != 2 || counts["getblockhash"] != 2 {
				t.Fatal("fixed read set")
			}

		})
	}
}

// Each Tip member is independently significant. Exhaustion performs three whole
// collections, includes 100/200ms backoff, and preserves bytes/inode/mtime.
func TestBracketMovedKeepsPrevious(t *testing.T) {
	for _, field := range []string{"hash", "height", "time"} {
		t.Run(field, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			a := tipFixture()
			z := tipFixture()
			if field == "hash" {
				z[field] = strings.Repeat("3", 64)
			} else {
				z[field] = 101
				if field == "time" {
					z[field] = 1699999991
				}
			}
			x.rpc.tips = []map[string]any{a, z}
			start := time.Now()
			want := ExitTipMoved
			if field != "hash" {
				want = ExitNode
			}
			if code, _ := x.execute(); code != want {
				t.Fatalf("expected tip exhaustion exit 12; got %d", code)
			}
			if field == "hash" && x.rpc.tipCalls != 6 {
				t.Fatalf("expected six bracket reads, got %d", x.rpc.tipCalls)
			}
			if field == "hash" && time.Since(start) < 300*time.Millisecond {
				t.Fatal("retry backoff omitted")
			}
			x.unchanged(t, old, b)
		})
	}
}

// A discarded first set cannot leak into the stable second attempt.
func TestBracketMovedRetriesThenWrites(t *testing.T) {
	x := makeFixture(t, "cookie")
	a := tipFixture()
	b := tipFixture()
	b["hash"] = strings.Repeat("3", 64)
	x.rpc.tips = []map[string]any{a, b, b, b}
	if code, _ := x.execute(); code != 0 || x.rpc.tipCalls != 4 {
		t.Fatalf("retry result code=%d reads=%d", code, x.rpc.tipCalls)
	}
	raw, _ := os.ReadFile(x.c.Output)
	m, e := parse(raw, 65536)
	if e != nil || m["tip"].(map[string]any)["hash"] != b["hash"] {
		t.Fatal("wrong retry tip")
	}
}

// Fixed node errors and malformed/binding failures never update the previous
// snapshot or expose upstream messages. No real node is contacted.
func TestNodeErrorKeepsPrevious(t *testing.T) {
	cases := []string{"getblockhash", "getblockchaininfo", "getblockheader", "name_show", "gettxout", "network", "ibd", "genesis", "name", "encoding", "duplicate", "alias", "oversize"}
	for _, failure := range cases {
		t.Run(failure, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			if strings.HasPrefix(failure, "get") || failure == "name_show" {
				x.rpc.fail = failure
			} else {
				x.rpc.invalid = failure
			}
			x.rpc.reflection = "synthetic-cookie-password"
			if code, out := x.execute(); code != ExitNode || strings.Contains(out, x.rpc.reflection) {
				t.Fatalf("node failure code=%d", code)
			}
			x.unchanged(t, old, b)
		})
	}
}

// An open old reader retains old complete bytes after replacement; a new reader
// sees the new schema and a different inode. In-place writes violate this claim.
func TestAtomicPublication(t *testing.T) {
	x := makeFixture(t, "cookie")
	old, b := x.previous(t)
	f, e := os.Open(x.c.Output)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if code, _ := x.execute(); code != 0 {
		t.Fatalf("code=%d", code)
	}
	retained, _ := io.ReadAll(f)
	fresh, _ := os.ReadFile(x.c.Output)
	st, _ := os.Stat(x.c.Output)
	if !bytes.Equal(retained, b) || os.SameFile(st, old) || bytes.Equal(fresh, b) || validate("snapshot", fresh) != nil {
		t.Fatal("atomic replacement violated")
	}
	if st.Mode().Perm() != 0644 {
		t.Fatal("output mode")
	}
	temps, _ := filepath.Glob(filepath.Join(x.root, ".snapshot-*"))
	if len(temps) != 0 {
		t.Fatal("temp file retained")
	}
}

// While a first writer holds its RPC read, the second exits 13 without any RPC
// call or output change. Release then lets the original writer publish.
func TestLockExcludesSecondWriter(t *testing.T) {
	x := makeFixture(t, "cookie")
	old, b := x.previous(t)
	x.rpc.entered = make(chan struct{}, 1)
	x.rpc.release = make(chan struct{})
	done := make(chan int, 1)
	go func() { code, _ := x.execute(); done <- code }()
	select {
	case <-x.rpc.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first writer did not enter")
	}
	watch, e := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if e != nil {
		close(x.rpc.release)
		<-done
		t.Fatal(e)
	}
	defer syscall.Close(watch)
	if _, e = syscall.InotifyAddWatch(watch, x.c.CredentialFile, syscall.IN_OPEN); e != nil {
		close(x.rpc.release)
		<-done
		t.Fatal(e)
	}
	second := make(chan int, 1)
	go func() { code, _ := x.execute(); second <- code }()
	code := -1
	select {
	case code = <-second:
	case <-time.After(time.Second):
		close(x.rpc.release)
		<-done
		<-second
		t.Fatal("second writer was not excluded")
	}
	// The first writer may continue its parallel seal reads while its name read
	// is blocked; global RPC counts cannot identify the second writer's effects.
	events := make([]byte, 4096)
	n, watchError := syscall.Read(watch, events)
	x.unchanged(t, old, b)
	close(x.rpc.release)
	select {
	case first := <-done:
		if first != 0 {
			t.Fatalf("first code=%d", first)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not finish")
	}
	// Bind the supervisor result to the shared contract rather than a local constant.
	var expected map[string]any
	for _, v := range observations(t) {
		if v.Name == "snapshot_stage_lock_busy" {
			expected = v.Expected
		}
	}
	if expected == nil || code != int(uintValue(expected["exit"])) {
		t.Fatalf("lock failed: second code=%d", code)
	}
	if n > 0 || watchError != syscall.EAGAIN {
		t.Fatalf("second writer opened credential: %d %v", n, watchError)
	}
}

// Both file modes authenticate with synthetic credentials, reload rotation each
// run and suppress raw/base64 credentials on success, upstream error and reflected
// name bytes. The leak plant must fail this named diagnostic assertion.
func TestCredentialsNeverAppearInOutput(t *testing.T) {
	for _, mode := range []string{"cookie", "rpcauth-user"} {
		t.Run(mode, func(t *testing.T) {
			x := makeFixture(t, mode)
			for _, scenario := range []string{"success", "rotated", "error", "projection"} {
				raw, _ := os.ReadFile(x.c.CredentialFile)
				s := strings.TrimSpace(string(raw))
				user, pass, _ := strings.Cut(s, ":")
				if scenario == "rotated" {
					pass = "synthetic-rotated-password"
					s = user + ":" + pass
					os.WriteFile(x.c.CredentialFile, []byte(s), 0600)
					x.rpc.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
				}
				x.rpc.fail = ""
				x.rpc.reflection = ""
				want := 0
				if scenario == "error" {
					x.rpc.fail = "name_show"
					x.rpc.reflection = s
					want = ExitNode
				}
				if scenario == "projection" {
					x.rpc.reflection = s
					want = ExitNode
				}
				code, out := x.execute()
				if code != want {
					t.Fatalf("%s code=%d want=%d", scenario, code, want)
				}
				published, _ := os.ReadFile(x.c.Output)
				for _, secret := range []string{s, user, pass, base64.StdEncoding.EncodeToString([]byte(s)), base64.StdEncoding.EncodeToString([]byte(pass))} {
					if strings.Contains(out, secret) || bytes.Contains(published, []byte(secret)) {
						t.Fatal("credential disclosure in output")
					}
				}
			}
		})
	}
}

// Config failures are rejected before node access, with unchanged previous data;
// a valid neighbor above proves that rejecting every configuration cannot pass.
func TestConfigNegatives(t *testing.T) {
	mutations := map[string]func(*fixture){
		"same verifier user": func(x *fixture) { x.c.GatewayVerifierUser = x.c.VerifierUser },
		"profile":            func(x *fixture) { x.c.Profile = "cg1-v2" },
		"cookie source":      func(x *fixture) { x.c.CookieSource = "fallback" },
		"external endpoint":  func(x *fixture) { x.c.RPCURL = "http://192.0.2.1:1234" },
		"endpoint user":      func(x *fixture) { x.c.RPCURL = "http://user:pass@127.0.0.1:1234" },
		"endpoint query":     func(x *fixture) { x.c.RPCURL += "?debug=1" },
		"endpoint path":      func(x *fixture) { x.c.RPCURL += "/wallet/x" },
		"https":              func(x *fixture) { x.c.RPCURL = strings.Replace(x.c.RPCURL, "http:", "https:", 1) },
		"network":            func(x *fixture) { x.c.Network = "testnet" },
		"genesis":            func(x *fixture) { x.c.Genesis = "bad" },
		"mode":               func(x *fixture) { x.c.CredentialMode = "rpcauth" },
		"relative path":      func(x *fixture) { x.c.Output = "snapshot.json" },
		"unclean path":       func(x *fixture) { x.c.Output = x.root + "/./snapshot.json" },
		"path collision":     func(x *fixture) { x.c.Output = x.c.CredentialFile },
		"no names":           func(x *fixture) { x.c.Names = []string{} },
		"duplicate name":     func(x *fixture) { x.c.Names = append(x.c.Names, x.c.Names...) },
		"name case":          func(x *fixture) { x.c.Names = []string{"id/Example"} },
		"names capacity":     func(x *fixture) { x.c.Names = make([]string, 17) },
		"no seals":           func(x *fixture) { x.c.Seals = []Outpoint{} },
		"duplicate seal":     func(x *fixture) { x.c.Seals = append(x.c.Seals, x.c.Seals...) },
		"seal hash":          func(x *fixture) { x.c.Seals[0].Txid = "BAD" },
		"seal capacity":      func(x *fixture) { x.c.Seals = make([]Outpoint, 257) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			mutate(x)
			x.config(t)
			if code, _ := x.execute(); code != ExitConfig {
				t.Fatalf("config exit %d", code)
			}
			x.c.Output = filepath.Join(x.root, "snapshot.json")
			x.unchanged(t, old, b)
			if len(x.rpc.methods) != 0 {
				t.Fatal("node call on invalid config")
			}
		})
	}
	for _, raw := range []string{`{}`, `{"names":[],"names":[]}`, `{"names":[],"Names":[]}`, `{"\u006eames":[]}`, `null`, `{} {}`} {
		t.Run(raw, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			os.WriteFile(x.path, []byte(raw), 0600)
			if code, _ := x.execute(); code != ExitConfig {
				t.Fatalf("json exit %d", code)
			}
		})
	}
}

// No symlink/hardlink or writable input/output custody can be used; the fixture
// anchor models trusted installed ancestry without running tests as root.
func TestCustodyNegatives(t *testing.T) {
	for _, kind := range []string{"config symlink", "config hardlink", "config writable", "credential symlink", "credential hardlink", "credential writable", "credential group", "credential verifier", "credential bare verifier", "cookie mode", "output symlink", "output hardlink", "output writable", "lock symlink", "lock hardlink"} {
		t.Run(kind, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			want := ExitConfig
			target := x.path
			if strings.HasPrefix(kind, "credential") {
				target = x.c.CredentialFile
				want = ExitNode
			}
			if kind == "cookie mode" {
				target = x.c.CredentialFile
				want = ExitNode
			}
			if strings.HasPrefix(kind, "output") {
				target = x.c.Output
				want = ExitPublish
			}
			if strings.HasPrefix(kind, "lock") {
				target = x.c.Lock
				os.WriteFile(target, []byte{}, 0600)
			}
			if strings.Contains(kind, "symlink") {
				os.Rename(target, target+".real")
				os.Symlink(target+".real", target)
			}
			if strings.Contains(kind, "hardlink") {
				os.Link(target, target+".link")
			}
			if strings.Contains(kind, "writable") {
				os.Chmod(target, 0666)
			}
			if kind == "credential group" {
				x.c.CredentialGroup++
				x.config(t)
			}
			if kind == "credential bare verifier" {
				os.WriteFile(target, []byte("reader:abcdef$"+strings.Repeat("a", 64)), 0600)
			}
			if kind == "credential verifier" {
				os.WriteFile(target, []byte("rpcauth=user:salt$hash"), 0600)
			}
			if kind == "cookie mode" {
				os.WriteFile(target, []byte("other:synthetic-password"), 0600)
			}
			if code, _ := x.execute(); code != want {
				t.Fatalf("custody exit=%d want=%d", code, want)
			}
			x.unchanged(t, old, b)
		})
	}
}

// Public CLI refuses unprivileged execution without opening host inputs.
func TestMainRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("tests must run unprivileged")
	}
	var out bytes.Buffer
	if Main([]string{"-config", "/nonexistent"}, &out) != ExitConfig {
		t.Fatal("root admission")
	}
}

// Intermediate symlinks and writable directories are forbidden even when the
// leaf itself has acceptable ownership and mode.
func TestProtectedAncestors(t *testing.T) {
	for _, kind := range []string{"symlink", "writable"} {
		t.Run(kind, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			dir := filepath.Join(x.root, "protected")
			if e := os.Mkdir(dir, 0755); e != nil {
				t.Fatal(e)
			}
			leaf := filepath.Join(dir, "credential")
			raw, _ := os.ReadFile(x.c.CredentialFile)
			os.WriteFile(leaf, raw, 0600)
			if kind == "symlink" {
				alias := filepath.Join(x.root, "alias")
				os.Symlink(dir, alias)
				leaf = filepath.Join(alias, "credential")
			} else {
				os.Chmod(dir, 0777)
			}
			x.c.CredentialFile = leaf
			x.config(t)
			if code, _ := x.execute(); code != ExitNode {
				t.Fatalf("ancestor accepted: %d", code)
			}
			x.unchanged(t, old, b)
		})
	}
}

// Closed outpoints require both exact names; struct-decoder case folding and
// missing uint32 defaults cannot admit a different operator watch set. Zero and
// max uint32 remain valid neighboring configurations without contacting a node.
func TestConfigExactOutpointFields(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"zero", func(m map[string]any) { m["vout"] = 0 }, true},
		{"max", func(m map[string]any) { m["vout"] = uint64(4294967295) }, true},
		{"missing vout", func(m map[string]any) { delete(m, "vout") }, false},
		{"missing txid", func(m map[string]any) { delete(m, "txid") }, false},
		{"case alias", func(m map[string]any) { m["Vout"] = m["vout"]; delete(m, "vout") }, false},
		{"extra field", func(m map[string]any) { m["other"] = 0 }, false},
		{"overflow", func(m map[string]any) { m["vout"] = uint64(4294967296) }, false},
		{"negative", func(m map[string]any) { m["vout"] = -1 }, false},
		{"string", func(m map[string]any) { m["vout"] = "2" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			raw, _ := json.Marshal(x.c)
			var m map[string]any
			json.Unmarshal(raw, &m)
			point := m["seals"].([]any)[0].(map[string]any)
			tc.change(point)
			raw, _ = json.Marshal(m)
			if e := os.WriteFile(x.path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			_, e := loadConfig(x.path, x.p)
			if (e == nil) != tc.valid {
				t.Fatalf("exact outpoint verdict valid=%v error=%v", tc.valid, e)
			}
			if !tc.valid {
				if code, _ := x.execute(); code != ExitConfig {
					t.Fatalf("outpoint config code %d", code)
				}
			}
			x.unchanged(t, old, b)
			if len(x.rpc.methods) != 0 {
				t.Fatal("node called by config gate")
			}
		})
	}
}
