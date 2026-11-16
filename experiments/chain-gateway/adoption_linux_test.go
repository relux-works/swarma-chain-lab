package chaingateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A genuine unprivileged TCP endpoint is authenticated by the real kernel.
// The wrong pinned UID receives zero bytes, not merely a missing HTTP request.
func TestEndpointAuthenticationBeforeCredential(t *testing.T) {
	x := makeFixture(t, "cookie")
	if code, _ := x.execute(); code != 0 {
		t.Fatalf("genuine endpoint refused: %d", code)
	}
	old, b := x.previous(t)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	received := make(chan int, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			received <- -1
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		received <- len(b)
	}()
	x.c.RPCURL = "http://" + listener.Addr().String()
	x.c.NodeUID++
	x.config(t)
	fd, e := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(fd)
	if _, e = syscall.InotifyAddWatch(fd, x.c.CredentialFile, syscall.IN_OPEN); e != nil {
		t.Fatal(e)
	}
	if code, _ := x.execute(); code != ExitNode {
		t.Fatalf("endpoint authentication bypassed: %d", code)
	}
	if n := <-received; n != 0 {
		t.Fatalf("unauthenticated endpoint received %d bytes", n)
	}
	events := make([]byte, 4096)
	n, e := syscall.Read(fd, events)
	if n > 0 || e != syscall.EAGAIN {
		t.Fatalf("credential opened before authentication: %d %v", n, e)
	}
	x.unchanged(t, old, b)
}

// Synthetic kernel rows isolate reverse ownership, tuple/cookie and ambiguity
// decisions; the preceding test separately exercises the actual netlink source.
func TestEndpointReverseTupleEvidence(t *testing.T) {
	server := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	client := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321}
	uid := uint32(os.Getuid())
	valid := []socketEvidence{{state: 10, local: server.IP, localPort: 1234, uid: uid}, {state: 1, local: server.IP, remote: client.IP, localPort: 1234, remotePort: 4321, uid: uid, inode: 1, cookie: [8]byte{1}}}
	if e := verifySocketRows(valid, server, client, uid); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func([]socketEvidence) []socketEvidence{
		"listener uid":       func(r []socketEvidence) []socketEvidence { r[0].uid++; return r },
		"reverse uid":        func(r []socketEvidence) []socketEvidence { r[1].uid++; return r },
		"reverse port":       func(r []socketEvidence) []socketEvidence { r[1].remotePort++; return r },
		"reverse address":    func(r []socketEvidence) []socketEvidence { r[1].remote = net.ParseIP("127.0.0.2"); return r },
		"missing listener":   func(r []socketEvidence) []socketEvidence { return r[1:] },
		"missing peer":       func(r []socketEvidence) []socketEvidence { return r[:1] },
		"mixed reuseport":    func(r []socketEvidence) []socketEvidence { other := r[0]; other.uid++; return append(r, other) },
		"ambiguous listener": func(r []socketEvidence) []socketEvidence { return append(r, r[0]) },
		"ambiguous peer":     func(r []socketEvidence) []socketEvidence { return append(r, r[1]) },
		"missing cookie":     func(r []socketEvidence) []socketEvidence { r[1].cookie = [8]byte{}; return r },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if verifySocketRows(mutate(slices.Clone(valid)), server, client, uid) == nil {
				t.Fatal("invalid endpoint evidence accepted")
			}
		})
	}
}

// Every verifier runs only its inspected exact whitelist plus a denied harmless
// probe. Missing/union/extra methods and a successful probe retain the old file.
func TestVerifierWhitelistAndDenial(t *testing.T) {
	good := "rpcwhitelistdefault=1\nrpcwhitelist=snapshot-observer:" + verifierMethods + "\n"
	cases := map[string]string{
		"valid": good, "missing": "rpcwhitelistdefault=1\n",
		"extra":           strings.Replace(good, "gettxout", "gettxout,stop", 1),
		"union":           good + "rpcwhitelist=snapshot-observer:getrpcinfo\n",
		"default open":    strings.Replace(good, "default=1", "default=0", 1),
		"missing default": strings.TrimPrefix(good, "rpcwhitelistdefault=1\n"),
		"include":         good + "includeconf=other.conf\n",
		"section":         "[main]\n" + good,
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			x := makeFixture(t, "rpcauth-user")
			old, b := x.previous(t)
			if e := os.WriteFile(x.c.NodeConfig, []byte(config), 0600); e != nil {
				t.Fatal(e)
			}
			want := ExitNode
			if name == "valid" {
				want = 0
			}
			if code, _ := x.execute(); code != want {
				t.Fatalf("whitelist exit %d want %d", code, want)
			}
			if want != 0 {
				x.unchanged(t, old, b)
				if len(x.rpc.methods) != 0 {
					t.Fatal("RPC before whitelist acceptance")
				}
			} else {
				if x.rpc.methods[0] != "getrpcinfo" {
					t.Fatal("denial probe omitted")
				}
				for _, m := range x.rpc.methods {
					if m != "getrpcinfo" && !slices.Contains(strings.Split(verifierMethods, ","), m) {
						t.Fatal("method outside exact set")
					}
				}
			}
		})
	}
	t.Run("probe allowed", func(t *testing.T) {
		x := makeFixture(t, "rpcauth-user")
		old, b := x.previous(t)
		x.rpc.probeAllowed = true
		if code, _ := x.execute(); code != ExitNode {
			t.Fatal("successful denial probe accepted")
		}
		x.unchanged(t, old, b)
		if !reflect.DeepEqual(x.rpc.methods, []string{"getrpcinfo"}) {
			t.Fatal("continued after denied capability check")
		}
	})
}

// A bracketed snapshot reports all F5 states without creating any permanent
// journal, even across pending/absence/recovery; absent on first sight is local
// to that observation. The helper has no enforcement-state output.
func TestSnapshotF5StatesNeverPermanent(t *testing.T) {
	x := makeFixture(t, "cookie")
	for _, state := range []string{"not_in_utxo_set", "unconfirmed", "unspent", "spend_pending", "not_in_utxo_set", "unspent"} {
		x.rpc.mu.Lock()
		x.rpc.state = state
		x.rpc.absent = state == "not_in_utxo_set"
		x.rpc.mu.Unlock()
		if code, _ := x.execute(); code != 0 {
			t.Fatalf("%s exit %d", state, code)
		}
		b, e := os.ReadFile(x.c.Output)
		if e != nil {
			t.Fatal(e)
		}
		m, e := parse(b, 65536)
		if e != nil {
			t.Fatal(e)
		}
		seal := m["seals"].([]any)[0].(map[string]any)
		if seal["state"] != state {
			t.Fatalf("F5 state %s projected as %v", state, seal["state"])
		}
		if state != "not_in_utxo_set" && (seal["script_pubkey"] != "51" || fmt.Sprint(seal["confirmations"]) != map[bool]string{true: "0", false: "1"}[state == "unconfirmed"]) {
			t.Fatal("F5 metadata")
		}
		entries, e := os.ReadDir(x.root)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if !slices.Contains([]string{"config.json", "credential", "node.conf", "snapshot.json", "writer.lock"}, entry.Name()) {
				t.Fatalf("permanent journal or unexpected output: %s", entry.Name())
			}
		}
	}
}

// A failed name or either UTXO read refuses the whole set (exit 11), preserving
// bytes/inode/mtime rather than converting the record into an absence.
func TestFailedRecordReadExit11KeepsPrevious(t *testing.T) {
	for _, method := range []string{"name_show", "gettxout"} {
		t.Run(method, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			x.rpc.fail = method
			if code, _ := x.execute(); code != 11 {
				t.Fatalf("failed record exit %d", code)
			}
			x.unchanged(t, old, b)
		})
	}
}

// Inconsistent view metadata fails closed, while valid two-view controls above
// prove the adapter does not merely reject every pair.
func TestF5InconsistentViewsKeepPrevious(t *testing.T) {
	for _, invalid := range []string{"bestblock", "script_disagrees", "zero_confirmed", "count_disagrees", "confirmed_missing"} {
		t.Run(invalid, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			x.rpc.invalid = invalid
			if code, _ := x.execute(); code != ExitNode {
				t.Fatalf("inconsistent views accepted: %d", code)
			}
			x.unchanged(t, old, b)
		})
	}
}

// Exact full credentials and their two Basic forms are refused in decoded name
// octets; fragments/usernames/password substrings remain legitimate public data.
func TestExactCredentialReflection(t *testing.T) {
	for _, kind := range []string{"raw", "base64", "header", "username", "password fragment"} {
		t.Run(kind, func(t *testing.T) {
			x := makeFixture(t, "rpcauth-user")
			raw, _ := os.ReadFile(x.c.CredentialFile)
			full := strings.TrimSpace(string(raw))
			encoded := base64.StdEncoding.EncodeToString([]byte(full))
			value := map[string]string{"raw": full, "base64": encoded, "header": "Basic " + encoded, "username": "snapshot-observer", "password fragment": "synthetic-user"}[kind]
			x.rpc.reflection = value
			want := 0
			if kind == "raw" || kind == "base64" || kind == "header" {
				want = 11
			}
			if code, _ := x.execute(); code != want {
				t.Fatalf("reflection %s exit %d want %d", kind, code, want)
			}
		})
	}
}

// Cleanup removes only recognized owned regular crash temps under the writer
// lock, keeps unknown files, and refuses matching symlinks/hardlinks.
func TestOwnedCrashTempCleanup(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			temp := filepath.Join(x.root, ".snapshot-"+strings.Repeat("a", 24))
			unknown := filepath.Join(x.root, ".snapshot-unrecognized")
			os.WriteFile(unknown, []byte("keep"), 0600)
			switch kind {
			case "regular":
				os.WriteFile(temp, []byte("incomplete"), 0600)
			case "symlink":
				os.Symlink(x.c.Output, temp)
			case "hardlink":
				os.Link(x.c.Output, temp)
			}
			code, _ := x.execute()
			if kind == "regular" {
				if code != 0 {
					t.Fatalf("cleanup exit %d", code)
				}
				if _, e := os.Lstat(temp); !os.IsNotExist(e) {
					t.Fatal("recognized temp retained")
				}
			} else {
				if code != ExitPublish {
					t.Fatalf("invalid crash temp exit %d", code)
				}
				x.unchanged(t, old, b)
			}
			if got, _ := os.ReadFile(unknown); string(got) != "keep" {
				t.Fatal("unknown file removed")
			}
		})
	}
}

// A canceled collection cannot publish a partial set; fixed worker count is
// separately exercised by the complete fake-RPC output paths above.
func TestCanceledCollectionRefuses(t *testing.T) {
	x := makeFixture(t, "cookie")
	r, e := newRPC(x.c, x.p)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, e = r.collect(ctx, x.c, tipFixture())
	if e == nil {
		t.Fatal("canceled collection accepted")
	}
}

// Explicit upstream hex options preserve expired records and opaque value bytes.
func TestHexNameValueAndExpiredRecord(t *testing.T) {
	x := makeFixture(t, "cookie")
	x.rpc.nameBytes = []byte{0, 255, 128, 10, 34}
	x.rpc.expired = true
	if code, _ := x.execute(); code != 0 {
		t.Fatalf("hex record exit %d", code)
	}
	raw, _ := os.ReadFile(x.c.Output)
	m, e := parse(raw, 65536)
	if e != nil {
		t.Fatal(e)
	}
	n := m["names"].([]any)[0].(map[string]any)
	if n["name"] != "id/example" || n["expired"] != true || n["value_b64"] != base64.StdEncoding.EncodeToString(x.rpc.nameBytes) {
		t.Fatal("hex octet projection")
	}
}

// Each fixed UTXO view can fail independently without synthesizing absence.
func TestEitherUTXOReadFailureKeepsPrevious(t *testing.T) {
	for _, view := range []string{"false", "true"} {
		t.Run(view, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			x.rpc.failView = view
			if code, _ := x.execute(); code != ExitNode {
				t.Fatalf("failed view exit %d", code)
			}
			x.unchanged(t, old, b)
		})
	}
}

// Maximal configured counts exercise bounded concurrency and ordering. An
// oversized serialized result refuses the whole attempt and keeps the old file;
// this fake-node check does not qualify live-node cadence under competing load.
func TestMaximalWatchSetAndSerializedBound(t *testing.T) {
	for _, oversize := range []bool{false, true} {
		t.Run(fmt.Sprint(oversize), func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, b := x.previous(t)
			x.rpc.flexible = true
			x.rpc.delay = time.Millisecond
			x.rpc.nameBytes = make([]byte, 520)
			if oversize {
				x.rpc.scriptHex = strings.Repeat("ab", 512)
			}
			x.c.Names = nil
			x.c.Seals = nil
			for i := 0; i < 16; i++ {
				x.c.Names = append(x.c.Names, fmt.Sprintf("id/example-%02d", i))
			}
			for i := 0; i < 256; i++ {
				x.c.Seals = append(x.c.Seals, Outpoint{strings.Repeat("a", 64), uint32(i)})
			}
			x.config(t)
			code, _ := x.execute()
			if oversize {
				if code != ExitNode {
					t.Fatalf("oversized snapshot exit %d", code)
				}
				x.unchanged(t, old, b)
			} else {
				if code != 0 {
					t.Fatalf("maximal set exit %d", code)
				}
				raw, _ := os.ReadFile(x.c.Output)
				m, e := parse(raw, 65536)
				if e != nil {
					t.Fatal(e)
				}
				if len(m["names"].([]any)) != 16 || len(m["seals"].([]any)) != 256 {
					t.Fatal("partial maximal set")
				}
			}
			if x.rpc.maxActive > 16 || x.rpc.maxActive < 2 {
				t.Fatalf("worker bound/max overlap %d", x.rpc.maxActive)
			}
		})
	}
}

// The fixed dispatcher refuses out-of-set operations before any node request.
func TestHelperMethodSetClosed(t *testing.T) {
	x := makeFixture(t, "rpcauth-user")
	r, e := newRPC(x.c, x.p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.call(context.Background(), "stop", nil); e == nil {
		t.Fatal("write method accepted")
	}
	if len(x.rpc.methods) != 0 {
		t.Fatal("forbidden RPC dispatched")
	}
}

// The process is non-dumpable with both core limits zero before credentials.
func TestDumpHardening(t *testing.T) {
	if e := hardenDumps(); e != nil {
		t.Fatal(e)
	}
	v, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 3, 0, 0, 0, 0, 0)
	var limit syscall.Rlimit
	if e != 0 || v != 0 || syscall.Getrlimit(syscall.RLIMIT_CORE, &limit) != nil || limit.Cur != 0 || limit.Max != 0 {
		t.Fatal("dump custody not enforced")
	}
}

// Active-network sections are inspected with global entries; inactive sections
// cannot supply this helper's whitelist and duplicate active entries are unions.
func TestVerifierNetworkSections(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			x := makeFixture(t, "rpcauth-user")
			section := "main"
			want := 11
			if active {
				section = "regtest"
				want = 0
			}
			os.WriteFile(x.c.NodeConfig, []byte("rpcwhitelistdefault=1\n["+section+"]\nrpcwhitelist=snapshot-observer:"+verifierMethods+"\n"), 0600)
			if code, _ := x.execute(); code != want {
				t.Fatalf("section exit %d want %d", code, want)
			}
		})
	}
}

// With each successful RPC below its one-second timeout, a maximal moving set
// still exhausts the single twenty-second budget across retries, preserving the
// previous file. This checks collection cancellation, not scheduler cadence.
func TestTotalCollectionDeadlineAcrossAttempts(t *testing.T) {
	x := makeFixture(t, "cookie")
	old, b := x.previous(t)
	x.rpc.flexible = true
	x.rpc.delay = 300 * time.Millisecond
	a := tipFixture()
	z := tipFixture()
	z["hash"] = strings.Repeat("3", 64)
	x.rpc.tips = []map[string]any{a, z}
	x.c.Seals = nil
	for i := 0; i < 256; i++ {
		x.c.Seals = append(x.c.Seals, Outpoint{strings.Repeat("a", 64), uint32(i)})
	}
	x.config(t)
	start := time.Now()
	code, _ := x.execute()
	elapsed := time.Since(start)
	if code != ExitNode {
		t.Fatalf("total deadline exit %d", code)
	}
	if elapsed < 20*time.Second || elapsed > 24*time.Second {
		t.Fatalf("total collection duration %s", elapsed)
	}
	x.unchanged(t, old, b)
}

// An individual stalled RPC hits its one-second budget without publication.
func TestRPCDeadlineKeepsPrevious(t *testing.T) {
	x := makeFixture(t, "cookie")
	old, b := x.previous(t)
	x.rpc.delay = 1500 * time.Millisecond
	start := time.Now()
	if code, _ := x.execute(); code != ExitNode {
		t.Fatalf("RPC timeout exit %d", code)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("RPC deadline %s", elapsed)
	}
	x.unchanged(t, old, b)
}

// High unsigned indexes remain unavailable until the pinned backend's signed
// index and absence profile is qualified; they are never sent as wrapped values.
func TestUnqualifiedHighVoutKeepsPrevious(t *testing.T) {
	x := makeFixture(t, "cookie")
	old, b := x.previous(t)
	x.c.Seals[0].Vout = 2147483648
	x.config(t)
	if code, _ := x.execute(); code != ExitNode {
		t.Fatalf("unqualified vout exit %d", code)
	}
	for _, method := range x.rpc.methods {
		if method == "gettxout" {
			t.Fatal("high vout dispatched")
		}
	}
	x.unchanged(t, old, b)
}
