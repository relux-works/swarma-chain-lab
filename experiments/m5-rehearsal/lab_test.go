package rehearsal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const daemonPin = "86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f"
const cliPin = "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"
const agentName = "id/rehearsal-agent"
const landlordName = "id/rehearsal-landlord"

type process struct {
	role    string
	cmd     *exec.Cmd
	log     *os.File
	done    chan error
	stopped bool
}
type lab struct {
	canonical                                                bool
	peers                                                    map[string]*canonicalNode
	signerRead, bookingRead                                  su.Route
	bookingDir, minerP2P                                     string
	verifierPaused                                           bool
	t                                                        *testing.T
	root, private, public, repo, cli, conf, nodeDir, address string
	read, broadcast, payment, paymentIssuer                  su.Route
	bins                                                     map[string]string
	processes                                                []*process
	pids                                                     []int
	secrets                                                  [][]byte
	evidence                                                 map[string]any
	responses                                                bool
	modelConfigPath                                          string
}

func encoded(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func checked(t *testing.T, e error, code string) {
	t.Helper()
	if e != nil {
		t.Fatal(code)
	}
}
func (l *lab) dir(name string) string {
	l.t.Helper()
	p := filepath.Join(l.private, name)
	checked(l.t, os.MkdirAll(p, 0700), "fixture directory")
	return p
}
func (l *lab) write(path string, b []byte, mode os.FileMode) {
	l.t.Helper()
	checked(l.t, os.WriteFile(path, b, mode), "fixture write")
}
func (l *lab) json(name string, v any, mode os.FileMode) string {
	p := filepath.Join(l.private, name)
	l.write(p, encoded(v), mode)
	return p
}
func (l *lab) secret(b []byte) {
	l.secrets = append(l.secrets, append([]byte(nil), b...), []byte(hex.EncodeToString(b)), []byte(base64.StdEncoding.EncodeToString(b)))
}
func (l *lab) key(name string, binary bool) *nostr.PrivKey {
	k, e := nostr.GeneratePrivKey()
	checked(l.t, e, "fixture key")
	l.secret(k.Bytes())
	b := k.Bytes()
	if !binary {
		b = []byte(hex.EncodeToString(b))
	}
	l.write(filepath.Join(l.private, name), b, 0600)
	return k
}
func (l *lab) command(role, path string, args ...string) ([]byte, int) {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	c.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	checked(l.t, c.Start(), "command start: "+role)
	l.pids = append(l.pids, c.Process.Pid)
	e := c.Wait()
	if ctx.Err() != nil {
		l.t.Fatal("command timeout: " + role)
	}
	code := 0
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			code = x.ExitCode()
		} else {
			l.t.Fatal("command wait: " + role)
		}
	}
	return out.Bytes(), code
}
func (l *lab) spawn(role string, args ...string) *process {
	l.t.Helper()
	log, e := os.OpenFile(filepath.Join(l.private, role+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	checked(l.t, e, "process log")
	p := &process{role: role, cmd: exec.Command(l.bins[role], args...), log: log, done: make(chan error, 1)}
	p.cmd.Stdout = log
	p.cmd.Stderr = log
	checked(l.t, p.cmd.Start(), "process start: "+role)
	l.pids = append(l.pids, p.cmd.Process.Pid)
	l.processes = append(l.processes, p)
	go func() { p.done <- p.cmd.Wait() }()
	return p
}
func (l *lab) stop(p *process) {
	if p.stopped {
		return
	}
	p.stopped = true
	select {
	case <-p.done:
	default:
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case <-p.done:
		case <-time.After(8 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
			l.t.Error("forced process stop: " + p.role)
		}
	}
	_ = p.log.Close()
}
func (l *lab) await(code string, f func() bool) {
	l.t.Helper()
	end := time.Now().Add(30 * time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatal("timeout: " + code)
}
func address(t *testing.T) string {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	checked(t, e, "fixture port")
	defer l.Close()
	return l.Addr().String()
}
func (l *lab) rpc(wallet, method string, args ...any) json.RawMessage {
	l.t.Helper()
	argv := []string{"-regtest", "-datadir=" + l.nodeDir, "-conf=" + l.conf}
	if wallet != "" {
		argv = append(argv, "-rpcwallet="+wallet)
	}
	argv = append(argv, method)
	for _, a := range args {
		if s, ok := a.(string); ok {
			argv = append(argv, s)
		} else {
			argv = append(argv, string(encoded(a)))
		}
	}
	b, code := l.command("Core "+method, l.cli, argv...)
	if code != 0 {
		l.t.Fatal("Core RPC refused: " + method)
	}
	if !json.Valid(b) {
		b = encoded(strings.TrimSpace(string(b)))
	}
	return b
}
func str(t *testing.T, b []byte) string {
	var s string
	checked(t, json.Unmarshal(b, &s), "JSON string")
	return s
}
func (l *lab) mine(n int) {
	if l.canonical {
		l.syncMempools()
	}
	l.rpc("", "generatetoaddress", n, l.address)
	if l.canonical {
		l.syncTips()
	}
}
func leaked(b []byte, secrets [][]byte) bool {
	for _, s := range secrets {
		if len(s) >= 16 && bytes.Contains(b, s) {
			return true
		}
	}
	return false
}

// The scanner catches a known secret and its encodings beside a public control.
// It does not claim to discover unknown secrets or inspect unrecorded streams.
func TestEvidenceScanner(t *testing.T) {
	s := []byte("canary-only-never-a-real-secret")
	l := &lab{}
	l.secret(s)
	for _, b := range [][]byte{s, []byte(hex.EncodeToString(s)), []byte(base64.StdEncoding.EncodeToString(s))} {
		if !leaked(b, l.secrets) {
			t.Fatal("secret canary missed")
		}
	}
	if leaked([]byte("public stage passed"), l.secrets) {
		t.Fatal("public control refused")
	}
}
func newLab(t *testing.T) *lab {
	t.Helper()
	if os.Getenv("IT1_REGTEST") != "1" {
		t.Skip("requires explicit IT1_REGTEST=1 and pinned Core")
	}
	if runtime.GOOS != "darwin" {
		t.Fatal("this rehearsal records the Darwin composition boundary")
	}
	productBase := os.Getenv("IT1_PRODUCT_HEAD")
	headBytes, headErr := hex.DecodeString(productBase)
	if headErr != nil || len(headBytes) != 20 || hex.EncodeToString(headBytes) != productBase {
		t.Fatal("exact signed IT1_PRODUCT_HEAD required")
	}
	root := os.Getenv("IT1_RUN_ROOT")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("new absolute run root required")
	}
	checked(t, os.Mkdir(root, 0700), "fresh run root")
	repo, e := filepath.Abs("../..")
	checked(t, e, "repo path")
	l := &lab{t: t, root: root, private: filepath.Join(root, "private"), public: filepath.Join(root, "public"), repo: repo, cli: os.Getenv("IT1_CORE_CLI"), bins: map[string]string{}, evidence: map[string]any{"product_base": productBase, "outcome": "incomplete", "full_scenario": "not_run"}}
	checked(t, os.Mkdir(l.private, 0700), "private root")
	checked(t, os.Mkdir(l.public, 0700), "public root")
	t.Cleanup(func() {
		for i := len(l.processes) - 1; i >= 0; i-- {
			l.stop(l.processes[i])
		}
		clean := true
		walkErr := filepath.WalkDir(l.private, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if !d.IsDir() && strings.HasSuffix(p, ".log") {
				b, e := os.ReadFile(p)
				if e != nil || leaked(b, l.secrets) {
					clean = false
				}
			}
			return nil
		})
		if walkErr != nil {
			clean = false
		}
		l.evidence["known_secret_log_scan"] = clean
		if !clean {
			t.Error("known secret appeared in private process log; contents withheld")
		}
		var audit []map[string]any
		seen := map[int]bool{}
		for _, pid := range l.pids {
			if seen[pid] {
				continue
			}
			seen[pid] = true
			gone := syscall.Kill(pid, 0) == syscall.ESRCH
			audit = append(audit, map[string]any{"pid": pid, "absent": gone})
			if !gone {
				t.Error("recorded direct process remains present")
			}
		}
		l.evidence["direct_processes"] = audit
		l.evidence["descendants_inventoried"] = false
		if t.Failed() {
			l.evidence["outcome"] = "FAIL"
			l.evidence["full_scenario"] = "incomplete; see last recorded stage and test failure"
		}
		b := encoded(l.evidence)
		if leaked(b, l.secrets) {
			t.Error("public evidence secret scan refused")
			return
		}
		l.write(filepath.Join(l.public, "result.json"), b, 0600)
	})
	for _, entry := range []struct{ p, pin string }{{os.Getenv("IT1_CORE_DAEMON"), daemonPin}, {l.cli, cliPin}} {
		b, e := os.ReadFile(entry.p)
		if e != nil || rental.Hash(b) != entry.pin {
			t.Fatal("Core binary pin")
		}
	}
	l.evidence["core_pins"] = map[string]string{"daemon": daemonPin, "cli": cliPin}
	// The exact task head must be clean on every exercised product and harness
	// path. It contains the payload change atop landed dependencies, not glue.
	products := []string{"experiments/m5-host-smoke", "experiments/m5-rehearsal", "experiments/station-payload", "experiments/relay", "experiments/model-proxy", "deploy", "experiments/rental-booking", "experiments/rental-gateway", "experiments/rental", "experiments/single-use", "experiments/signer-service", "experiments/grant-store", "experiments/station-lifecycle", "experiments/payment-chain", "experiments/sealwatch"}
	head, code := l.command("product head", "git", "-C", repo, "rev-parse", "HEAD")
	if code != 0 || strings.TrimSpace(string(head)) != productBase {
		t.Fatal("checkout is not requested exact head")
	}
	args := append([]string{"-C", repo, "diff", "--exit-code", productBase, "--"}, products...)
	_, code = l.command("product source equality", "git", args...)
	if code != 0 {
		t.Fatal("product source differs from pinned base")
	}
	args = append([]string{"-C", repo, "ls-files", "--others", "--exclude-standard", "--"}, products...)
	foreign, code := l.command("untracked product source", "git", args...)
	if code != 0 || len(bytes.TrimSpace(foreign)) != 0 {
		t.Fatal("untracked product source")
	}
	binDir := l.dir("bin")
	var builds []map[string]string
	for _, v := range []struct{ role, module, pkg string }{{"booking", "rental-booking", "rental-booking"}, {"relay", "relay", "swarma-relay"}, {"store", "grant-store", "grant-store"}, {"signer", "signer-service", "swarma-signer"}, {"gateway", "rental-gateway", "gateway"}, {"manager", "station-lifecycle", "station-manager"}, {"payload", "station-payload", "station-payload"}} {
		path := filepath.Join(binDir, v.role)
		tag := ""
		if v.role == "manager" {
			tag = "slotdfake"
		}
		_, code := l.command("build "+v.role, "go", "-C", filepath.Join(repo, "experiments", v.module), "build", "-tags", tag, "-race", "-trimpath", "-buildvcs=false", "-o", path, "./cmd/"+v.pkg)
		if code != 0 {
			t.Fatal("native build failed: " + v.role)
		}
		l.bins[v.role] = path
		b, e := os.ReadFile(path)
		checked(t, e, "binary read")
		builds = append(builds, map[string]string{"role": v.role, "sha256": rental.Hash(b)})
	}
	l.evidence["native_builds"] = builds
	t.Log("seven native product CLIs built from pinned source")
	return l
}
func (l *lab) startCore(agent, issuer string) {
	l.nodeDir = l.dir("node")
	port := strings.Split(address(l.t), ":")[1]
	var auth strings.Builder
	for _, entry := range []struct {
		name, methods string
		dest          *su.Route
	}{{"w3-observer", "getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock", &l.read}, {"sg1-broadcaster", "sendrawtransaction", &l.broadcast}, {"payment-observer", "getnetworkinfo,getblockchaininfo,getblockhash,getblockheader,getrawtransaction,getrawmempool,getblock", &l.payment}, {"payment-issuer", "getnetworkinfo,getblockchaininfo,getblockhash,getblockheader,getrawtransaction,getrawmempool,getblock,gettxout", &l.paymentIssuer}} {
		b := make([]byte, 32)
		_, e := rand.Read(b)
		checked(l.t, e, "RPC fixture random")
		pass := hex.EncodeToString(b)
		l.secret([]byte(pass))
		salt := hex.EncodeToString(b[:8])
		mac := hmac.New(sha256.New, []byte(salt))
		mac.Write([]byte(pass))
		fmt.Fprintf(&auth, "rpcauth=%s:%s$%x\nrpcwhitelist=%s:%s\n", entry.name, salt, mac.Sum(nil), entry.name, entry.methods)
		var n int
		fmt.Sscan(port, &n)
		*entry.dest = su.Route{Host: "127.0.0.1", Port: n, Username: entry.name, Password: pass}
	}
	l.conf = filepath.Join(l.nodeDir, "namecoin.conf")
	conf := "server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\n" + auth.String() + "[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=" + port + "\n"
	if l.canonical {
		l.minerP2P = address(l.t)
		conf = strings.Replace(conf, "listen=0\n", "listen=1\n", 1)
		conf = strings.Replace(conf, "networkactive=0\n", "networkactive=1\n", 1)
		conf += "connect=0\nbind=" + l.minerP2P + "\nport=" + strings.Split(l.minerP2P, ":")[1] + "\n"
	}
	l.write(l.conf, []byte(conf), 0600)
	l.bins["node"] = os.Getenv("IT1_CORE_DAEMON")
	l.spawn("node", "-regtest", "-datadir="+l.nodeDir, "-conf="+l.conf)
	n, e := su.NewRPC(l.read)
	checked(l.t, e, "observer constructor")
	l.await("Core readiness", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, e := n.Call(ctx, "getblockchaininfo")
		return e == nil
	})
	cookie, e := os.ReadFile(filepath.Join(l.nodeDir, "regtest", ".cookie"))
	checked(l.t, e, "fixture cookie scan registration")
	l.secret(bytes.TrimSpace(cookie))
	l.rpc("", "createwallet", "rehearsal", false, false, "", false, false)
	l.address = str(l.t, l.rpc("rehearsal", "getnewaddress", "", "legacy"))
	l.mine(101)
	av, e := rental.AgentBindingValue(rental.AgentBinding{Nostr: agent, Landlord: landlordName})
	checked(l.t, e, "agent binding")
	lv, e := rental.LandlordValue(rental.LandlordBinding{Grant: issuer})
	checked(l.t, e, "landlord binding")
	reserved := map[string][]string{}
	for _, name := range []string{agentName, landlordName} {
		var r []string
		checked(l.t, json.Unmarshal(l.rpc("rehearsal", "name_new", name), &r), "name reservation")
		reserved[name] = r
	}
	l.mine(12)
	for _, v := range []struct{ name, value string }{{agentName, av}, {landlordName, lv}} {
		r := reserved[v.name]
		l.rpc("rehearsal", "name_firstupdate", v.name, r[1], r[0], v.value)
	}
	l.mine(1)
	if l.canonical {
		l.startObservers()
	}
	l.evidence["core_names_registered"] = true
	l.t.Log("genuine Core ready; agent and landlord names registered")
}
