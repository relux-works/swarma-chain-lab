// Fixture adapted from the repository P1 genuine-Core lab; no issuer code is copied.
package signerservice

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type paymentCoreLab struct {
	t                                               *testing.T
	root, private, public, cli, daemon, conf, miner string
	profile                                         pc.Profile
	readRoute                                       pc.Route
	node                                            *exec.Cmd
	log                                             *os.File
	read                                            su.Node
	issuer                                          su.Node
	commands                                        []string
	pids                                            []int
	stopped                                         []int
}

func textValue(t *testing.T, b json.RawMessage) string {
	t.Helper()
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func (l *paymentCoreLab) rpc(wallet, method string, args ...any) json.RawMessage {
	l.t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 60*time.Second)
	defer c()
	argv := []string{"-regtest", "-datadir=" + l.private, "-conf=" + l.conf}
	if wallet != "" {
		argv = append(argv, "-rpcwallet="+wallet)
	}
	argv = append(argv, method)
	for _, a := range args {
		if s, ok := a.(string); ok {
			argv = append(argv, s)
		} else {
			argv = append(argv, string(eventBytes(a)))
		}
	}
	cmd := exec.CommandContext(ctx, l.cli, argv...)
	raw, e := cmd.Output()
	l.commands = append(l.commands, method)
	if e != nil {
		if ctx.Err() != nil {
			l.t.Fatalf("Core %s: operation deadline", method)
		}
		if x, ok := e.(*exec.ExitError); ok {
			l.t.Fatalf("Core %s: %s", method, x.Stderr)
		}
		l.t.Fatalf("Core %s failed", method)
	}
	if !json.Valid(raw) {
		raw = eventBytes(strings.TrimSpace(string(raw)))
	}
	return raw
}
func (l *paymentCoreLab) save(name string, v any) {
	l.t.Helper()
	if e := os.WriteFile(filepath.Join(l.public, name+".json"), eventBytes(v), 0600); e != nil {
		l.t.Fatal(e)
	}
}
func (l *paymentCoreLab) stop() {
	if l.node == nil {
		return
	}
	pid := l.node.Process.Pid
	_ = l.node.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- l.node.Wait() }()
	var e error
	select {
	case e = <-done:
	case <-time.After(45 * time.Second):
		_ = l.node.Process.Kill()
		e = <-done
	}
	_ = l.log.Close()
	l.node = nil
	if e != nil {
		l.t.Errorf("Core clean stop: %v", e)
	} else {
		l.stopped = append(l.stopped, pid)
	}
}
func newPaymentCoreLab(t *testing.T, coin string) *paymentCoreLab {
	t.Helper()
	if os.Getenv("SG1_REGTEST") != "1" {
		t.Skip("set SG1_REGTEST=1 with explicit isolated binary/root paths")
	}
	root := os.Getenv("SG1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute SG1_RUN_ROOT required")
	}
	root = filepath.Join(root, coin)
	if e := os.MkdirAll(filepath.Dir(root), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	p, _ := pc.ForCoin(coin)
	l := &paymentCoreLab{t: t, root: root, private: root + "/private", public: root + "/public", profile: p}
	for _, d := range []string{l.private, l.public} {
		if e := os.Mkdir(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	prefix := strings.ToUpper(coin)
	l.cli = os.Getenv("SG1_" + prefix + "_CLI")
	l.daemon = os.Getenv("SG1_" + prefix + "_DAEMON")
	pins := map[string][2]string{"btc": {"58f9e3b5b8cf0cecd268cc6bf02993f3244e1a93fe8d67949ced6b52c2fdd9fb", "5310684b6028bdc48e2155645408f02bd2b46e0ee0799317168e74ce9b823aba"}, "ltc": {"0a97c3edbdfec36c73bf8995fe6c8a1c2d9133e1c7e1cf2790392e4b1bef52ef", "7435e2f05c736b3e196912fbe11b4b00ed6ef1e970928a43b07604e239575c61"}, "nmc": {"86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f", "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"}}
	for i, path := range []string{l.daemon, l.cli} {
		b, e := os.ReadFile(path)
		if e != nil || hash(b) != pins[coin][i] {
			t.Fatal("Core binary pin")
		}
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var entropy [32]byte
	if _, e = rand.Read(entropy[:]); e != nil {
		t.Fatal(e)
	}
	password := hex.EncodeToString(entropy[:])
	salt := hex.EncodeToString(entropy[:8])
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(password))
	var issuerEntropy [32]byte
	if _, e = rand.Read(issuerEntropy[:]); e != nil {
		t.Fatal(e)
	}
	issuerPassword := hex.EncodeToString(issuerEntropy[:])
	issuerSalt := hex.EncodeToString(issuerEntropy[:8])
	issuerMAC := hmac.New(sha256.New, []byte(issuerSalt))
	issuerMAC.Write([]byte(issuerPassword))
	conf := fmt.Sprintf("server=1\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=0\nprune=550\nfallbackfee=0.002\nwalletbroadcast=0\nrpcwhitelistdefault=0\nrpcauth=payment-observer:%s$%x\nrpcwhitelist=payment-observer:getnetworkinfo,getblockchaininfo,getblockhash,getblockheader,getblock,getrawtransaction,getrawmempool\nrpcauth=payment-issuer:%s$%x\nrpcwhitelist=payment-issuer:getnetworkinfo,getblockchaininfo,getblockhash,getblockheader,getblock,getrawtransaction,getrawmempool\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", salt, mac.Sum(nil), issuerSalt, issuerMAC.Sum(nil), port)

	if coin == "ltc" {
		conf = "mempoolreplacement=1\n" + conf
	}
	l.conf = l.private + "/test.conf"
	if e = os.WriteFile(l.conf, []byte(conf), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		l.stop()
		l.save("lifecycle", map[string]any{"pids": l.pids, "stopped_pids": l.stopped, "methods": l.commands, "regtest": true, "networkactive": false, "txindex": false, "prune": 550})
	})
	l.log, e = os.OpenFile(l.private+"/node.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	l.node = exec.Command(l.daemon, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "-persistmempool=0")
	l.node.Stdout = l.log
	l.node.Stderr = l.log
	if e = l.node.Start(); e != nil {
		l.node = nil
		t.Fatal(e)
	}
	l.pids = append(l.pids, l.node.Process.Pid)
	l.save("started", map[string]any{"pids": l.pids})
	ready := false
	for i := 0; i < 100; i++ {
		ctx, c := context.WithTimeout(context.Background(), time.Second)
		cmd := exec.CommandContext(ctx, l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "getblockchaininfo")
		e = cmd.Run()
		c()
		if e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Core startup timeout; private node.log retained")
	}
	l.readRoute = pc.Route{Host: "127.0.0.1", Port: port, Username: "payment-observer", Password: password}
	l.read, e = pc.NewRPC(l.readRoute)
	if e != nil {
		t.Fatal(e)
	}
	l.issuer, e = pc.NewIssuerRPC(pc.Route{Host: "127.0.0.1", Port: port, Username: "payment-issuer", Password: issuerPassword})
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("", "createwallet", "lab")
	l.miner = textValue(t, l.rpc("lab", "getnewaddress"))
	l.mine(110)
	l.save("network", json.RawMessage(l.rpc("", "getnetworkinfo")))
	l.save("chain", json.RawMessage(l.rpc("", "getblockchaininfo")))
	return l
}
func (l *paymentCoreLab) mine(n int) string {
	var hashes []string
	if e := json.Unmarshal(l.rpc("", "generatetoaddress", n, l.miner), &hashes); e != nil {
		l.t.Fatal(e)
	}
	return hashes[len(hashes)-1]
}
func (l *paymentCoreLab) pay(address string, atoms int64) string {
	return l.paySignaling(address, atoms, true)
}
func (l *paymentCoreLab) paySignaling(address string, atoms int64, signaling bool) string {
	id := textValue(l.t, l.rpc("lab", "sendtoaddress", address, json.Number(fmt.Sprintf("%d.%08d", atoms/100000000, atoms%100000000)), "", "", false, signaling))
	var tx struct {
		Hex string `json:"hex"`
	}
	if e := json.Unmarshal(l.rpc("lab", "gettransaction", id), &tx); e != nil {
		l.t.Fatal(e)
	}
	if got := textValue(l.t, l.rpc("", "sendrawtransaction", tx.Hex)); got != id {
		l.t.Fatal("txid")
	}
	return id
}
