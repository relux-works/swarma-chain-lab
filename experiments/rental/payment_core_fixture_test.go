package rental

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pc "relux.works/swarma-chain-lab/experiments/payment-chain"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type paymentCoreLab struct {
	t                                               *testing.T
	root, private, public, cli, daemon, conf, miner string
	profile                                         pc.Profile
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
	if os.Getenv("P1_REGTEST") != "1" {
		t.Skip("set P1_REGTEST=1 with explicit isolated binary/root paths")
	}
	root := os.Getenv("P1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute P1_RUN_ROOT required")
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
	l.cli = os.Getenv("P1_" + prefix + "_CLI")
	l.daemon = os.Getenv("P1_" + prefix + "_DAEMON")
	pins := map[string][2]string{"btc": {"58f9e3b5b8cf0cecd268cc6bf02993f3244e1a93fe8d67949ced6b52c2fdd9fb", "5310684b6028bdc48e2155645408f02bd2b46e0ee0799317168e74ce9b823aba"}, "ltc": {"0a97c3edbdfec36c73bf8995fe6c8a1c2d9133e1c7e1cf2790392e4b1bef52ef", "7435e2f05c736b3e196912fbe11b4b00ed6ef1e970928a43b07604e239575c61"}, "nmc": {"86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f", "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"}}
	for i, path := range []string{l.daemon, l.cli} {
		b, e := os.ReadFile(path)
		if e != nil || Hash(b) != pins[coin][i] {
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
	l.read, e = pc.NewRPC(pc.Route{Host: "127.0.0.1", Port: port, Username: "payment-observer", Password: password})
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

// Restart only this fixture's recorded process; persistmempool=0 and disabled
// wallet broadcasting make disappearance deterministic without a test RPC shim.
func (l *paymentCoreLab) restart() {
	l.t.Helper()
	l.stop()
	var e error
	l.log, e = os.OpenFile(l.private+"/node.log", os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		l.t.Fatal(e)
	}
	l.node = exec.Command(l.daemon, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "-persistmempool=0")
	l.node.Stdout = l.log
	l.node.Stderr = l.log
	if e = l.node.Start(); e != nil {
		l.node = nil
		l.t.Fatal(e)
	}
	l.pids = append(l.pids, l.node.Process.Pid)
	l.save("started", map[string]any{"pids": l.pids})
	for i := 0; i < 100; i++ {
		ctx, c := context.WithTimeout(context.Background(), time.Second)
		e = exec.CommandContext(ctx, l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "getblockchaininfo").Run()
		c()
		if e == nil {
			var wallets []string
			if err := json.Unmarshal(l.rpc("", "listwallets"), &wallets); err != nil {
				l.t.Fatal(err)
			}
			loaded := false
			for _, wallet := range wallets {
				loaded = loaded || wallet == "lab"
			}
			if !loaded {
				l.rpc("", "loadwallet", "lab")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatal("Core restart timeout; private log retained")
}

// Build real unrelated noise with 17 inputs, exceeding the legacy planner's
// 16-input cap. It remains a valid ordinary transaction for the payment watcher.
func (l *paymentCoreLab) noise() string {
	l.t.Helper()
	l.mine(20)
	var coins []struct {
		TxID   string      `json:"txid"`
		Vout   uint32      `json:"vout"`
		Amount json.Number `json:"amount"`
	}
	if e := json.Unmarshal(l.rpc("lab", "listunspent", 101), &coins); e != nil {
		l.t.Fatal(e)
	}
	if len(coins) < 17 {
		l.t.Fatal("insufficient mature inputs for noise control")
	}
	inputs := []any{}
	var total int64
	for _, c := range coins[:17] {
		inputs = append(inputs, map[string]any{"txid": c.TxID, "vout": c.Vout})
		v, ok := new(big.Rat).SetString(string(c.Amount))
		if !ok {
			l.t.Fatal("noise amount")
		}
		v.Mul(v, big.NewRat(100000000, 1))
		if !v.IsInt() || !v.Num().IsInt64() {
			l.t.Fatal("noise amount precision")
		}
		total += v.Num().Int64()
	}
	raw := textValue(l.t, l.rpc("", "createrawtransaction", inputs, map[string]any{l.miner: json.Number(fmt.Sprintf("%d.%08d", (total-1000000)/100000000, (total-1000000)%100000000))}))
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if e := json.Unmarshal(l.rpc("lab", "signrawtransactionwithwallet", raw), &signed); e != nil || !signed.Complete {
		l.t.Fatal("noise signing", e)
	}
	id := textValue(l.t, l.rpc("", "sendrawtransaction", signed.Hex))
	var view struct {
		Vin []struct {
			Witness []string `json:"txinwitness"`
		} `json:"vin"`
	}
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &view); e != nil || len(view.Vin) != 17 {
		l.t.Fatal("noise input count", e)
	}
	witness := false
	for _, in := range view.Vin {
		witness = witness || len(in.Witness) > 0
	}
	if l.profile.Coin != "nmc" && !witness {
		l.t.Fatal("BTC/LTC noise did not exercise witness")
	}
	l.save("noise", map[string]any{"txid": id, "inputs": len(view.Vin), "witness": witness})
	return id
}

// Replace a non-signaling transaction through the node's actual full-RBF policy,
// rather than wallet bumpfee (which itself requires wallet replaceability).
func (l *paymentCoreLab) replaceNonSignaling(id, keepScript string) string {
	raw := l.nonSignalingReplacement(id, keepScript, false)
	replacement := textValue(l.t, l.rpc("", "sendrawtransaction", raw))
	if replacement == id {
		l.t.Fatal("full-RBF did not replace")
	}
	return replacement
}
func (l *paymentCoreLab) nonSignalingReplacement(id, keepScript string, redirect bool) string {
	l.t.Helper()
	var original struct {
		Hex string `json:"hex"`
	}
	if e := json.Unmarshal(l.rpc("lab", "gettransaction", id), &original); e != nil {
		l.t.Fatal(e)
	}
	raw, e := hex.DecodeString(original.Hex)
	if e != nil {
		l.t.Fatal(e)
	}
	var tx wire.MsgTx
	if e = tx.Deserialize(bytes.NewReader(raw)); e != nil {
		l.t.Fatal(e)
	}
	for _, in := range tx.TxIn {
		if in.Sequence < 0xfffffffe {
			l.t.Fatal("full-RBF original unexpectedly signaled")
		}
		in.SignatureScript = nil
		in.Witness = nil
	}
	changed := false
	for _, out := range tx.TxOut {
		if hex.EncodeToString(out.PkScript) != keepScript && out.Value > 200000 {
			out.Value -= 100000
			changed = true
			break
		}
	}
	if !changed {
		l.t.Fatal("full-RBF fixture lacks change")
	}
	if redirect {
		var address struct {
			Script string `json:"scriptPubKey"`
		}
		if e = json.Unmarshal(l.rpc("lab", "getaddressinfo", l.miner), &address); e != nil {
			l.t.Fatal(e)
		}
		script, e := hex.DecodeString(address.Script)
		if e != nil || len(script) == 0 {
			l.t.Fatal("miner redirect script", e)
		}
		for _, out := range tx.TxOut {
			if hex.EncodeToString(out.PkScript) == keepScript {
				out.PkScript = script
			}
		}
	}
	var buf bytes.Buffer
	if e = tx.Serialize(&buf); e != nil {
		l.t.Fatal(e)
	}
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if e = json.Unmarshal(l.rpc("lab", "signrawtransactionwithwallet", hex.EncodeToString(buf.Bytes())), &signed); e != nil || !signed.Complete {
		l.t.Fatal("full-RBF signing", e)
	}
	return signed.Hex
}
