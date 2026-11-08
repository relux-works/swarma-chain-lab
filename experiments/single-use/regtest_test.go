package singleuse

import (
	"bytes"
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
)

type coreLab struct {
	t                                                                     *testing.T
	root, public, private, cli, daemon, executor, signer, conf, routePath string
	issuerAddress, ownerName, issuerKey, granteeKey, sealAddress, payment string
	route                                                                 Route
	certificate, request, enrollment                                      []byte
	template                                                              Policy
	rows                                                                  []map[string]any
	node                                                                  *exec.Cmd
	next                                                                  int
}

func (l *coreLab) save(name string, v any) {
	l.t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		l.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(l.public, name), append(b, '\n'), 0600); e != nil {
		l.t.Fatal(e)
	}
}
func (l *coreLab) rpc(wallet, method string, args ...any) json.RawMessage {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	argv := []string{"-regtest", "-datadir=" + l.private, "-conf=" + l.conf}
	if wallet != "" {
		argv = append(argv, "-rpcwallet="+wallet)
	}
	argv = append(argv, method)
	for _, arg := range args {
		if s, ok := arg.(string); ok {
			argv = append(argv, s)
		} else {
			b, e := json.Marshal(arg)
			if e != nil {
				l.t.Fatal(e)
			}
			argv = append(argv, string(b))
		}
	}
	cmd := exec.CommandContext(ctx, l.cli, argv...)
	raw, e := cmd.Output()
	exit := 0
	if e != nil {
		exit = 1
	}
	l.rows = append(l.rows, map[string]any{"kind": "core-rpc", "argv": append([]string{l.cli}, argv...), "exit_code": exit})
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			l.t.Fatalf("Core %s exit%d: %s", method, x.ExitCode(), x.Stderr)
		}
		l.t.Fatal(e)
	}
	if !json.Valid(raw) {
		raw, _ = json.Marshal(strings.TrimSpace(string(raw)))
	}
	return raw
}
func textValue(t *testing.T, b json.RawMessage) string {
	t.Helper()
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func object(t *testing.T, b json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if e := json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	return m
}
func (l *coreLab) mine(n int) { l.rpc("", "generatetoaddress", n, l.issuerAddress) }
func newCoreLab(t *testing.T) *coreLab {
	t.Helper()
	if os.Getenv("W3_REGTEST") != "1" {
		t.Skip("genuine Core integration requires W3_REGTEST=1 and explicit fixture paths")
	}
	root := os.Getenv("W3_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute new W3_RUN_ROOT required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	l := &coreLab{t: t, root: root, public: filepath.Join(root, "public"), private: filepath.Join(root, "private"), cli: os.Getenv("W3_CORE_CLI"), daemon: os.Getenv("W3_CORE_DAEMON"), executor: os.Getenv("W3_EXECUTOR"), signer: os.Getenv("W3_LAB_SIGNER"), ownerName: "id/w3-single-use-issuer"}
	for _, dir := range []string{l.public, l.private} {
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for path, want := range map[string]string{l.cli: "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d", l.daemon: "86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f"} {
		b, e := os.ReadFile(path)
		if e != nil || Hash(b) != want {
			t.Fatal("Core binary pin")
		}
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	random := make([]byte, 32)
	if _, e = rand.Read(random); e != nil {
		t.Fatal(e)
	}
	password := hex.EncodeToString(random)
	salt := hex.EncodeToString(random[:8])
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(password))
	l.route = Route{"127.0.0.1", port, "w3-observer", password}
	l.routePath = filepath.Join(l.private, "observer-route.json")
	route, _ := json.Marshal(l.route)
	if e = os.WriteFile(l.routePath, route, 0600); e != nil {
		t.Fatal(e)
	}
	l.conf = filepath.Join(l.private, "namecoin.conf")
	methods := []string{"getblockchaininfo", "getblockhash", "getblockheader", "getrawtransaction", "gettxout", "name_show", "getrawmempool", "getblock"}
	config := fmt.Sprintf("server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\nrpcauth=w3-observer:%s$%x\nrpcwhitelist=w3-observer:%s\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", salt, mac.Sum(nil), strings.Join(methods, ","), port)
	if e = os.WriteFile(l.conf, []byte(config), 0600); e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(l.private, "node.log"))
	if e != nil {
		t.Fatal(e)
	}
	l.node = exec.Command(l.daemon, "-regtest", "-datadir="+l.private, "-conf="+l.conf)
	l.node.Stdout = log
	l.node.Stderr = log
	if e = l.node.Start(); e != nil {
		t.Fatal(e)
	}
	pid := l.node.Process.Pid
	t.Cleanup(func() {
		_ = l.node.Process.Signal(os.Interrupt)
		_ = l.node.Wait()
		_ = log.Close()
		l.save("commands.json", l.rows)
		l.save("node-lifecycle.json", map[string]any{"pid": pid, "stopped": true, "regtest": true, "networkactive": false, "acceptnonstdtxn": true, "private_keys_exported": false})
	})
	if e = os.WriteFile(filepath.Join(l.root, "node.pid"), []byte(fmt.Sprintf("%d\n", pid)), 0600); e != nil {
		t.Fatal(e)
	}
	ready := false
	for i := 0; i < 150; i++ {
		cmd := exec.Command(l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "getblockchaininfo")
		if cmd.Run() == nil {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Core startup deadline")
	}
	keys := []string{}
	for _, wallet := range []string{"issuer", "grantee"} {
		l.rpc("", "createwallet", wallet, false, false, "", false, false)
		address := textValue(t, l.rpc(wallet, "getnewaddress", "", "legacy"))
		info := object(t, l.rpc(wallet, "getaddressinfo", address))
		keys = append(keys, textValue(t, info["pubkey"]))
		if wallet == "issuer" {
			l.issuerAddress = address
			l.payment = textValue(t, info["scriptPubKey"])
		}
	}
	l.issuerKey, l.granteeKey = keys[0], keys[1]
	for _, wallet := range []string{"issuer", "grantee"} {
		m := object(t, l.rpc(wallet, "addmultisigaddress", 1, keys, "w3", "legacy"))
		l.sealAddress = textValue(t, m["address"])
	}
	l.mine(101)
	var reservation []string
	if e = json.Unmarshal(l.rpc("issuer", "name_new", l.ownerName), &reservation); e != nil {
		t.Fatal(e)
	}
	l.mine(12)
	l.rpc("issuer", "name_firstupdate", l.ownerName, reservation[1], reservation[0], "{}", map[string]string{"destAddress": l.issuerAddress})
	l.mine(1)
	fixture := os.Getenv("W3_PUBLIC_FIXTURE")
	for name, dst := range map[string]*[]byte{"certificate.json": &l.certificate, "request.json": &l.request, "enrollment.json": &l.enrollment} {
		b, e := os.ReadFile(filepath.Join(fixture, name))
		if e != nil {
			t.Fatal(e)
		}
		*dst = b
		if e = os.WriteFile(filepath.Join(l.public, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	var enrollment map[string]json.RawMessage
	if e = json.Unmarshal(l.enrollment, &enrollment); e != nil {
		t.Fatal(e)
	}
	verifier := os.Getenv("W3_PUBLIC_VERIFIER")
	b, e := os.ReadFile(verifier)
	if e != nil {
		t.Fatal(e)
	}
	_, script, e := SealScript(l.issuerKey, l.granteeKey)
	if e != nil {
		t.Fatal(e)
	}
	l.template = Policy{Network: "regtest", Genesis: RegtestGenesis, SealScript: hex.EncodeToString(script), IssuerKey: l.issuerKey, GranteeKey: l.granteeKey, OwnerName: l.ownerName, OwnerPaymentScript: l.payment, OwnerSPKI: textValue(t, enrollment["owner_spki"]), RequesterSPKI: textValue(t, enrollment["requester_spki"]), CertificateHash: Hash(l.certificate), Enrollment: l.enrollment, VerifierPath: verifier, VerifierHash: Hash(b)}
	return l
}

func (l *coreLab) send(wallet, raw, mode string, mine bool) string {
	l.t.Helper()
	signed := object(l.t, l.rpc(wallet, "signrawtransactionwithwallet", raw, nil, mode))
	if string(signed["complete"]) != "true" {
		l.t.Fatal("incomplete wallet signature")
	}
	signedHex := textValue(l.t, signed["hex"])
	bytes, err := hex.DecodeString(signedHex)
	if err != nil {
		l.t.Fatal(err)
	}
	transaction, err := DecodeTransaction(bytes)
	if err != nil {
		l.t.Fatal(err)
	}
	var burn int64
	for _, out := range transaction.Outputs {
		if len(out.Script) > 0 && out.Script[0] == 0x6a {
			burn += out.Value
		}
	}
	if burn > 1 {
		l.t.Fatal("regtest burn control exceeds one satoshi")
	}
	// Explicitly admit only the one-satoshi negative control; Core's default
	// maxburnamount=0 would reject it before the executor is exercised.
	txid := textValue(l.t, l.rpc("", "sendrawtransaction", signedHex, Coins(10000000), Coins(burn)))
	if mine {
		l.mine(1)
	}
	return txid
}
func (l *coreLab) newPolicy() Policy {
	l.t.Helper()
	l.next++
	p := l.template
	funding := textValue(l.t, l.rpc("issuer", "sendtoaddress", l.sealAddress, Coins(1000000)))
	l.mine(1)
	var tx rpcTx
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", funding, true), &tx); e != nil {
		l.t.Fatal(e)
	}
	found := false
	for _, v := range tx.Vout {
		if v.Script.Hex == p.SealScript && int64(v.Value) == 1000000 {
			p.Seal = Point{funding, v.N}
			found = true
		}
	}
	if !found {
		l.t.Fatal("funded seal missing")
	}
	l.rpc("issuer", "lockunspent", false, []Point{p.Seal})
	l.anchor(&p, true)
	return p
}
func (l *coreLab) anchor(p *Policy, mine bool) {
	current := object(l.t, l.rpc("", "name_show", l.ownerName))
	var n uint32
	_ = json.Unmarshal(current["vout"], &n)
	value, _ := json.Marshal(map[string]any{"swarma": map[string]any{"keyvault_owner_spki": p.OwnerSPKI, "keyvault_certificate_sha256": p.CertificateHash, "keyvault_seal": p.Seal}})
	raw := textValue(l.t, l.rpc("", "createrawtransaction", []Point{{textValue(l.t, current["txid"]), n}}, []map[string]any{{l.issuerAddress: Coins(1000000)}, {"data": p.CertificateHash}}))
	named := object(l.t, l.rpc("", "namerawtransaction", raw, 0, map[string]any{"op": "name_update", "name": l.ownerName, "value": string(value)}))
	funded := object(l.t, l.rpc("issuer", "fundrawtransaction", textValue(l.t, named["hex"]), map[string]any{"fee_rate": 200}))
	id := l.send("issuer", textValue(l.t, funded["hex"]), "ALL", mine)
	var view rpcTx
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &view); e != nil {
		l.t.Fatal(e)
	}
	p.Anchor.TxID = id
	p.Anchor.Block = view.Block
	for _, v := range view.Vout {
		if v.Script.Name != nil && v.Script.Name.Name == l.ownerName {
			p.Anchor.Vout = v.N
		}
	}
	if view.Block != "" {
		var h header
		if e := json.Unmarshal(l.rpc("", "getblockheader", view.Block), &h); e != nil {
			l.t.Fatal(e)
		}
		p.Anchor.Height = h.Height
	}
}
func (l *coreLab) use(p Policy, role, mode string, mutate func(*Transaction), mine bool) string {
	raw := textValue(l.t, l.rpc("", "createrawtransaction", []Point{p.Seal}, []map[string]any{{l.issuerAddress: Coins(940000)}, {"data": Hash(l.request)}}))
	if mutate != nil {
		b, _ := hex.DecodeString(raw)
		tx, e := DecodeTransaction(b)
		if e != nil {
			l.t.Fatal(e)
		}
		mutate(tx)
		raw = hex.EncodeToString(tx.Bytes())
	}
	return l.send(role, raw, mode, mine)
}
func (l *coreLab) state(p Policy, label string) Policy {
	l.t.Helper()
	p.StateDir = filepath.Join(l.private, fmt.Sprintf("state-%03d-%s", l.next, label))
	if e := os.Mkdir(p.StateDir, 0700); e != nil {
		l.t.Fatal(e)
	}
	return p
}
func (l *coreLab) invoke(p Policy, request []byte, label string, extra ...string) (Receipt, int) {
	l.t.Helper()
	policyPath := filepath.Join(l.public, label+"-policy.json")
	b, _ := json.Marshal(p)
	if e := os.WriteFile(policyPath, b, 0600); e != nil {
		l.t.Fatal(e)
	}
	certPath := filepath.Join(l.private, "certificate-exact.json")
	requestPath := filepath.Join(l.public, label+"-request.json")
	if e := os.WriteFile(certPath, l.certificate, 0600); e != nil {
		l.t.Fatal(e)
	}
	if e := os.WriteFile(requestPath, request, 0600); e != nil {
		l.t.Fatal(e)
	}
	args := []string{"--policy", policyPath, "--route", l.routePath, "--certificate", certPath, "--request", requestPath}
	args = append(args, extra...)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.executor, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, e := cmd.Output()
	exit := 0
	if e != nil {
		if ee, ok := e.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			l.t.Fatal(e)
		}
	}
	var receipt Receipt
	if e = json.Unmarshal(out, &receipt); e != nil {
		l.t.Fatalf("%s exit%d missing receipt: %s %s", label, exit, out, stderr.Bytes())
	}
	l.save(label+"-receipt.json", receipt)
	l.rows = append(l.rows, map[string]any{"kind": "executor", "label": label, "argv": append([]string{l.executor}, args...), "exit_code": exit, "receipt": receipt})
	return receipt, exit
}
func effectCount(t *testing.T, p Policy) int {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(p.StateDir, "effects.jsonl"))
	if os.IsNotExist(e) {
		return 0
	}
	if e != nil {
		t.Fatal(e)
	}
	return bytes.Count(b, []byte{'\n'})
}
func journalCount(t *testing.T, p Policy) int {
	t.Helper()
	v, e := filepath.Glob(filepath.Join(p.StateDir, "journal-*.json"))
	if e != nil {
		t.Fatal(e)
	}
	return len(v)
}

// This first integration proves the actual P256/anchor/Core-signature/journal
// composition, pending with no reservation, one confirmation, and replay.
func TestGenuineCoreSmoke(t *testing.T) {
	l := newCoreLab(t)
	p := l.state(l.newPolicy(), "smoke")
	l.use(p, "grantee", "ALL", nil, false)
	r, exit := l.invoke(p, l.request, "pending")
	if exit != 0 || r.Status != "pending" || effectCount(t, p) != 0 || journalCount(t, p) != 0 {
		t.Fatalf("pending: %+v exit%d", r, exit)
	}
	l.mine(1)
	r, exit = l.invoke(p, l.request, "confirmed")
	if exit != 0 || r.Status != "executed" || effectCount(t, p) != 1 {
		t.Fatalf("confirmed: %+v exit%d", r, exit)
	}
	r, exit = l.invoke(p, l.request, "replay")
	if exit != 0 || r.Status != "already-executed" || effectCount(t, p) != 1 {
		t.Fatalf("replay: %+v exit%d", r, exit)
	}
	l.save("result.json", map[string]any{"status": "PASS", "scope": "smoke only", "negative_controls": 2, "effect_count": 1})
}
