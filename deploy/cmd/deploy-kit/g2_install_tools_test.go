package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/relux-works/swarma-chain-lab/deploy"
)

// Every key, password and salt in this file is a fixed TEST value or is drawn
// fresh into a test temporary directory; none is a real credential.

const (
	g2TestRegtestGenesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	g2TestRegtestChange  = "mh5CE8Nbj38iND267s4XnvhSmhDW7yWc6Q" // regtest P2PKH of hash160 0x11*20 (test value)
	g2TestMainChange     = "Mx8c8inbqPo27dnyg7QjBXe2dw1rCHULXZ" // Namecoin main P2PKH of hash160 0x11*20 (test value)
	// secp256k1 group order n.
	g2TestOrderN = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
)

// g2TestScalar returns the 32-byte big-endian encoding of k (k small).
func g2TestScalar(k uint32) []byte {
	b := make([]byte, 32)
	b[28], b[29], b[30], b[31] = byte(k>>24), byte(k>>16), byte(k>>8), byte(k)
	return b
}

// g2TestNMinus returns n-k as 32 bytes.
func g2TestNMinus(k uint32) []byte {
	var s, m secp256k1.ModNScalar
	m.SetInt(k).Negate()
	s.Set(&m)
	b := s.Bytes()
	return b[:]
}

func g2TestHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// g2TestXOnly derives x(k*G) from a 32-byte scalar.
func g2TestXOnly(t *testing.T, b []byte) string {
	t.Helper()
	var k secp256k1.ModNScalar
	if k.SetByteSlice(b) || k.IsZero() {
		t.Fatal("G2_KEYGEN_SETUP invalid test scalar")
	}
	return g2KeyXOnly(&k)
}

// g2TestGoodScalar is a fixed non-trivial TEST scalar (SHA-256 of a label).
func g2TestGoodScalar(label string) []byte {
	h := sha256.Sum256([]byte("g2-install-tools test scalar " + label))
	return h[:]
}

var g2KeyLine = regexp.MustCompile(`^G2_KEY_XONLY ([0-9a-f]{64})\n$`)

// Claim: with crypto/rand, g2-keygen writes a new file of EXACTLY 64
// lowercase hex characters (no newline) at mode 0600, or 0640 with -mode
// 0640, and prints only "G2_KEY_XONLY <x>" where x is x(scalar*G) of the
// written scalar; the private hex never appears on stdout.
func TestG2KeygenWritesLoaderFormat(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name string
		args []string
		mode os.FileMode
	}{{"default", nil, 0600}, {"0600", []string{"-mode", "0600"}, 0600}, {"0640", []string{"-mode", "0640"}, 0640}} {
		path := filepath.Join(dir, c.name+".key")
		var stdout bytes.Buffer
		if e := g2Keygen(append([]string{"-out", path}, c.args...), &stdout); e != nil {
			t.Fatal("G2_KEYGEN positive", c.name, e)
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		info, _ := os.Lstat(path)
		if len(raw) != 64 || !regexp.MustCompile(`^[0-9a-f]{64}$`).Match(raw) || bytes.ContainsAny(raw, "\r\n") || info.Mode().Perm() != c.mode || !info.Mode().IsRegular() {
			t.Fatalf("G2_KEYGEN_FORMAT %s: len=%d mode=%v", c.name, len(raw), info.Mode())
		}
		m := g2KeyLine.FindStringSubmatch(stdout.String())
		if m == nil || m[1] != g2TestXOnly(t, g2TestHex(t, string(raw))) {
			t.Fatalf("G2_KEYGEN_STDOUT %s: stdout is not exactly the x-only line of the written key", c.name)
		}
		if strings.Contains(stdout.String(), string(raw)) {
			t.Fatalf("G2_KEYGEN_LEAK %s: the private scalar is on stdout", c.name)
		}
	}
}

// Claim: g2-keygen refuses, writing nothing, an existing file (left
// unchanged), a dangling symlink at the path, a parent that is a symlink, a
// parent path with a symlink component, a relative or unclean path, a missing
// parent and a mode other than 0600/0640; the real-directory neighbour of
// each path is accepted.
func TestG2KeygenRefusals(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0700)
	existing := filepath.Join(real, "existing.key")
	os.WriteFile(existing, []byte("prior content"), 0600)
	os.Symlink(filepath.Join(real, "absent-target"), filepath.Join(real, "dangling.key"))
	os.Symlink(real, filepath.Join(root, "link"))
	os.Mkdir(filepath.Join(real, "sub"), 0700)
	cases := []struct{ name, path, mode string }{
		{"existing", existing, "0600"},
		{"dangling-symlink", filepath.Join(real, "dangling.key"), "0600"},
		{"symlink-parent", filepath.Join(root, "link", "new.key"), "0600"},
		{"symlink-ancestor", filepath.Join(root, "link", "sub", "new.key"), "0600"},
		{"relative", "relative.key", "0600"},
		{"unclean", real + "/sub/../new.key", "0600"},
		{"missing-parent", filepath.Join(real, "absent", "new.key"), "0600"},
		{"mode-0644", filepath.Join(real, "mode.key"), "0644"},
		{"mode-0400", filepath.Join(real, "mode.key"), "0400"},
	}
	for _, c := range cases {
		var stdout bytes.Buffer
		if e := g2Keygen([]string{"-out", c.path, "-mode", c.mode}, &stdout); e != deploy.ErrInput || stdout.Len() != 0 {
			t.Fatalf("G2_KEYGEN_ACCEPTED %s: err=%v stdout=%q", c.name, e, stdout.String())
		}
	}
	if b, _ := os.ReadFile(existing); string(b) != "prior content" {
		t.Fatal("G2_KEYGEN_OVERWRITE the existing file changed")
	}
	if _, e := os.Lstat(filepath.Join(real, "absent-target")); !os.IsNotExist(e) {
		t.Fatal("G2_KEYGEN_FOLLOWED the dangling symlink was followed")
	}
	entries, _ := os.ReadDir(real)
	if len(entries) != 3 { // existing.key, dangling.key, sub
		t.Fatal("G2_KEYGEN_PARTIAL a refused run left a file", entries)
	}
	// Valid neighbours: the same directories reached without a symlink.
	for _, path := range []string{filepath.Join(real, "new.key"), filepath.Join(real, "sub", "new.key")} {
		if e := g2Keygen([]string{"-out", path}, &bytes.Buffer{}); e != nil {
			t.Fatal("G2_KEYGEN valid neighbour refused", path, e)
		}
	}
}

// Claim: the writer itself, without the commands' existence precheck (the
// window between that precheck and the open), refuses an existing file with
// ErrInput and leaves its bytes and mode unchanged; a new path beside it is
// created with exactly the bytes and mode.
func TestG2NewSecretFileExclusive(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	os.WriteFile(existing, []byte("prior"), 0644)
	os.Chmod(existing, 0644) // independent of the umask
	if e := g2NewSecretFile(existing, []byte("new"), 0600); e != deploy.ErrInput {
		t.Fatal("G2_SECRET_FILE_EXCLUSIVE an existing file was opened", e)
	}
	if b, e := os.ReadFile(existing); e != nil || string(b) != "prior" {
		t.Fatal("G2_SECRET_FILE_EXCLUSIVE the existing file changed or vanished", e)
	}
	if info, _ := os.Lstat(existing); info.Mode().Perm() != 0644 {
		t.Fatal("G2_SECRET_FILE_EXCLUSIVE the existing mode changed", info.Mode())
	}
	fresh := filepath.Join(dir, "fresh")
	if e := g2NewSecretFile(fresh, []byte("new"), 0640); e != nil {
		t.Fatal("G2_SECRET_FILE valid neighbour", e)
	}
	if b, _ := os.ReadFile(fresh); string(b) != "new" {
		t.Fatal("G2_SECRET_FILE content")
	}
	if info, _ := os.Lstat(fresh); info.Mode().Perm() != 0640 {
		t.Fatal("G2_SECRET_FILE mode", info.Mode())
	}
}

// Claim: a trivial draw is never written: a fixed source yielding k=1, n-1
// (the same x-only key as 1), k=1024, BIP-340 vector secret #1, n (>= n), 0
// and only then a good scalar writes the good scalar and prints its key. The
// boundary k=1025 is not trivial and is written. A source that yields k=1
// forever refuses after the bounded attempts and creates no file; a failing
// source refuses the same way.
func TestG2KeygenTrivialResample(t *testing.T) {
	dir := t.TempDir()
	good := g2TestGoodScalar("resample")
	stream := bytes.Join([][]byte{g2TestScalar(1), g2TestNMinus(1), g2TestScalar(1024), g2TestHex(t, g2TrivialBIP340Secrets[1]), g2TestHex(t, g2TestOrderN), make([]byte, 32), good}, nil)
	path := filepath.Join(dir, "resampled.key")
	var stdout bytes.Buffer
	if e := g2KeygenFrom([]string{"-out", path}, &stdout, bytes.NewReader(stream)); e != nil {
		t.Fatal("G2_KEYGEN resample", e)
	}
	if raw, _ := os.ReadFile(path); string(raw) != hex.EncodeToString(good) {
		t.Fatal("G2_KEYGEN_TRIVIAL_WRITTEN the written scalar is not the first non-trivial draw")
	}
	if stdout.String() != "G2_KEY_XONLY "+g2TestXOnly(t, good)+"\n" {
		t.Fatal("G2_KEYGEN_STDOUT resample", stdout.String())
	}

	boundary := filepath.Join(dir, "k1025.key")
	if e := g2KeygenFrom([]string{"-out", boundary}, &bytes.Buffer{}, bytes.NewReader(g2TestScalar(1025))); e != nil {
		t.Fatal("G2_KEYGEN k=1025 refused", e)
	}
	if raw, _ := os.ReadFile(boundary); string(raw) != hex.EncodeToString(g2TestScalar(1025)) {
		t.Fatal("G2_KEYGEN k=1025 not written")
	}

	forever := filepath.Join(dir, "forever.key")
	if e := g2KeygenFrom([]string{"-out", forever}, &stdout, bytes.NewReader(bytes.Repeat(g2TestScalar(1), g2KeygenAttempts+1))); e != errG2KeygenRandom {
		t.Fatal("G2_KEYGEN_TRIVIAL_WRITTEN a source of only k=1 was accepted", e)
	}
	failing := filepath.Join(dir, "failing.key")
	if e := g2KeygenFrom([]string{"-out", failing}, &stdout, bytes.NewReader(make([]byte, 31))); e != errG2KeygenRandom {
		t.Fatal("G2_KEYGEN a failing source was accepted", e)
	}
	for _, p := range []string{forever, failing} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("G2_KEYGEN_PARTIAL a refused draw created", p)
		}
	}
}

// Claim: the trivial-key rule is exactly the g2-funded-preflight rule: x(k*G)
// for 1 <= k <= 1024 and the BIP-340 vector keys #0-#3, whose derived keys
// equal the "public key" column of rows 0..3 of bip-0340/test-vectors.csv.
// x(1025*G) and a hash-derived key are outside it.
func TestG2KeygenTrivialRuleList(t *testing.T) {
	published := [4]string{
		"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
		"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
		"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
	}
	set := g2TrivialXOnly()
	// 1024 small scalars plus the four vectors, of which #0 (secret 3) is
	// already the small scalar k=3.
	if g2TrivialScalarMax != 1024 || len(set) != 1024+3 {
		t.Fatal("G2_TRIVIAL_LIST size", g2TrivialScalarMax, len(set))
	}
	for i, s := range g2TrivialBIP340Secrets {
		if x := g2TestXOnly(t, g2TestHex(t, s)); x != published[i] || !set[x] {
			t.Fatal("G2_TRIVIAL_LIST BIP-340 vector", i, x)
		}
	}
	for _, k := range []uint32{1, 2, 3, 1023, 1024} {
		if !set[g2TestXOnly(t, g2TestScalar(k))] || !set[g2TestXOnly(t, g2TestNMinus(k))] {
			t.Fatal("G2_TRIVIAL_LIST small scalar missing", k)
		}
	}
	if set[g2TestXOnly(t, g2TestScalar(1025))] || set[g2TestXOnly(t, g2TestGoodScalar("list"))] {
		t.Fatal("G2_TRIVIAL_LIST refuses a non-trivial key")
	}
}

// g2TestBuildWalletCLI builds one agent-wallet command from this checkout,
// in its own module context, like TestPX1S5ClientConsumerResolved. It skips
// only where GOPROXY=off and the agent-wallet closure is not in the module
// cache; the Deploy kit workflow downloads it, so there it runs.
func g2TestBuildWalletCLI(t *testing.T, name string) string {
	t.Helper()
	goBin, e := exec.LookPath("go")
	if e != nil {
		t.Fatal("G2_INSTALL_CONSUMER_SETUP go toolchain not on PATH", e)
	}
	cwd, _ := os.Getwd()
	module := filepath.Join(cwd, "..", "..", "..", "experiments", "agent-wallet")
	if _, e := os.Stat(filepath.Join(module, "cmd", name, "main.go")); e != nil {
		t.Fatal("G2_INSTALL_CONSUMER_SETUP agent-wallet source", e)
	}
	bin := filepath.Join(t.TempDir(), name)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, goBin, "build", "-mod=readonly", "-buildvcs=false", "-o", bin, "./cmd/"+name)
	build.Dir = module
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "GOWORK=") {
			build.Env = append(build.Env, v)
		}
	}
	build.Env = append(build.Env, "GOWORK=off")
	if out, e := build.CombinedOutput(); e != nil {
		if os.Getenv("GOPROXY") == "off" && bytes.Contains(out, []byte("module lookup disabled by GOPROXY=off")) {
			t.Skipf("G2_INSTALL_CONSUMER_SKIP agent-wallet dependencies are not in the module cache: %v\n%s", e, out)
		}
		t.Fatalf("G2_INSTALL_CONSUMER_SETUP build %s: %v\n%s", name, e, out)
	}
	return bin
}

// g2TestRunCLI runs a built agent-wallet command with an empty environment
// (plus env) and returns its exit code and stdout; stderr must stay empty.
func g2TestRunCLI(t *testing.T, bin string, env []string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	e := cmd.Run()
	var exit *exec.ExitError
	if e != nil && !errors.As(e, &exit) {
		t.Fatal("G2_INSTALL_CONSUMER_RUN", e)
	}
	if stderr.Len() != 0 {
		t.Fatalf("G2_INSTALL_CONSUMER_RUN stderr %q", stderr.String())
	}
	return cmd.ProcessState.ExitCode(), stdout.String()
}

// Claim: a key file written by g2-keygen is accepted by agent-wallet's
// LoadActionKey (privateBytes(path, 64) then parseActionKey), run as its
// real consumer, the agent-wallet CLI: with a balance request whose grantee
// is the PRINTED x-only key, the CLI loads the key, signs (SignActionForNetwork
// refuses ACTION_KEY unless the loaded key's x-only key equals the grantee),
// and only then stops at the absent socket with SERVICE_SOCKET_MODE. The
// refusing neighbours prove the loader discriminates: the same scalar with a
// newline (65 bytes) or at mode 0640 is SERVICE_PRIVATE_FILE, in uppercase
// hex ACTION_KEY, and a request for another grantee ACTION_KEY. Limit: the
// receipt key's loader (loadReceiptKey: DK5 installedRead, then the same
// parseActionKey) is not run; its admission needs a signed installed set.
func TestG2KeygenActionKeyLoader(t *testing.T) {
	cli := g2TestBuildWalletCLI(t, "agent-wallet")
	dir := t.TempDir()
	key := filepath.Join(dir, "action.key")
	var stdout bytes.Buffer
	if e := g2Keygen([]string{"-out", key}, &stdout); e != nil {
		t.Fatal("G2_KEYGEN", e)
	}
	m := g2KeyLine.FindStringSubmatch(stdout.String())
	if m == nil {
		t.Fatal("G2_KEYGEN_STDOUT", stdout.String())
	}
	xonly := m[1]
	raw, _ := os.ReadFile(key)
	write := func(name string, b []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, b, mode); e != nil {
			t.Fatal(e)
		}
		os.Chmod(p, mode)
		return p
	}
	newline := write("newline.key", append(append([]byte{}, raw...), '\n'), 0600)
	upper := write("upper.key", bytes.ToUpper(raw), 0600)
	group := write("group.key", raw, 0640)
	request := func(name, grantee string) string {
		nonce := make([]byte, 16)
		rand.Read(nonce)
		return write(name, []byte(`{"v":1,"service":"wallet.nmc","action":"balance","params":{},"grant":{"kind":"none"},"nonce":"`+hex.EncodeToString(nonce)+`","created_at":`+strconv.FormatInt(time.Now().Unix(), 10)+`,"grantee":"`+grantee+`"}`), 0644)
	}
	client := func(name, keyFile string) string {
		return write(name, []byte(`{"version":1,"service":"wallet.nmc","socket":"`+filepath.Join(dir, "absent.sock")+`","service_uid":1101,"receipt_key":"`+cliKey2G+`","key_file":"`+keyFile+`"}`), 0644)
	}
	own := request("own.json", xonly)
	other := request("other.json", cliKeyG)
	cases := []struct{ name, config, request, want string }{
		{"written", client("c-written.json", key), own, "SERVICE_SOCKET_MODE"},
		{"newline", client("c-newline.json", newline), own, "SERVICE_PRIVATE_FILE"},
		{"group-readable", client("c-group.json", group), own, "SERVICE_PRIVATE_FILE"},
		{"uppercase", client("c-upper.json", upper), own, "ACTION_KEY"},
		{"other-grantee", client("c-other.json", key), other, "ACTION_KEY"},
	}
	for _, c := range cases {
		code, out := g2TestRunCLI(t, cli, []string{}, "--config", c.config, "--request", c.request)
		if code != 2 || out != `{"error":"`+c.want+`"}`+"\n" {
			t.Fatalf("G2_KEYGEN_CONSUMER %s: exit %d stdout %q, want %s", c.name, code, out, c.want)
		}
	}
}

// g2TestPolicy is a TEST policy object pinned to one chain, with the fixed
// G2 kernel state directory.
func g2TestPolicy(network, genesis string) string {
	return `{"construction_profile":"W","network":"` + network + `","genesis":"` + genesis + `","agent_name":"id/g2-test-agent","landlord_name":"id/g2-test-landlord","seal_script":"76a914111111111111111111111111111111111111111188ac","state_dir":"/var/lib/swarma-wallet/kernel"}`
}

// g2TestWritePublic writes the operator's public wallet members.
func g2TestWritePublic(t *testing.T, dir, name, network, genesis, change string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	b := `{"policy":` + g2TestPolicy(network, genesis) + `,"change_address":"` + change + `","wallet_dir":"/srv/agent/.local/share/swarma/agent-wallet/node","memory_zone":"/srv/agent/.local/share/swarma/memory"}` + "\n"
	if e := os.WriteFile(p, []byte(b), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}

func g2TestWriteParams(t *testing.T, dir, name string, p deploy.G2PayParameters) string {
	t.Helper()
	path := filepath.Join(dir, name)
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, append(raw, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}

var g2RPCAuthLines = regexp.MustCompile(`^rpcauth=w3-observer:([0-9a-f]{32})\$([0-9a-f]{64})\nrpcauth=w1-wallet:([0-9a-f]{32})\$([0-9a-f]{64})\nrpcauth=w1-broadcast:([0-9a-f]{32})\$([0-9a-f]{64})\n$`)

// g2TestCoreVerify is the node's login check, written independently from
// share/rpcauth/rpcauth.py: HMAC-SHA256(key = salt text, msg = password).
func g2TestCoreVerify(salt, hash, password string) bool {
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte(password))
	want, _ := hex.DecodeString(hash)
	return hmac.Equal(m.Sum(nil), want)
}

// Claim: g2RPCAuthLine equals Namecoin Core 28's share/rpcauth/rpcauth.py
// (byte-identical to Bitcoin Core v28.0's) for a fixed TEST salt and
// password: the expected line is that script's password_to_hmac output. The
// two wrong constructions (key and message swapped; the salt hex decoded to
// bytes as the key) give other values.
func TestG2RPCAuthKnownAnswer(t *testing.T) {
	const salt, password = "000102030405060708090a0b0c0d0e0f", "fixed-test-password-g2-rpcauth-kat"
	const want = "rpcauth=w1-wallet:000102030405060708090a0b0c0d0e0f$a9cd38c144b75197d7a1ad419ec0d6c3f3f556f20faa0c86dbcefdc430a99d6d"
	if got := g2RPCAuthLine("w1-wallet", salt, []byte(password)); got != want {
		t.Fatalf("G2_RPCAUTH_KAT got %s want %s", got, want)
	}
	for _, wrong := range []string{"654c208d6b6943628031a66caf3ed6e39eb6630a67738f667a739b6ef27df3db", "388a08cbf243f3ce4a17d0bd00921eb30e54711b6873b7cb411519c631b94962"} {
		if strings.HasSuffix(want, wrong) {
			t.Fatal("G2_RPCAUTH_KAT the expected value is a wrong construction")
		}
	}
	if !g2TestCoreVerify(salt, strings.TrimPrefix(want, "rpcauth=w1-wallet:"+salt+"$"), password) {
		t.Fatal("G2_RPCAUTH_KAT independent verifier disagrees")
	}
}

// Claim: g2-rpcauth writes a new wallet.json (mode 0640, compact, no trailing
// newline) holding three distinct 64-hex passwords on loopback routes with
// the fixed user names, the parameters' port, hot wallet name, chain pin and
// fee rate, the operator's public members verbatim and the fixed state and
// object directories (port, wallet name and fee rate are non-default test
// values); stdout is exactly the three rpcauth lines in route
// order, each verifies its stored password under Core's check, and no
// password appears on stdout. The fixed source shows every password and salt
// is drawn from the injected source in route order.
func TestG2RPCAuthCommand(t *testing.T) {
	dir := t.TempDir()
	p := cliParams()
	// Non-default values, so a member hardcoded to the template is visible.
	p.NodeRPCPort, p.HotWalletName, p.FeeRateSatVB = 18336, "g2-test-hot", 120
	params := g2TestWriteParams(t, dir, "params.json", p)
	public := g2TestWritePublic(t, dir, "public.json", p.Network, p.Genesis, g2TestMainChange)
	out := filepath.Join(dir, "wallet.json")
	var stdout bytes.Buffer
	if e := g2RPCAuth([]string{"-params", params, "-wallet-public", public, "-wallet-config-out", out}, &stdout); e != nil {
		t.Fatal("G2_RPCAUTH positive", e)
	}
	raw, _ := os.ReadFile(out)
	info, _ := os.Lstat(out)
	if info.Mode().Perm() != 0640 || len(raw) == 0 || raw[len(raw)-1] != '}' {
		t.Fatalf("G2_RPCAUTH_FILE mode %v, last byte", info.Mode())
	}
	var c g2WalletConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.More() {
		t.Fatal("G2_RPCAUTH_FILE schema")
	}
	routes := []g2WalletRoute{c.Observer, c.Wallet.Route, c.Broadcast}
	m := g2RPCAuthLines.FindStringSubmatch(stdout.String())
	if m == nil {
		t.Fatalf("G2_RPCAUTH_STDOUT not exactly three rpcauth lines: %d bytes", stdout.Len())
	}
	seen := map[string]bool{}
	for i, r := range routes {
		if r.Host != "127.0.0.1" || r.Port != int(p.NodeRPCPort) || r.Username != g2RPCRoutes[i] || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(r.Password) || seen[r.Password] {
			t.Fatalf("G2_RPCAUTH_ROUTE %d host=%s port=%d user=%s", i, r.Host, r.Port, r.Username)
		}
		seen[r.Password] = true
		if !g2TestCoreVerify(m[1+2*i], m[2+2*i], r.Password) {
			t.Fatalf("G2_RPCAUTH_VERIFY route %s: the printed line does not verify the stored password", r.Username)
		}
		if strings.Contains(stdout.String(), r.Password) {
			t.Fatalf("G2_RPCAUTH_LEAK route %s: password on stdout", r.Username)
		}
	}
	wantPolicy := g2TestPolicy(p.Network, p.Genesis)
	if c.Version != 1 || c.Network != p.Network || c.Genesis != p.Genesis || string(c.Policy) != wantPolicy || c.Wallet.Wallet != p.HotWalletName || c.StateDir != "/var/lib/swarma-wallet/wallet" || c.ObjectsDir != "/var/lib/swarma-wallet/objects" || c.ChangeAddress != g2TestMainChange || c.FeeRate != p.FeeRateSatVB || c.WalletDir != "/srv/agent/.local/share/swarma/agent-wallet/node" || c.MemoryZone != "/srv/agent/.local/share/swarma/memory" {
		t.Fatal("G2_RPCAUTH_FILE members")
	}

	// Fixed TEST source: password i is 32 bytes of 0x10+i, salt i 16 bytes of 0x20+i.
	var stream []byte
	for i := range 3 {
		stream = append(stream, bytes.Repeat([]byte{byte(0x10 + i)}, 32)...)
		stream = append(stream, bytes.Repeat([]byte{byte(0x20 + i)}, 16)...)
	}
	fixed := filepath.Join(dir, "fixed.json")
	stdout.Reset()
	if e := g2RPCAuthFrom([]string{"-params", params, "-wallet-public", public, "-wallet-config-out", fixed}, &stdout, bytes.NewReader(stream)); e != nil {
		t.Fatal("G2_RPCAUTH fixed source", e)
	}
	var want strings.Builder
	for i, user := range g2RPCRoutes {
		want.WriteString(g2RPCAuthLine(user, strings.Repeat(hex.EncodeToString([]byte{byte(0x20 + i)}), 16), []byte(strings.Repeat(hex.EncodeToString([]byte{byte(0x10 + i)}), 32))) + "\n")
	}
	if stdout.String() != want.String() {
		t.Fatal("G2_RPCAUTH fixed source lines differ")
	}
	raw, _ = os.ReadFile(fixed)
	for i := range 3 {
		if !bytes.Contains(raw, []byte(`"password":"`+strings.Repeat(hex.EncodeToString([]byte{byte(0x10 + i)}), 32)+`"`)) {
			t.Fatal("G2_RPCAUTH fixed source password", i)
		}
	}
}

// Claim: g2-rpcauth refuses, printing nothing and writing nothing, an
// existing output (left unchanged), a dangling symlink or symlink-parent
// output, a relative output, a failing random source, and public members
// that are not exactly the operator's part: a route or password member, a
// chain pin member, a policy pinned to another chain or another kernel state
// directory, a missing policy or change address, a relative wallet_dir, a
// placeholder, and invalid parameters. The valid neighbour beside them is
// accepted (TestG2RPCAuthCommand).
func TestG2RPCAuthRefusals(t *testing.T) {
	dir := t.TempDir()
	p := cliParams()
	params := g2TestWriteParams(t, dir, "params.json", p)
	public := g2TestWritePublic(t, dir, "public.json", p.Network, p.Genesis, g2TestMainChange)
	good, _ := os.ReadFile(public)
	variant := func(name, from, to string) string {
		if !bytes.Contains(good, []byte(from)) {
			t.Fatal("G2_RPCAUTH_SETUP", name)
		}
		path := filepath.Join(dir, name+".json")
		os.WriteFile(path, bytes.Replace(good, []byte(from), []byte(to), 1), 0600)
		return path
	}
	existing := filepath.Join(dir, "existing.json")
	os.WriteFile(existing, []byte("prior"), 0640)
	os.Symlink(filepath.Join(dir, "absent-target"), filepath.Join(dir, "dangling.json"))
	os.Mkdir(filepath.Join(dir, "real"), 0700)
	os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link"))
	bad := cliParams()
	bad.FeeRateSatVB = 200000
	badParams := g2TestWriteParams(t, dir, "bad-params.json", bad)
	fresh := func(name string) string { return filepath.Join(dir, "out-"+name+".json") }
	E, P := deploy.ErrInput, deploy.ErrPolicy
	cases := []struct {
		name, params, public, out string
		rnd                       []byte
		want                      error
	}{
		{"existing", params, public, existing, nil, E},
		{"dangling-symlink", params, public, filepath.Join(dir, "dangling.json"), nil, E},
		{"symlink-parent", params, public, filepath.Join(dir, "link", "wallet.json"), nil, E},
		{"relative", params, public, "wallet.json", nil, E},
		{"short-random", params, public, fresh("short-random"), make([]byte, 100), errG2KeygenRandom},
		{"route-member", params, variant("route-member", `"change_address"`, `"observer":{"host":"127.0.0.1","port":8336,"username":"w3-observer","password":"0123456789abcdef"},"change_address"`), fresh("route-member"), nil, P},
		{"pin-member", params, variant("pin-member", `"change_address"`, `"network":"main","change_address"`), fresh("pin-member"), nil, P},
		{"policy-chain", params, variant("policy-chain", `"network":"main"`, `"network":"regtest"`), fresh("policy-chain"), nil, P},
		{"policy-state", params, variant("policy-state", `/var/lib/swarma-wallet/kernel`, `/var/lib/swarma-wallet/other`), fresh("policy-state"), nil, P},
		{"no-policy", params, variant("no-policy", `{"policy":`+g2TestPolicy(p.Network, p.Genesis)+`,`, `{`), fresh("no-policy"), nil, P},
		{"policy-not-object", params, variant("policy-not-object", `{"policy":`+g2TestPolicy(p.Network, p.Genesis)+`,`, `{"policy":"main",`), fresh("policy-not-object"), nil, P},
		{"no-change", params, variant("no-change", `"change_address":"`+g2TestMainChange+`"`, `"change_address":""`), fresh("no-change"), nil, P},
		{"relative-wallet-dir", params, variant("relative-wallet-dir", `"/srv/agent/.local/share/swarma/agent-wallet/node"`, `"node"`), fresh("relative-wallet-dir"), nil, P},
		{"placeholder", params, variant("placeholder", g2TestMainChange, "PLACEHOLDER_CHANGE"), fresh("placeholder"), nil, deploy.ErrPlaceholder},
		{"duplicate", params, variant("duplicate", `"change_address"`, `"change_address":"x","change_address"`), fresh("duplicate"), nil, P},
		{"bad-params", badParams, public, fresh("bad-params"), nil, P},
	}
	for _, c := range cases {
		var rnd = rand.Reader
		if c.rnd != nil {
			rnd = bytes.NewReader(c.rnd)
		}
		var stdout bytes.Buffer
		e := g2RPCAuthFrom([]string{"-params", c.params, "-wallet-public", c.public, "-wallet-config-out", c.out}, &stdout, rnd)
		if !errors.Is(e, c.want) || stdout.Len() != 0 {
			t.Fatalf("G2_RPCAUTH_ACCEPTED %s: err=%v want %v, stdout=%d bytes", c.name, e, c.want, stdout.Len())
		}
		if c.out != existing && c.name != "dangling-symlink" && filepath.IsAbs(c.out) {
			if _, e := os.Lstat(c.out); !os.IsNotExist(e) {
				t.Fatal("G2_RPCAUTH_PARTIAL", c.name)
			}
		}
	}
	if b, _ := os.ReadFile(existing); string(b) != "prior" {
		t.Fatal("G2_RPCAUTH_OVERWRITE")
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "real")); len(entries) != 0 {
		t.Fatal("G2_RPCAUTH_PARTIAL symlink parent", entries)
	}
	if _, e := os.Lstat(filepath.Join(dir, "absent-target")); !os.IsNotExist(e) {
		t.Fatal("G2_RPCAUTH_FOLLOWED")
	}
}

// Claim: the wallet.json g2-rpcauth writes is accepted by agent-wallet's
// wallet config loader, run as its real consumer, agent-wallet-legacy
// (LoadConfig: owner-only file admission, then parseWalletConfig, the parse
// LoadInstalledWalletConfig shares). On main the loader accepts it and the
// legacy Open refuses CONFIG_REGTEST_ONLY (legacy execution is regtest-only).
// On regtest Open goes on through validateNetwork (policy pins, fee rate,
// change address), the path checks and all four route constructors
// (loopback, one node, the exact user names, password length) and stops only
// at the absent G2 wallet state directory with PRIVATE_STATE_ROOT. The
// refusing neighbours prove each stage discriminates: an extra member is
// CONFIG_SCHEMA, a 15-character password READ_ONLY_ROUTE, a swapped user name
// RPC_ROUTE. Limits: the test chmods the file 0600 because LoadConfig admits
// only owner-only files (the installed loader admits 0640 root:swarma-wallet
// in a DK5 signed set, not reproducible here); it runs no node and no service.
func TestG2RPCAuthWalletLoader(t *testing.T) {
	cli := g2TestBuildWalletCLI(t, "agent-wallet-legacy")
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.Mkdir(home, 0700)
	reg := cliParams()
	reg.Network, reg.Genesis = "regtest", g2TestRegtestGenesis
	write := func(network string, p deploy.G2PayParameters, change string) []byte {
		params := g2TestWriteParams(t, dir, network+"-params.json", p)
		public := g2TestWritePublic(t, dir, network+"-public.json", p.Network, p.Genesis, change)
		out := filepath.Join(dir, network+"-wallet.json")
		if e := g2RPCAuth([]string{"-params", params, "-wallet-public", public, "-wallet-config-out", out}, &bytes.Buffer{}); e != nil {
			t.Fatal("G2_RPCAUTH", network, e)
		}
		raw, _ := os.ReadFile(out)
		return raw
	}
	mainRaw := write("main", cliParams(), g2TestMainChange)
	regRaw := write("regtest", reg, g2TestRegtestChange)
	var c g2WalletConfig
	json.Unmarshal(regRaw, &c)
	short := bytes.Replace(regRaw, []byte(`"password":"`+c.Observer.Password+`"`), []byte(`"password":"`+c.Observer.Password[:15]+`"`), 1)
	swapped := bytes.Replace(regRaw, []byte(`"username":"w1-broadcast"`), []byte(`"username":"w1-wallet"`), 1)
	extra := bytes.Replace(regRaw, []byte(`{"version":1,`), []byte(`{"version":1,"extra":1,`), 1)
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"main-written", mainRaw, "CONFIG_REGTEST_ONLY"},
		{"regtest-written", regRaw, "PRIVATE_STATE_ROOT"},
		{"extra-member", extra, "CONFIG_SCHEMA"},
		{"short-password", short, "READ_ONLY_ROUTE"},
		{"swapped-user", swapped, "RPC_ROUTE"},
	}
	for _, k := range cases {
		if k.name != "main-written" && k.name != "regtest-written" && bytes.Equal(k.raw, regRaw) {
			t.Fatal("G2_RPCAUTH_CONSUMER_SETUP neighbour unchanged", k.name)
		}
		path := filepath.Join(dir, "consumer-"+k.name+".json")
		if e := os.WriteFile(path, k.raw, 0600); e != nil {
			t.Fatal(e)
		}
		code, out := g2TestRunCLI(t, cli, []string{"HOME=" + home}, "--config", path, "balance")
		var r struct{ Status, Reason string }
		if json.Unmarshal([]byte(out), &r) != nil || code != 2 || r.Status != "refused" || r.Reason != k.want {
			t.Fatalf("G2_RPCAUTH_CONSUMER %s: exit %d reason %q, want %s", k.name, code, r.Reason, k.want)
		}
	}
}
