package main

// g2-rpcauth: the station-side generator of the three G2 node RPC
// credentials. Each route password goes only into a new private wallet.json;
// stdout carries only the Core rpcauth lines (salt and HMAC, no password).

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

// The G2 node routes, in the order of the wallet.json members and of the
// printed lines. The user names are the ones agent-wallet's RPC clients
// require (rpc.go: w3-observer, w1-wallet, w1-broadcast).
var g2RPCRoutes = [3]string{"w3-observer", "w1-wallet", "w1-broadcast"}

// Fixed G2 wallet layout: the wallet state, the kernel (policy) state and the
// object directory of templates/g2-pay tmpfiles.conf, the paths the T18
// custody spec denies to the agent. The node is on loopback.
const (
	g2WalletStateDir  = "/var/lib/swarma-wallet/wallet"
	g2KernelStateDir  = "/var/lib/swarma-wallet/kernel"
	g2WalletObjectDir = "/var/lib/swarma-wallet/objects"
	g2NodeHost        = "127.0.0.1"
)

// g2WalletRoute mirrors single-use Route; g2WalletWalletRoute mirrors
// agent-wallet WalletRoute.
type g2WalletRoute struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type g2WalletWalletRoute struct {
	Route  g2WalletRoute `json:"route"`
	Wallet string        `json:"wallet"`
}

// g2WalletConfig mirrors agent-wallet Config (wallet.go), the schema of
// /etc/swarma/wallet/wallet.json that LoadInstalledWalletConfig and
// LoadConfig parse: same members, same order, no omitempty. deploy never
// imports agent-wallet; TestG2RPCAuthWalletLoader runs the real loader on
// the written file.
type g2WalletConfig struct {
	Version       int                 `json:"version"`
	Network       string              `json:"network"`
	Genesis       string              `json:"genesis"`
	Policy        json.RawMessage     `json:"policy"`
	Observer      g2WalletRoute       `json:"observer"`
	Wallet        g2WalletWalletRoute `json:"wallet"`
	Broadcast     g2WalletRoute       `json:"broadcast"`
	StateDir      string              `json:"state_dir"`
	ObjectsDir    string              `json:"objects_dir"`
	ChangeAddress string              `json:"change_address"`
	FeeRate       int64               `json:"fee_rate_sat_vb"`
	WalletDir     string              `json:"wallet_dir"`
	MemoryZone    string              `json:"memory_zone"`
}

// g2WalletPublic is the operator's public part of wallet.json: the members
// the canonical parameters do not carry. It holds no credential, and none of
// the members the command takes from the parameters or fixes itself.
type g2WalletPublic struct {
	Policy        json.RawMessage `json:"policy"`
	ChangeAddress string          `json:"change_address"`
	WalletDir     string          `json:"wallet_dir"`
	MemoryZone    string          `json:"memory_zone"`
}

// g2RPCAuthLine is Core's rpcauth line for user, salt and password, as
// Namecoin Core 28 share/rpcauth/rpcauth.py writes it (identical to Bitcoin
// Core v28.0's): password_to_hmac(salt, password) is
// hmac.new(salt.encode('utf-8'), password.encode('utf-8'), 'SHA256').hexdigest(),
// that is HMAC-SHA256 keyed with the hex salt TEXT (not its decoded bytes)
// over the password, and the line is f'rpcauth={username}:{salt}${hmac}'.
// The node checks a login the same way (httprpc.cpp, CHMAC_SHA256 keyed with
// the salt string). TestG2RPCAuthKnownAnswer pins it to that script's output.
func g2RPCAuthLine(user, salt string, password []byte) string {
	m := hmac.New(sha256.New, []byte(salt))
	m.Write(password)
	return "rpcauth=" + user + ":" + salt + "$" + hex.EncodeToString(m.Sum(nil))
}

func g2AbsClean(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\n")
}

// g2PayPolicy is the W pay-path subset of rental.Policy. A rental import adds
// btcd and the payment-chain/rental-booking dependency closure to deploy;
// validateGrant and wallet.addressScriptForNetwork are also package-private.
// TestG2RPCAuthProductValidators pins these checks to those actual functions
// in their own modules, without adding dependencies or changing product code.
// Legacy-v1 members are intentionally absent: StrictInput refuses even empty
// legacy members, as well as unknown, duplicate, aliased and null members.
type g2PayPolicy struct {
	ConstructionProfile string `json:"construction_profile"`
	Network             string `json:"network"`
	Genesis             string `json:"genesis"`
	StateDir            string `json:"state_dir"`
	AgentName           string `json:"agent_name"`
	LandlordName        string `json:"landlord_name"`
	SealScript          string `json:"seal_script"`
	KnownPoolSeals      []struct {
		TxID string `json:"txid"`
		Vout uint32 `json:"vout"`
	} `json:"known_pool_seals,omitempty"`
}

func g2PublicRefusal(member string) error {
	return fmt.Errorf("%w: wallet-public %s", deploy.ErrPolicy, member)
}

// Same id/ name grammar as rental.station, including its byte limit.
func g2PayName(s string) bool {
	if !strings.HasPrefix(s, "id/") || len(s) <= 3 || len(s) > 255 {
		return false
	}
	for _, c := range []byte(s[3:]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func g2ValidatePayPolicy(raw []byte, p deploy.G2PayParameters) error {
	var policy g2PayPolicy
	if su.StrictInput(raw, &policy) != nil {
		return g2PublicRefusal("policy schema")
	}
	if su.RequireWitnessProfile(policy.ConstructionProfile) != nil {
		return g2PublicRefusal("policy.construction_profile")
	}
	if policy.Network != p.Network {
		return g2PublicRefusal("policy.network")
	}
	if policy.Genesis != p.Genesis || !su.NetworkPinned(policy.Network, policy.Genesis) {
		return g2PublicRefusal("policy.genesis")
	}
	if policy.StateDir != g2KernelStateDir {
		return g2PublicRefusal("policy.state_dir")
	}
	if !g2PayName(policy.AgentName) {
		return g2PublicRefusal("policy.agent_name")
	}
	if !g2PayName(policy.LandlordName) || policy.LandlordName == policy.AgentName {
		return g2PublicRefusal("policy.landlord_name")
	}
	b, e := hex.DecodeString(policy.SealScript)
	if e != nil || hex.EncodeToString(b) != policy.SealScript || len(b) != 25 || !bytes.Equal(b[:3], []byte{0x76, 0xa9, 20}) || !bytes.Equal(b[23:], []byte{0x88, 0xac}) {
		return g2PublicRefusal("policy.seal_script")
	}
	if len(policy.KnownPoolSeals) > 4096 {
		return g2PublicRefusal("policy.known_pool_seals")
	}
	seen := map[string]bool{}
	for _, point := range policy.KnownPoolSeals {
		b, e := hex.DecodeString(point.TxID)
		key := fmt.Sprintf("%s:%d", point.TxID, point.Vout)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != point.TxID || seen[key] {
			return g2PublicRefusal("policy.known_pool_seals")
		}
		seen[key] = true
	}
	return nil
}

// Equivalent to the wallet startup path: a canonical Base58Check encoding of
// a 20-byte pubkey hash on the pinned network, never P2SH or witness. The
// exact decoded length also rejects redundant leading Base58 zeroes.
func g2PayChangeAddress(address, network, genesis string) bool {
	if !su.NetworkPinned(network, genesis) || len(address) < 26 || len(address) > 35 {
		return false
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int)
	for _, c := range []byte(address) {
		i := strings.IndexByte(alphabet, c)
		if i < 0 {
			return false
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(i)))
	}
	b := n.Bytes()
	for i := 0; i < len(address) && address[i] == '1'; i++ {
		b = append([]byte{0}, b...)
	}
	version := byte(111)
	if network == "main" {
		version = 52
	}
	if len(b) != 25 || b[0] != version {
		return false
	}
	first := sha256.Sum256(b[:21])
	second := sha256.Sum256(first[:])
	return bytes.Equal(b[21:], second[:4])
}

// g2ReadWalletPublic validates every public input before any entropy is drawn
// or any output file or rpcauth line is written.
func g2ReadWalletPublic(path string, p deploy.G2PayParameters) (g2WalletPublic, error) {
	var w g2WalletPublic
	raw, e := readBounded(path, 1<<16)
	if e != nil {
		return w, e
	}
	if bytes.Contains(raw, []byte("PLACEHOLDER")) {
		return w, deploy.ErrPlaceholder
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	if su.StrictInput(raw, &w) != nil || len(w.Policy) == 0 {
		return g2WalletPublic{}, g2PublicRefusal("schema")
	}
	if e := g2ValidatePayPolicy(w.Policy, p); e != nil {
		return g2WalletPublic{}, e
	}
	if !g2PayChangeAddress(w.ChangeAddress, p.Network, p.Genesis) {
		return g2WalletPublic{}, g2PublicRefusal("change_address")
	}
	if !g2AbsClean(w.WalletDir) {
		return g2WalletPublic{}, g2PublicRefusal("wallet_dir")
	}
	for _, state := range []string{g2WalletStateDir, "/var/lib/swarma-wallet/service"} {
		if w.WalletDir == state || strings.HasPrefix(w.WalletDir, state+"/") || strings.HasPrefix(state, w.WalletDir+"/") {
			return g2WalletPublic{}, g2PublicRefusal("wallet_dir state overlap")
		}
	}
	if !g2AbsClean(w.MemoryZone) || w.MemoryZone == g2WalletStateDir {
		return g2WalletPublic{}, g2PublicRefusal("memory_zone")
	}
	return w, nil
}

// g2RPCAuth generates the three G2 node RPC credentials:
//
//	deploy-kit g2-rpcauth -params PARAMS -wallet-public PUBLIC -wallet-config-out FILE
//
// For each route (g2RPCRoutes) it draws a 32-byte random password (64 hex
// characters) and a 16-byte random salt (32 hex characters) and computes the
// Core rpcauth line (g2RPCAuthLine). The passwords go only into FILE, a new
// wallet.json in the agent-wallet Config schema, created exclusively with
// mode 0640 (g2NewSecretFile; the chown to root:swarma-wallet is the
// operator's step), compact JSON with no trailing newline. Its members come
// from:
//   - the parameters (-params, the g2-render parser): network, genesis,
//     fee_rate_sat_vb, the node port (node_rpc_port) of all three routes and
//     the wallet route's Core wallet name (hot_wallet_name);
//   - the operator's public members (-wallet-public): policy, change_address,
//     wallet_dir, memory_zone;
//   - fixed: version 1, host 127.0.0.1, the three user names, state_dir
//     g2WalletStateDir and objects_dir g2WalletObjectDir.
//
// Stdout is exactly the three rpcauth lines, in route order, for the node
// config; it never carries a password. Nothing is printed unless FILE was
// written.
func g2RPCAuth(args []string, out io.Writer) error { return g2RPCAuthFrom(args, out, rand.Reader) }

// g2RPCAuthFrom is g2RPCAuth with the random source as a parameter (the test
// seam); production passes crypto/rand.
func g2RPCAuthFrom(args []string, out io.Writer, rnd io.Reader) error {
	f := flag.NewFlagSet("g2-rpcauth", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	params := f.String("params", "", "canonical G2PayParameters JSON")
	public := f.String("wallet-public", "", "public wallet.json members: policy, change_address, wallet_dir, memory_zone")
	path := f.String("wallet-config-out", "", "new absolute wallet.json")
	if f.Parse(args) != nil || f.NArg() != 0 || !filepath.IsAbs(*path) || filepath.Clean(*path) != *path {
		return deploy.ErrInput
	}
	if _, e := os.Lstat(*path); !errors.Is(e, os.ErrNotExist) {
		return deploy.ErrInput
	}
	raw, e := readBounded(*params, 1<<16)
	if e != nil {
		return e
	}
	p, e := deploy.ParseG2PayParameters(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return e
	}
	pub, e := g2ReadWalletPublic(*public, p)
	if e != nil {
		return e
	}
	var secret [3][32]byte
	var salt [3][16]byte
	defer func() {
		for i := range secret {
			clear(secret[i][:])
		}
	}()
	var passwords [3][]byte
	var lines [3]string
	for i, user := range g2RPCRoutes {
		if _, e := io.ReadFull(rnd, secret[i][:]); e != nil {
			return errG2KeygenRandom
		}
		if _, e := io.ReadFull(rnd, salt[i][:]); e != nil {
			return errG2KeygenRandom
		}
		passwords[i] = make([]byte, 64)
		hex.Encode(passwords[i], secret[i][:])
		defer clear(passwords[i])
		lines[i] = g2RPCAuthLine(user, hex.EncodeToString(salt[i][:]), passwords[i])
	}
	route := func(i int) g2WalletRoute {
		return g2WalletRoute{Host: g2NodeHost, Port: int(p.NodeRPCPort), Username: g2RPCRoutes[i], Password: string(passwords[i])}
	}
	config, e := json.Marshal(g2WalletConfig{
		Version: 1, Network: p.Network, Genesis: p.Genesis, Policy: pub.Policy,
		Observer: route(0), Wallet: g2WalletWalletRoute{Route: route(1), Wallet: p.HotWalletName}, Broadcast: route(2),
		StateDir: g2WalletStateDir, ObjectsDir: g2WalletObjectDir, ChangeAddress: pub.ChangeAddress,
		FeeRate: p.FeeRateSatVB, WalletDir: pub.WalletDir, MemoryZone: pub.MemoryZone,
	})
	if e != nil {
		return deploy.ErrPolicy
	}
	e = g2NewSecretFile(*path, config, 0640)
	clear(config)
	if e != nil {
		return e
	}
	_, e = fmt.Fprint(out, lines[0]+"\n"+lines[1]+"\n"+lines[2]+"\n")
	return e
}
