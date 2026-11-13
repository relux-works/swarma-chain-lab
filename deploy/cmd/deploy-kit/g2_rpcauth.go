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

// g2ReadWalletPublic reads and checks the operator's public wallet members
// against the parameters: strict JSON (unknown, duplicate or null members
// refuse), no placeholder, a policy object pinned to the parameters' chain
// with state_dir g2KernelStateDir, a change address, and absolute clean
// wallet_dir and memory_zone.
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
		return g2WalletPublic{}, deploy.ErrPolicy
	}
	var policy struct {
		Network  string `json:"network"`
		Genesis  string `json:"genesis"`
		StateDir string `json:"state_dir"`
	}
	if json.Unmarshal(w.Policy, &policy) != nil || policy.Network != p.Network || policy.Genesis != p.Genesis || policy.StateDir != g2KernelStateDir {
		return g2WalletPublic{}, deploy.ErrPolicy
	}
	if w.ChangeAddress == "" || len(w.ChangeAddress) > 128 || strings.ContainsAny(w.ChangeAddress, " \t\r\n\x00") || !g2AbsClean(w.WalletDir) || !g2AbsClean(w.MemoryZone) {
		return g2WalletPublic{}, deploy.ErrPolicy
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
