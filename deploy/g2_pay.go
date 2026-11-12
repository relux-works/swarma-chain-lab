package deploy

// PX1 stream S5 implementation (owner S5): G2 pay deploy parameters, the
// templates/g2-pay render, and the T18 different-UID custody probe. The frozen
// signatures and types live in g2_pay_api.go.
//
// Scope: validation and rendering are pure (no account lookup); nothing here
// opens credentials, funds or spends. Two entry points touch a host:
// RunCustodyProbe, only as the agent UID (it opens each denied path read-only,
// sends one credential-less JSON-RPC call to each loopback node port, and
// connects, without sending a frame, to the agent's wallet socket); and
// RunG2HostFlow, the target-host provisioning order, whose host actions are
// supplied by the caller (deploy-kit g2-host-flow on the target host).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrCustody refuses a T18 probe run from the wrong UID, a probe that met an
// unclassifiable host error, and every report that does not prove custody.
var ErrCustody = errors.New("deploy: G2 custody check refused")

// Fixed G2 host layout. The paths repeat the W2 wallet layout (wallet_config.go,
// templates/wallet/*).
const (
	g2WalletSocket = G2WalletSocketPath
	g2WalletConfig = "/etc/swarma/wallet/wallet.json"
	g2ReceiptKey   = "/etc/swarma/wallet/receipt.key"
	g2StateRoot    = "/var/lib/swarma-wallet"
	g2StateDir     = "/var/lib/swarma-wallet/service"
	g2ServiceUser  = "swarma-wallet"
)

// Route method sets of the own node (experiments/agent-wallet/README.md, "Use
// separate Core rpcwhitelist entries"). Order is the README order.
var g2RPCWhitelist = [][2]string{
	{"w3-observer", "getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock"},
	{"w1-wallet", "getbalances,getnewaddress,listtransactions,fundrawtransaction,signrawtransactionwithwallet"},
	{"w1-broadcast", "sendrawtransaction"},
}

// g2DeniedFixed is the launch prefix of CustodySpecV1.DeniedReads: the private
// wallet config, the receipt scalar, every service-owned state directory and
// the operator status socket directory (amendment 1, A8: the agent is not in
// the operator group, so it must get EACCES there). The node cookie and
// wallet.dat follow (they depend on the node datadir). A directory target
// passes only when the agent can neither list nor search it (probeRead), so no
// journal, state file or socket below it is reachable by name.
var g2DeniedFixed = []string{
	g2WalletConfig,
	g2ReceiptKey,
	g2StateDir,
	"/var/lib/swarma-wallet/wallet",
	"/var/lib/swarma-wallet/kernel",
	"/var/lib/swarma-wallet/objects",
	G2StatusSocketDir,
}

// secp256k1 field prime p = 2^256 - 2^32 - 977.
var secpP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

// xOnlyKey accepts a 32-byte lowercase-hex BIP-340 public key: x < p and
// x^3 + 7 is a square mod p (lift_x succeeds).
func xOnlyKey(s string) bool {
	if !exactHex(s, 32) {
		return false
	}
	x, _ := new(big.Int).SetString(s, 16)
	if x.Cmp(secpP) >= 0 {
		return false
	}
	c := new(big.Int).Exp(x, big.NewInt(3), secpP)
	c.Add(c, big.NewInt(7)).Mod(c, secpP)
	e := new(big.Int).Add(secpP, big.NewInt(1))
	e.Rsh(e, 2)
	y := new(big.Int).Exp(c, e, secpP)
	return new(big.Int).Exp(y, big.NewInt(2), secpP).Cmp(c) == 0
}

// g2Pins accepts only an explicit chain pin: main with the main genesis (the
// launch target) or regtest with the regtest genesis (T18 rehearsal and Core
// tests). An empty genesis is refused for G2 even where W2 defaults it.
func g2Pins(network, genesis string) bool {
	return network == "main" && genesis == mainGenesis || network == "regtest" && genesis == regtestGenesis
}

// validateG2Operator is the deploy pre-check of the "g2" operator block. The
// agent-wallet ValidateG2OperatorConfig (S1) stays authoritative at startup;
// this check is stricter for launch: single-use and "any" recipients are
// refused (Q7, Q2 phase 1).
func validateG2Operator(c G2OperatorParameters) error {
	o := c.Canary.Outpoint
	switch {
	case c.RequireTermsVersion != 2, c.AllowSingleUse, c.AllowAnyRecipients:
		return ErrPolicy
	case c.MaxTransferSat < 1 || c.MaxTransferSat > c.MaxDaySat:
		return ErrPolicy
	case c.MaxDayCount < 1 || c.MaxDayCount > 1000:
		return ErrPolicy
	case c.MaxFeeSat < 1 || c.MaxFeeSat > 1000000:
		return ErrPolicy
	case c.MaxFloatSat < 1 || c.MaxFloatSat > 21000000*100000000 || c.MaxDaySat > c.MaxFloatSat:
		return ErrPolicy
	case c.LowFloatSat < 0 || c.LowFloatSat >= c.MaxFloatSat:
		return ErrPolicy
	case !digestPin(o.TxID) || o.Vout > 0xffff || c.Canary.ValueSat < 546 || c.Canary.ValueSat > c.MaxFloatSat:
		return ErrPolicy
	case c.ConfirmationsK < 1 || c.ConfirmationsK > 6:
		return ErrPolicy
	case c.ConflictBlocksN < c.ConfirmationsK || c.ConflictBlocksN > 144:
		return ErrPolicy
	case c.ReadRatePerHour < 1 || c.ReadRatePerHour > 3600:
		return ErrPolicy
	case c.JournalSpendCapacity < c.MaxDayCount+64 || c.JournalSpendCapacity > 1<<20:
		return ErrPolicy
	}
	return nil
}

// ValidateG2PayParameters validates operator inputs. It returns the error of
// the frozen ValidateG2PayIdentityDomain(p) first (every UID and GID outside
// G2ReservedID, ServiceUID != AgentUID, the strict agent user name, the two
// absolute paths), then its own checks: a chain pin error is ErrNetwork; every
// group, key, fee-rate, wallet-name, port, node-datadir or ceiling error is
// ErrPolicy. It is pure: it reads no account database. The account binding is
// checked on the target host by RunG2HostFlow.
func ValidateG2PayParameters(p G2PayParameters) error {
	if e := ValidateG2PayIdentityDomain(p); e != nil {
		return e
	}
	if !g2Pins(p.Network, p.Genesis) {
		return ErrNetwork
	}
	switch {
	case p.AgentSocketGID == p.OperatorGID:
		// The agent's socket group never opens the operator status socket.
		return ErrPolicy
	case !g2NodeDatadir(p.NodeDataDir):
		return ErrPolicy
	case !xOnlyKey(p.Grantee), !xOnlyKey(p.ReceiptPubkey), p.Grantee == p.ReceiptPubkey:
		// The executor's receipt key is never the agent's action key.
		return ErrPolicy
	case p.FeeRateSatVB < 100 || p.FeeRateSatVB > 1000:
		return ErrPolicy
	case !g2WalletName(p.HotWalletName), p.NodeRPCPort == 0:
		return ErrPolicy
	}
	return validateG2Operator(p.G2)
}

// g2NodeDatadir keeps the own node's datadir out of the service-owned roots
// and the runtime tree, the same rule ValidateG2CustodyLaunchSpec applies to
// the cookie and wallet.dat, and short enough that both derived paths stay
// valid custody targets. ValidateG2PayIdentityDomain already requires an
// absolute, clean path.
func g2NodeDatadir(d string) bool {
	under := func(root string) bool { return d == root || strings.HasPrefix(d, root+"/") }
	return len(d) <= 1024 && !under(g2StateRoot) && !under("/etc/swarma") && !under("/run")
}

// g2WalletName: a Core wallet directory name that cannot leave the wallets
// directory and is never the unnamed default wallet.
func g2WalletName(s string) bool {
	if !label(s) || s[0] == '.' || s[0] == '-' {
		return false
	}
	return strings.ToLower(s) == s
}

// g2Chain returns the Core datadir subdirectory of the pinned chain.
func g2Chain(network string) string {
	if network == "regtest" {
		return "regtest/"
	}
	return ""
}

// G2NodeCustodyPaths returns the node cookie and wallet.dat paths that the T18
// spec denies, under the given node datadir. Namecoin Core keeps both under
// <datadir>[/regtest]; named wallets live in <...>/wallets/<name>/.
func G2NodeCustodyPaths(network, datadir, wallet string) (cookie, walletDat string) {
	base := strings.TrimSuffix(datadir, "/") + "/" + g2Chain(network)
	return base + ".cookie", base + "wallets/" + wallet + "/wallet.dat"
}

// Same member order as agent-wallet ActionClientConfig.
type g2ClientFile struct {
	Network    string `json:"network"`
	Genesis    string `json:"genesis"`
	Version    int    `json:"version"`
	Service    string `json:"service"`
	Socket     string `json:"socket"`
	ServiceUID uint32 `json:"service_uid"`
	ReceiptKey string `json:"receipt_key"`
	KeyFile    string `json:"key_file"`
}

// g2CustodySpec is the T18 spec of validated parameters: the fixed private
// set (with the status socket directory), then the node cookie and wallet.dat
// under the own node's datadir, the node RPC port and the agent's socket.
func g2CustodySpec(p G2PayParameters) CustodySpecV1 {
	cookie, walletDat := G2NodeCustodyPaths(p.Network, p.NodeDataDir, p.HotWalletName)
	denied := append(append([]string{}, g2DeniedFixed...), cookie, walletDat)
	return CustodySpecV1{Version: 1, AgentUID: p.AgentUID, ServiceUID: p.ServiceUID, DeniedReads: denied, DeniedRPC: []string{g2RPCTarget(p.NodeRPCPort)}, AllowedSocket: g2WalletSocket}
}

// RenderG2PayTemplates renders exactly the G2File* set from validated
// parameters. The output is deterministic, has no placeholder and never
// contains a credential: RPC users are named by route, and rpcauth lines are
// added by the operator. It is pure; the rendered sysusers.conf is applied
// only through RunG2HostFlow on the target host.
func RenderG2PayTemplates(p G2PayParameters) (map[string][]byte, error) {
	if e := ValidateG2PayParameters(p); e != nil {
		return nil, e
	}
	agent, e := G2AgentSysusers(p)
	if e != nil {
		return nil, e
	}
	operator := p.G2
	service, e := json.Marshal(walletServiceConfig{Network: p.Network, Genesis: p.Genesis, Version: 1, Service: "wallet.nmc", Socket: g2WalletSocket, SocketGID: p.AgentSocketGID, PeerUID: p.AgentUID, Grantee: p.Grantee, SkewSeconds: 60, TimeoutSeconds: 30, StateDir: g2StateDir, WalletConfig: g2WalletConfig, ReceiptKeyFile: g2ReceiptKey, G2: &operator})
	if e != nil {
		return nil, ErrPolicy
	}
	client, e := json.Marshal(g2ClientFile{Network: p.Network, Genesis: p.Genesis, Version: 1, Service: "wallet.nmc", Socket: g2WalletSocket, ServiceUID: p.ServiceUID, ReceiptKey: p.ReceiptPubkey, KeyFile: p.AgentKeyFile})
	if e != nil {
		return nil, ErrPolicy
	}
	spec, e := json.Marshal(g2CustodySpec(p))
	if e != nil {
		return nil, ErrPolicy
	}
	return map[string][]byte{
		G2FileServiceConfig: append(service, '\n'),
		G2FileClientConfig:  append(client, '\n'),
		G2FileSysusers:      g2Sysusers(p, agent),
		G2FileTmpfiles:      g2Tmpfiles(),
		G2FileRPCWhitelist:  g2NodeConf(p),
		G2FileCustodySpec:   append(spec, '\n'),
	}, nil
}

// ParseG2PayParameters decodes the canonical parameters file (exact
// json.Marshal bytes, unique keys, no unknown members) and validates it.
func ParseG2PayParameters(raw []byte) (G2PayParameters, error) {
	var p G2PayParameters
	if len(raw) == 0 || len(raw) > 1<<16 {
		return p, ErrPolicy
	}
	if bytes.Contains(raw, []byte("PLACEHOLDER")) {
		return p, ErrPlaceholder
	}
	if e := serviceDecode(raw, &p, true); e != nil {
		return G2PayParameters{}, e
	}
	if e := ValidateG2PayParameters(p); e != nil {
		return G2PayParameters{}, e
	}
	return p, nil
}

func g2RPCTarget(port uint16) string { return "127.0.0.1:" + strconv.Itoa(int(port)) }

// g2Sysusers renders the provisioning input. The service account carries its
// numeric UID; it is in the agent socket group (it owns wallet.sock) and in the
// operator group (it gives status.sock that group, amendment 1, A8). The agent
// lines are G2AgentSysusers(p) verbatim. No operator account is rendered: the
// operator's only G2 group is swarma-wallet-status, added by the owner, and
// it is never a member of swarma-wallet-peer.
func g2Sysusers(p G2PayParameters, agent string) []byte {
	var b strings.Builder
	b.WriteString("# G2 pay provisioning input (rendered). Apply it only through deploy-kit g2-host-flow on the target host:\n")
	b.WriteString("# preflight, then systemd-sysusers, then the required post-apply account check, and only then activation.\n")
	b.WriteString("# The agent user joins only " + G2AgentSocketGroup + ". The operator is never in " + G2AgentSocketGroup + "; its only G2 group is " + G2OperatorGroup + ".\n")
	b.WriteString("u " + g2ServiceUser + " " + strconv.FormatUint(uint64(p.ServiceUID), 10) + " \"Swarma G2 pay executor\" /var/lib/swarma-wallet /usr/sbin/nologin\n")
	b.WriteString("g " + G2AgentSocketGroup + " " + strconv.FormatUint(uint64(p.AgentSocketGID), 10) + "\n")
	b.WriteString("g " + G2OperatorGroup + " " + strconv.FormatUint(uint64(p.OperatorGID), 10) + "\n")
	b.WriteString("m " + g2ServiceUser + " " + G2AgentSocketGroup + "\n")
	b.WriteString("m " + g2ServiceUser + " " + G2OperatorGroup + "\n")
	b.WriteString(agent)
	return []byte(b.String())
}

func g2Tmpfiles() []byte {
	return []byte(`# G2 pay private roots (rendered). Run only during separately authorized host provisioning.
# /run/swarma-wallet is created by the unit (RuntimeDirectoryMode=0750, group swarma-wallet-peer); it holds only wallet.sock.
# /run/swarma-wallet-status holds only the operator status socket and is never bound into a slot.
d /etc/swarma/wallet 0750 root swarma-wallet -
d /var/lib/swarma-wallet 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/service 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/wallet 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/kernel 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/objects 0700 swarma-wallet swarma-wallet -
d ` + G2StatusSocketDir + ` 0750 swarma-wallet ` + G2OperatorGroup + ` -
`)
}

// g2NodeConf renders the own-node RPC policy. Every option sits in the
// pinned chain's section, so it cannot apply to another chain.
func g2NodeConf(p G2PayParameters) []byte {
	var b strings.Builder
	section := "main"
	if p.Network == "regtest" {
		section = "regtest"
	}
	b.WriteString("# G2 pay own-node RPC policy (rendered). Root merges it into the node config.\n")
	b.WriteString("# rpcauth lines for the three routes are added by the operator; no credential is rendered here.\n")
	b.WriteString("chain=" + section + "\n[" + section + "]\n")
	b.WriteString("server=1\nlisten=0\ntxindex=1\n")
	b.WriteString("rpcbind=127.0.0.1\nrpcallowip=127.0.0.1/32\nrpcport=" + strconv.Itoa(int(p.NodeRPCPort)) + "\n")
	b.WriteString("rpcwhitelistdefault=0\n")
	for _, route := range g2RPCWhitelist {
		b.WriteString("rpcwhitelist=" + route[0] + ":" + route[1] + "\n")
	}
	b.WriteString("wallet=" + p.HotWalletName + "\n")
	return []byte(b.String())
}

// CustodySpecSHA256 is the hex SHA-256 of the canonical (json.Marshal) spec.
func CustodySpecSHA256(spec CustodySpecV1) string {
	b, _ := json.Marshal(spec)
	return digest(b)
}

// ParseCustodySpec decodes canonical spec bytes and validates their shape.
// Unresolved placeholders refuse ErrPlaceholder.
func ParseCustodySpec(raw []byte) (CustodySpecV1, error) {
	var s CustodySpecV1
	if bytes.Contains(raw, []byte("PLACEHOLDER")) {
		return s, ErrPlaceholder
	}
	if e := serviceDecode(raw, &s, true); e != nil {
		return CustodySpecV1{}, e
	}
	if e := validCustodySpec(s); e != nil {
		return CustodySpecV1{}, e
	}
	return s, nil
}

func custodyPath(p string) bool {
	return len(p) > 1 && len(p) <= 4096 && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\n")
}

// loopbackTarget accepts exactly "127.0.0.1:<1..65535>" in canonical decimal.
func loopbackTarget(s string) bool {
	port, ok := strings.CutPrefix(s, "127.0.0.1:")
	n, e := strconv.ParseUint(port, 10, 16)
	return ok && e == nil && n > 0 && strconv.FormatUint(n, 10) == port
}

// validCustodySpec checks the spec shape. It does not require the launch
// path set; ValidateG2CustodyLaunchSpec adds that for the launch packet.
func validCustodySpec(s CustodySpecV1) error {
	if s.Version != 1 || G2ReservedID(s.AgentUID) || G2ReservedID(s.ServiceUID) || s.AgentUID == s.ServiceUID {
		return ErrPolicy
	}
	if len(s.DeniedReads) < 1 || len(s.DeniedReads) > 32 || len(s.DeniedRPC) < 1 || len(s.DeniedRPC) > 8 || !custodyPath(s.AllowedSocket) {
		return ErrPolicy
	}
	seen := map[string]bool{s.AllowedSocket: true}
	for _, p := range s.DeniedReads {
		if !custodyPath(p) || seen[p] {
			return ErrPolicy
		}
		seen[p] = true
	}
	for _, t := range s.DeniedRPC {
		if !loopbackTarget(t) || seen[t] {
			return ErrPolicy
		}
		seen[t] = true
	}
	return nil
}

// ValidateG2CustodyLaunchSpec additionally requires the launch layout that
// RenderG2PayTemplates produces: the fixed private set in order, then exactly
// the node cookie and a wallet.dat, one node RPC port, and the wallet socket.
// A trimmed spec cannot stand in for T18 evidence.
func ValidateG2CustodyLaunchSpec(s CustodySpecV1) error {
	if e := validCustodySpec(s); e != nil {
		return e
	}
	n := len(g2DeniedFixed)
	if len(s.DeniedReads) != n+2 || len(s.DeniedRPC) != 1 || s.AllowedSocket != g2WalletSocket {
		return ErrPolicy
	}
	for i, p := range g2DeniedFixed {
		if s.DeniedReads[i] != p {
			return ErrPolicy
		}
	}
	cookie, wallet := s.DeniedReads[n], s.DeniedReads[n+1]
	if filepath.Base(cookie) != ".cookie" || filepath.Base(wallet) != "wallet.dat" || filepath.Base(filepath.Dir(filepath.Dir(wallet))) != "wallets" || filepath.Dir(filepath.Dir(filepath.Dir(wallet))) != filepath.Dir(cookie) {
		return ErrPolicy
	}
	for _, p := range []string{cookie, wallet} {
		if p == g2StateRoot || strings.HasPrefix(p, g2StateRoot+"/") || strings.HasPrefix(p, "/etc/swarma/") || strings.HasPrefix(p, "/run/") {
			return ErrPolicy
		}
	}
	return nil
}

// Bounded observation codes of CustodyProbeV1.Observed.
const (
	obsEACCES    = "EACCES"
	obsEPERM     = "EPERM"
	obsENOENT    = "ENOENT"
	obsReadOK    = "READ_OK"
	obsHTTP401   = "HTTP_401"
	obsHTTP403   = "HTTP_403"
	obsHTTPOK    = "HTTP_OK"
	obsRefused   = "REFUSED"
	obsConnected = "CONNECTED"
)

// custodyPass is the single pass rule; VerifyCustodyReport recomputes it
// and never trusts a reported Pass bit. A missing path (ENOENT) proves
// nothing and never passes a denied probe.
func custodyPass(kind, observed string) bool {
	switch kind {
	case "read":
		return observed == obsEACCES || observed == obsEPERM
	case "rpc":
		return observed == obsHTTP401 || observed == obsHTTP403 || observed == obsRefused
	case "socket":
		return observed == obsConnected
	}
	return false
}

func knownObservation(kind, observed string) bool {
	switch kind {
	case "read":
		return observed == obsEACCES || observed == obsEPERM || observed == obsENOENT || observed == obsReadOK
	case "rpc":
		return observed == obsHTTP401 || observed == obsHTTP403 || observed == obsHTTPOK || observed == obsRefused
	case "socket":
		return observed == obsConnected || observed == obsEACCES || observed == obsEPERM || observed == obsENOENT || observed == obsRefused
	}
	return false
}

type custodyTarget struct{ kind, target, expect string }

func custodyTargets(s CustodySpecV1) []custodyTarget {
	var out []custodyTarget
	for _, p := range s.DeniedReads {
		out = append(out, custodyTarget{"read", p, "denied"})
	}
	for _, t := range s.DeniedRPC {
		out = append(out, custodyTarget{"rpc", t, "denied"})
	}
	return append(out, custodyTarget{"socket", s.AllowedSocket, "allowed"})
}

// errnoCode maps the three filesystem errnos the contract names. Any other
// error is unclassifiable and aborts the probe (fail closed).
func errnoCode(e error) (string, bool) {
	switch {
	case errors.Is(e, syscall.EACCES):
		return obsEACCES, true
	case errors.Is(e, syscall.EPERM):
		return obsEPERM, true
	case errors.Is(e, syscall.ENOENT):
		return obsENOENT, true
	}
	return "", false
}

// probeRead observes one denied-read target. A denied open or read is only
// half the evidence: a directory that the agent may search but not list (x
// without r, as in mode 0711 for others) still hands out every child whose
// name is known, such as a journal. So the denial counts only when traversal
// into the target is denied too, and a searchable target is READ_OK: its
// contents are readable by name. An unlistable directory cannot be proven
// private child by child, so it fails even if every known child is private.
func probeRead(path string) (string, error) {
	observed, e := probeContent(path)
	if e != nil || observed != obsEACCES && observed != obsEPERM {
		return observed, e
	}
	searchable, e := probeSearch(path)
	if e != nil {
		return "", e
	}
	if searchable {
		observed = obsReadOK
	}
	return observed, nil
}

// probeSearch resolves "<path>/.", which needs search permission on the
// target itself and on every parent. Success means the agent can traverse the
// target. EACCES or EPERM means traversal is denied. ENOTDIR means the target
// exists and is not a directory, so the content denial above is complete. Any
// other result (including ENOENT after a denied open) aborts the probe.
func probeSearch(path string) (bool, error) {
	var st syscall.Stat_t
	e := syscall.Stat(path+"/.", &st)
	switch {
	case e == nil:
		return true, nil
	case errors.Is(e, syscall.EACCES), errors.Is(e, syscall.EPERM), errors.Is(e, syscall.ENOTDIR):
		return false, nil
	}
	return false, ErrCustody
}

// probeContent opens the path read-only (non-blocking, so a FIFO cannot hang
// the probe) and reads one byte or one directory entry.
func probeContent(path string) (string, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		if code, ok := errnoCode(e); ok {
			return code, nil
		}
		return "", ErrCustody
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return "", ErrCustody
	}
	if info.IsDir() {
		_, e = f.ReadDir(1)
	} else {
		var one [1]byte
		_, e = f.Read(one[:])
	}
	if e != nil && e != io.EOF {
		if code, ok := errnoCode(e); ok {
			return code, nil
		}
		return "", ErrCustody
	}
	return obsReadOK, nil
}

// probeRPC sends one credential-less JSON-RPC call over loopback. 401/403 is
// a refusal; any other HTTP status means the call was not refused (HTTP_OK).
// Connection refused is REFUSED; any other transport error aborts.
func probeRPC(ctx context.Context, target string) (string, error) {
	body := []byte(`{"jsonrpc":"1.0","id":"t18","method":"getblockchaininfo","params":[]}`)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+target+"/", bytes.NewReader(body))
	if e != nil {
		return "", ErrCustody
	}
	req.Header.Set("Content-Type", "text/plain")
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, e := client.Do(req)
	if e != nil {
		if errors.Is(e, syscall.ECONNREFUSED) {
			return obsRefused, nil
		}
		return "", ErrCustody
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return obsHTTP401, nil
	case http.StatusForbidden:
		return obsHTTP403, nil
	}
	return obsHTTPOK, nil
}

// probeSocket connects to the agent's own socket and closes it without
// sending a frame, so the service admits nothing.
func probeSocket(ctx context.Context, path string) (string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		if errors.Is(e, syscall.ECONNREFUSED) {
			return obsRefused, nil
		}
		if code, ok := errnoCode(e); ok {
			return code, nil
		}
		return "", ErrCustody
	}
	c.Close()
	return obsConnected, nil
}

// RunCustodyProbe runs T18 as the agent UID. It refuses a malformed spec
// (ErrPolicy) and any process whose real and effective UID is not
// spec.AgentUID, or is spec.ServiceUID (ErrCustody). A completed run returns a
// report even when probes fail; the report's Pass is false then.
func RunCustodyProbe(ctx context.Context, spec CustodySpecV1) (CustodyReportV1, error) {
	if e := validCustodySpec(spec); e != nil {
		return CustodyReportV1{}, e
	}
	uid, euid := os.Getuid(), os.Geteuid()
	if uid < 0 || uid != euid || uint64(uid) != uint64(spec.AgentUID) || uint64(uid) == uint64(spec.ServiceUID) {
		return CustodyReportV1{}, ErrCustody
	}
	r := CustodyReportV1{Version: 1, SpecSHA256: CustodySpecSHA256(spec), UID: uint32(uid), GID: uint32(os.Getgid()), Pass: true}
	for _, t := range custodyTargets(spec) {
		if ctx.Err() != nil {
			return CustodyReportV1{}, ErrCustody
		}
		var observed string
		var e error
		switch t.kind {
		case "read":
			observed, e = probeRead(t.target)
		case "rpc":
			observed, e = probeRPC(ctx, t.target)
		default:
			observed, e = probeSocket(ctx, t.target)
		}
		if e != nil {
			return CustodyReportV1{}, e
		}
		pass := custodyPass(t.kind, observed)
		r.Probes = append(r.Probes, CustodyProbeV1{Kind: t.kind, Target: t.target, Expect: t.expect, Observed: observed, Pass: pass})
		r.Pass = r.Pass && pass
	}
	return r, nil
}

// VerifyCustodyReport accepts only a report that ran as spec.AgentUID (never
// the service UID), binds SHA256(canonical spec), has exactly one probe per
// target in spec order, and passes every probe under the recomputed rule.
func VerifyCustodyReport(spec CustodySpecV1, report CustodyReportV1) error {
	if e := validCustodySpec(spec); e != nil {
		return e
	}
	if report.Version != 1 || report.UID != spec.AgentUID || report.UID == spec.ServiceUID || report.SpecSHA256 != CustodySpecSHA256(spec) || !report.Pass {
		return ErrCustody
	}
	targets := custodyTargets(spec)
	if len(report.Probes) != len(targets) {
		return ErrCustody
	}
	for i, t := range targets {
		p := report.Probes[i]
		if p.Kind != t.kind || p.Target != t.target || p.Expect != t.expect || !knownObservation(p.Kind, p.Observed) {
			return ErrCustody
		}
		if pass := custodyPass(p.Kind, p.Observed); !pass || p.Pass != pass {
			return ErrCustody
		}
	}
	return nil
}

// G2HostSteps are the two host actions of the target-host provisioning flow.
// The caller supplies them; RunG2HostFlow alone decides whether they run.
type G2HostSteps struct {
	// Apply gives the rendered sysusers.conf to systemd-sysusers. Its success
	// is no evidence about the result: sysusers substitutes a free UID on a
	// collision and keeps an existing name at its UID, both with exit 0.
	Apply func(sysusers []byte) error
	// Activate starts the G2 services (agent-walletd, then the slot). T18
	// runs after it.
	Activate func() error
}

// RunG2HostFlow is the target-host provisioning order of freeze amendment 1
// (A3), run on the TARGET host with that host's account database:
//
//  1. render (pure: ValidateG2PayParameters, no account lookup);
//  2. the preflight ValidateG2PayIdentity(p, db);
//  3. steps.Apply with the sysusers.conf rendered from the same p;
//  4. the REQUIRED VerifyG2AgentAccount(p, db);
//  5. only then steps.Activate.
//
// A failed step stops the flow before the next one; in particular nothing is
// activated unless the post-apply check passed. Missing steps refuse ErrInput
// before anything runs. The error names the step and wraps its cause.
func RunG2HostFlow(p G2PayParameters, db G2AccountDB, steps G2HostSteps) error {
	if steps.Apply == nil || steps.Activate == nil {
		return ErrInput
	}
	files, e := RenderG2PayTemplates(p)
	if e != nil {
		return fmt.Errorf("g2 host flow: render: %w", e)
	}
	if e := ValidateG2PayIdentity(p, db); e != nil {
		return fmt.Errorf("g2 host flow: preflight: %w", e)
	}
	if e := steps.Apply(files[G2FileSysusers]); e != nil {
		return fmt.Errorf("g2 host flow: sysusers apply: %w", e)
	}
	if e := VerifyG2AgentAccount(p, db); e != nil {
		return fmt.Errorf("g2 host flow: post-apply account check: %w", e)
	}
	if e := steps.Activate(); e != nil {
		return fmt.Errorf("g2 host flow: activation: %w", e)
	}
	return nil
}

// g2DeclaredPrimaryGID reads the agent's own primary GID from its sysusers
// declaration decl (the output of G2AgentSysusers), with systemd-sysusers'
// rule for the ID field of a "u" line: "UID" creates the account's own group
// at the same number, "UID:GID" names that number. It refuses ErrPolicy unless
// decl has exactly one "u <user> ..." line, its UID is uid and its GID part is
// a canonical decimal (a group name cannot be resolved without the target
// host's database, so it is never assumed).
func g2DeclaredPrimaryGID(decl, user string, uid uint32) (uint32, error) {
	var id string
	n := 0
	for _, line := range strings.Split(decl, "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "u" && f[1] == user {
			id, n = f[2], n+1
		}
	}
	if n != 1 {
		return 0, ErrPolicy
	}
	uidText, gidText, named := strings.Cut(id, ":")
	if !named {
		gidText = uidText
	}
	parse := func(s string) (uint32, bool) {
		v, e := strconv.ParseUint(s, 10, 32)
		return uint32(v), e == nil && strconv.FormatUint(v, 10) == s
	}
	if v, ok := parse(uidText); !ok || v != uid {
		return 0, ErrPolicy
	}
	gid, ok := parse(gidText)
	if !ok {
		return 0, ErrPolicy
	}
	return gid, nil
}

// G2AgentSlotGIDs derives the two GIDs the agent's slot credentials carry
// (R9, as adopted). The slot runs the payload with User= and Group= set to
// the agent account, and systemd applies the account's group list through
// initgroups, so the agent runs with exactly its own primary group and
// swarma-wallet-peer (AgentSocketGID). The primary GID is derived from the
// agent's own declaration, G2AgentSysusers(p), never from a fixed number.
//
// It refuses with ValidateG2PayParameters' error, and with ErrPolicy when the
// derived primary GID is a G2ReservedID or equals AgentSocketGID, OperatorGID
// or the service group's GID (ServiceUID): sysusers would then give the
// account's own group another number, so no readback could be bound to the
// declaration.
func G2AgentSlotGIDs(p G2PayParameters) (primary, socket uint32, err error) {
	if e := ValidateG2PayParameters(p); e != nil {
		return 0, 0, e
	}
	decl, e := G2AgentSysusers(p)
	if e != nil {
		return 0, 0, e
	}
	primary, e = g2DeclaredPrimaryGID(decl, p.AgentUser, p.AgentUID)
	if e != nil {
		return 0, 0, e
	}
	if G2ReservedID(primary) || primary == p.AgentSocketGID || primary == p.OperatorGID || primary == p.ServiceUID {
		return 0, 0, ErrPolicy
	}
	return primary, p.AgentSocketGID, nil
}

// CheckG2AgentGroups is the T18 credential readback rule. readback is the
// GID list `id -G` prints for the running agent; it must be exactly the set
// {primary, socket} of G2AgentSlotGIDs(p): both present and nothing else, so
// OperatorGID (never one of the two) is refused like any other extra group.
// Order does not matter, and a repeated GID is not an extra group. It
// refuses with G2AgentSlotGIDs' error, otherwise ErrPolicy.
func CheckG2AgentGroups(p G2PayParameters, readback []uint32) error {
	primary, socket, e := G2AgentSlotGIDs(p)
	if e != nil {
		return e
	}
	hasPrimary, hasSocket := false, false
	for _, g := range readback {
		switch g {
		case primary:
			hasPrimary = true
		case socket:
			hasSocket = true
		default:
			return ErrPolicy // a third group, the operator group included
		}
	}
	if !hasPrimary || !hasSocket {
		return ErrPolicy
	}
	return nil
}

// g2ReadbackGID parses one GID as `id` prints it: a canonical decimal in the
// uint32 range. Anything else, the empty string of a failed or missing
// readback included, refuses ErrInput.
func g2ReadbackGID(s string) (uint32, error) {
	v, e := strconv.ParseUint(s, 10, 32)
	if e != nil || strconv.FormatUint(v, 10) != s {
		return 0, ErrInput
	}
	return uint32(v), nil
}

// CheckG2AgentCredentials is the complete T18 credential readback, applied
// before any probe or request. gid is what the running agent's `id -g`
// printed (its effective primary GID), groups one entry per GID of its
// `id -G`. Both are the OBSERVED values, never values derived from p.
//
// The observed primary GID must equal the primary GID of G2AgentSlotGIDs(p),
// the one the agent's own sysusers declaration names. The unordered set rule
// of CheckG2AgentGroups cannot establish that: swapping the roles (primary
// agent_socket_gid, the agent's own group supplementary) keeps exactly the
// same two-GID set. groups must then pass CheckG2AgentGroups unchanged.
//
// It refuses with G2AgentSlotGIDs' error; ErrInput when gid is missing or any
// GID is not a canonical decimal; ErrPolicy when the observed primary GID is
// not the declared one or the set rule refuses.
func CheckG2AgentCredentials(p G2PayParameters, gid string, groups []string) error {
	primary, _, e := G2AgentSlotGIDs(p)
	if e != nil {
		return e
	}
	observed, e := g2ReadbackGID(gid)
	if e != nil {
		return e
	}
	readback := make([]uint32, 0, len(groups))
	for _, s := range groups {
		g, e := g2ReadbackGID(s)
		if e != nil {
			return e
		}
		readback = append(readback, g)
	}
	if observed != primary {
		return ErrPolicy // a swapped role, or the primary is another group
	}
	return CheckG2AgentGroups(p, readback)
}
