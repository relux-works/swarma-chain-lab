package deploy

// PX1 stream S5 implementation (owner S5): G2 pay deploy parameters, the
// templates/g2-pay render, and the T18 different-UID custody probe. The frozen
// signatures and types live in g2_pay_api.go.
//
// Scope: validation and rendering are pure; nothing here opens credentials,
// provisions users, funds, starts or spends. RunCustodyProbe is the only entry
// point that touches the host, and only as the agent UID: it opens each denied
// path read-only, sends one credential-less JSON-RPC call to each loopback node
// port, and connects (without sending a frame) to the agent's wallet socket.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
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
	g2WalletSocket = "/run/swarma-wallet/wallet.sock"
	g2WalletConfig = "/etc/swarma/wallet/wallet.json"
	g2ReceiptKey   = "/etc/swarma/wallet/receipt.key"
	g2StateRoot    = "/var/lib/swarma-wallet"
	g2StateDir     = "/var/lib/swarma-wallet/service"

	// Values G2PayParameters does not carry (see the S5 freeze-amendment
	// proposal). The operator resolves them after provisioning; until then the
	// rendered client.json and custody-spec.json refuse ErrPlaceholder and the
	// probe refuses the spec.
	G2ServiceUIDPlaceholder   = "PLACEHOLDER_WALLET_UID_INTEGER"
	G2AgentKeyFilePlaceholder = "PLACEHOLDER_AGENT_SIGNING_KEY_ABSOLUTE_PATH"
	G2NodeDataDirPlaceholder  = "PLACEHOLDER_NODE_DATADIR"
	G2AgentUserPlaceholder    = "PLACEHOLDER_AGENT_USER"
)

// Route method sets of the own node (experiments/agent-wallet/README.md, "Use
// separate Core rpcwhitelist entries"). Order is the README order.
var g2RPCWhitelist = [][2]string{
	{"w3-observer", "getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock"},
	{"w1-wallet", "getbalances,getnewaddress,listtransactions,fundrawtransaction,signrawtransactionwithwallet"},
	{"w1-broadcast", "sendrawtransaction"},
}

// g2DeniedFixed is the launch prefix of CustodySpecV1.DeniedReads: the private
// wallet config, the receipt scalar and every service-owned state directory.
// The node cookie and wallet.dat follow (they depend on the node datadir).
var g2DeniedFixed = []string{
	g2WalletConfig,
	g2ReceiptKey,
	g2StateDir,
	"/var/lib/swarma-wallet/wallet",
	"/var/lib/swarma-wallet/kernel",
	"/var/lib/swarma-wallet/objects",
}

// reservedID refuses root, the overflow id (uid_t)-1 and nobody/nogroup.
func reservedID(id uint32) bool { return id == 0 || id == 65534 || id == math.MaxUint32 }

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

// ValidateG2PayParameters validates operator inputs. A chain pin error is
// ErrNetwork; every UID, GID, key, fee-rate, wallet-name, port or ceiling
// error is ErrPolicy.
func ValidateG2PayParameters(p G2PayParameters) error {
	if !g2Pins(p.Network, p.Genesis) {
		return ErrNetwork
	}
	switch {
	case reservedID(p.AgentUID), reservedID(p.AgentSocketGID), reservedID(p.OperatorGID):
		return ErrPolicy
	case p.AgentSocketGID == p.OperatorGID:
		// The agent's socket group never opens the operator status socket.
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

// Same member order as agent-wallet ActionClientConfig; service_uid is a raw
// value so the unresolved placeholder stays a JSON string.
type g2ClientFile struct {
	Network    string          `json:"network"`
	Genesis    string          `json:"genesis"`
	Version    int             `json:"version"`
	Service    string          `json:"service"`
	Socket     string          `json:"socket"`
	ServiceUID json.RawMessage `json:"service_uid"`
	ReceiptKey string          `json:"receipt_key"`
	KeyFile    string          `json:"key_file"`
}

// Same member order as CustodySpecV1, so the resolved bytes are canonical.
type g2CustodyFile struct {
	Version       int             `json:"v"`
	AgentUID      uint32          `json:"agent_uid"`
	ServiceUID    json.RawMessage `json:"service_uid"`
	DeniedReads   []string        `json:"denied_reads"`
	DeniedRPC     []string        `json:"denied_rpc"`
	AllowedSocket string          `json:"allowed_socket"`
}

// RenderG2PayTemplates renders exactly the G2File* set from validated
// parameters. The output is deterministic and never contains a credential:
// RPC users are named by route, and rpcauth lines are added by the operator.
func RenderG2PayTemplates(p G2PayParameters) (map[string][]byte, error) {
	if e := ValidateG2PayParameters(p); e != nil {
		return nil, e
	}
	uidPlaceholder := json.RawMessage(strconv.Quote(G2ServiceUIDPlaceholder))
	operator := p.G2
	service, e := json.Marshal(walletServiceConfig{Network: p.Network, Genesis: p.Genesis, Version: 1, Service: "wallet.nmc", Socket: g2WalletSocket, SocketGID: p.AgentSocketGID, PeerUID: p.AgentUID, Grantee: p.Grantee, SkewSeconds: 60, TimeoutSeconds: 30, StateDir: g2StateDir, WalletConfig: g2WalletConfig, ReceiptKeyFile: g2ReceiptKey, G2: &operator})
	if e != nil {
		return nil, ErrPolicy
	}
	client, e := json.Marshal(g2ClientFile{Network: p.Network, Genesis: p.Genesis, Version: 1, Service: "wallet.nmc", Socket: g2WalletSocket, ServiceUID: uidPlaceholder, ReceiptKey: p.ReceiptPubkey, KeyFile: G2AgentKeyFilePlaceholder})
	if e != nil {
		return nil, ErrPolicy
	}
	cookie, walletDat := G2NodeCustodyPaths(p.Network, G2NodeDataDirPlaceholder, p.HotWalletName)
	denied := append(append([]string{}, g2DeniedFixed...), cookie, walletDat)
	spec, e := json.Marshal(g2CustodyFile{Version: 1, AgentUID: p.AgentUID, ServiceUID: uidPlaceholder, DeniedReads: denied, DeniedRPC: []string{g2RPCTarget(p.NodeRPCPort)}, AllowedSocket: g2WalletSocket})
	if e != nil {
		return nil, ErrPolicy
	}
	return map[string][]byte{
		G2FileServiceConfig: append(service, '\n'),
		G2FileClientConfig:  append(client, '\n'),
		G2FileSysusers:      g2Sysusers(p),
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

func g2Sysusers(p G2PayParameters) []byte {
	var b strings.Builder
	b.WriteString("# G2 pay provisioning input (rendered). Root applies it; the owner pre-provisions on agents1-class hosts.\n")
	b.WriteString("# The agent user (UID " + strconv.FormatUint(uint64(p.AgentUID), 10) + ") joins only swarma-wallet-peer, never swarma-wallet.\n")
	b.WriteString("u swarma-wallet - \"Swarma G2 pay executor\" /var/lib/swarma-wallet /usr/sbin/nologin\n")
	b.WriteString("g swarma-wallet-peer " + strconv.FormatUint(uint64(p.AgentSocketGID), 10) + "\n")
	b.WriteString("g swarma-wallet-status " + strconv.FormatUint(uint64(p.OperatorGID), 10) + "\n")
	b.WriteString("m swarma-wallet swarma-wallet-peer\n")
	b.WriteString("m swarma-wallet swarma-wallet-status\n")
	b.WriteString("m " + G2AgentUserPlaceholder + " swarma-wallet-peer\n")
	return []byte(b.String())
}

func g2Tmpfiles() []byte {
	return []byte(`# G2 pay private roots (rendered). Run only during separately authorized host provisioning.
# /run/swarma-wallet is created by the unit (RuntimeDirectoryMode=0750, group swarma-wallet-peer).
d /etc/swarma/wallet 0750 root swarma-wallet -
d /var/lib/swarma-wallet 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/service 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/wallet 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/kernel 0700 swarma-wallet swarma-wallet -
d /var/lib/swarma-wallet/objects 0700 swarma-wallet swarma-wallet -
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
	if s.Version != 1 || reservedID(s.AgentUID) || reservedID(s.ServiceUID) || s.AgentUID == s.ServiceUID {
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

// probeRead opens the path read-only (non-blocking, so a FIFO cannot hang
// the probe) and reads one byte or one directory entry.
func probeRead(path string) (string, error) {
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
