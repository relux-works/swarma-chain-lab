package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

var errConfig = errors.New("CONFIG_REFUSED")
var errMode = errors.New("TEST_MODE_REQUIRED")

type serveConfig struct {
	Version       int               `json:"version"`
	Mode          string            `json:"mode"`
	AgentKeyFile  string            `json:"agent_key_file"`
	AgentPubkey   string            `json:"agent_pubkey"`
	RelayURL      string            `json:"relay_url"`
	RelayAuth     string            `json:"relay_auth,omitempty"`
	JournalDir    string            `json:"journal_dir"`
	StationSocket string            `json:"station_socket"`
	Screening     string            `json:"screening"`
	Kernel        kernelConfig      `json:"kernel"`
	Exchange      exchangeConfig    `json:"exchange"`
	Station       stationConfig     `json:"station"`
	ModelProxy    *modelProxyConfig `json:"model_proxy,omitempty"`
}
type kernelConfig struct {
	Kind         string `json:"kind"`
	StubVerdict  string `json:"stub_verdict"`
	Network      string `json:"network"`
	Genesis      string `json:"genesis"`
	AgentName    string `json:"agent_name"`
	LandlordName string `json:"landlord_name"`
	IssuerPubkey string `json:"issuer_pubkey"`
	SealScript   string `json:"seal_script"`
	StateDir     string `json:"state_dir"`
	RPCHost      string `json:"rpc_host"`
	RPCPort      int    `json:"rpc_port"`
	RPCRouteFile string `json:"rpc_route_file"`
}
type exchangeConfig struct {
	BookingVersion    int             `json:"booking_version"`
	PaymentCoins      []exchange.Coin `json:"payment_coins"`
	StateDir          string          `json:"state_dir"`
	BookingURL        string          `json:"booking_url"`
	PresentationsDir  string          `json:"presentations_dir"`
	PrivacySHA256     string          `json:"privacy_sha256"`
	TemplateSHA256    string          `json:"template_sha256"`
	ProfileSHA256     string          `json:"profile_sha256"`
	PowBits           int             `json:"pow_bits"`
	MaxClients        int             `json:"max_clients"`
	QueueSize         int             `json:"queue_size"`
	Burst             int             `json:"burst"`
	MaxReplay         int             `json:"max_replay"`
	RefillSeconds     int64           `json:"refill_seconds"`
	KnownSeconds      int64           `json:"known_seconds"`
	MessageAgeSeconds int64           `json:"message_age_seconds"`
	PollMilliseconds  int64           `json:"poll_milliseconds"`
	CallMilliseconds  int64           `json:"call_milliseconds"`
}
type stationConfig struct {
	Driver    string         `json:"driver"`
	Root      string         `json:"root"`
	StubAgent bool           `json:"stub_agent"`
	Manager   *managerConfig `json:"manager,omitempty"`
}

type managerConfig struct {
	StateDir          string           `json:"state_dir"`
	PayloadID         string           `json:"payload_id"`
	PayloadSHA256     string           `json:"payload_sha256"`
	SlotMin           int              `json:"slot_min"`
	SlotMax           int              `json:"slot_max"`
	StartMilliseconds int64            `json:"start_milliseconds"`
	Listen            string           `json:"listen"`
	PayloadListen     string           `json:"payload_listen"`
	TLS               gatewayTLSConfig `json:"tls"`
}

func listenAddress(s string) bool {
	h, p, e := net.SplitHostPort(s)
	ip := net.ParseIP(h)
	n, ne := strconv.Atoi(p)
	return e == nil && ne == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == p && ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() == h
}

func (c serveConfig) stationStateDir() string {
	if c.Station.Manager != nil {
		return c.Station.Manager.StateDir
	}
	return c.Station.Root
}

func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// Public pins reject repeated-byte placeholders. Keep digest's identifier
// syntax separate: booking IDs are not assertions of an external object's hash.
func pinDigest(s string) bool {
	if !digest(s) {
		return false
	}
	for i := 2; i < len(s); i += 2 {
		if s[i:i+2] != s[:2] {
			return true
		}
	}
	return false // repeated-byte pin
}
func absPath(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && s != "/" && !strings.ContainsAny(s, "\x00\r\n")
}
func namePin(s string) bool {
	if !strings.HasPrefix(s, "id/") || len(s) < 4 || len(s) > 160 {
		return false
	}
	for _, r := range s[3:] {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._", r)) {
			return false
		}
	}
	return true
}
func loopURL(s, scheme string) bool {
	u, e := url.Parse(s)
	if e != nil || u.Scheme != scheme || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return false
	}
	host, port, e := net.SplitHostPort(u.Host)
	ip := net.ParseIP(host)
	p, pe := strconv.Atoi(port)
	return e == nil && ip != nil && ip.IsLoopback() && pe == nil && p > 0 && p <= 65535 && u.String() == s
}
func (c serveConfig) validate(allowTest bool) error {
	if c.Version != 1 || (c.Mode != "regtest" && c.Mode != "test") || c.Kernel.Network != "regtest" || c.Kernel.Genesis != su.RegtestGenesis {
		return errConfig
	}
	if c.Mode == "test" && !allowTest {
		return errMode
	}
	if c.Mode != "test" && (c.Kernel.Kind != "real" || c.Kernel.StubVerdict != "" || c.Screening != "off" || c.Station.Driver == "local-test" || c.Station.StubAgent) {
		return errMode
	}
	if (c.Kernel.Kind != "real" && c.Kernel.Kind != "stub") || (c.Kernel.Kind == "real" && c.Kernel.StubVerdict != "") || (c.Kernel.Kind == "stub" && c.Kernel.StubVerdict != "live" && c.Kernel.StubVerdict != "pending" && c.Kernel.StubVerdict != "refused") {
		return errConfig
	}
	if c.Screening != "off" && c.Screening != "stub" {
		return errConfig
	}
	if nostr.ParseXOnlyPubKey(c.AgentPubkey) != nil || nostr.ParseXOnlyPubKey(c.Kernel.IssuerPubkey) != nil || !namePin(c.Kernel.AgentName) || !namePin(c.Kernel.LandlordName) || c.Kernel.AgentName == c.Kernel.LandlordName {
		return errConfig
	}
	seal, e := rental.GrantSealScript(c.Kernel.IssuerPubkey)
	if e != nil || seal != c.Kernel.SealScript {
		return errConfig
	}
	ip := net.ParseIP(c.Kernel.RPCHost)
	if ip == nil || !ip.IsLoopback() || c.Kernel.RPCPort < 1 || c.Kernel.RPCPort > 65535 {
		return errConfig
	}
	if !c.ModelProxy.valid() || (c.ModelProxy != nil && c.Station.Driver != "manager") {
		return errConfig
	}
	if !gateway.ValidRelayAuth(c.RelayAuth) {
		return errConfig
	}
	if c.Exchange.BookingVersion == 1 {
		if c.Mode != "test" || !allowTest || len(c.Exchange.PaymentCoins) != 1 || c.Exchange.PaymentCoins[0] != exchange.NMC {
			return errMode
		}
	} else if c.Exchange.BookingVersion != 2 {
		return errConfig
	}
	seenCoins := map[exchange.Coin]bool{}
	if len(c.Exchange.PaymentCoins) < 1 || len(c.Exchange.PaymentCoins) > 3 {
		return errConfig
	}
	for _, coin := range c.Exchange.PaymentCoins {
		if _, e := exchange.ParseCoin(string(coin)); e != nil || seenCoins[coin] {
			return errConfig
		}
		seenCoins[coin] = true
	}
	if !loopURL(c.RelayURL, "ws") || !loopURL(c.Exchange.BookingURL, "http") {
		return errConfig
	}
	if c.Exchange.PrivacySHA256 != booking.Hash([]byte(booking.PrivacyNotice)) || !pinDigest(c.Exchange.TemplateSHA256) || !pinDigest(c.Exchange.ProfileSHA256) {
		return errConfig
	}
	for _, p := range []string{c.AgentKeyFile, c.JournalDir, c.Kernel.StateDir, c.Kernel.RPCRouteFile, c.Exchange.StateDir, c.Exchange.PresentationsDir, c.stationStateDir()} {
		if !absPath(p) {
			return errConfig
		}
	}
	dirs := []string{c.JournalDir, c.Kernel.StateDir, c.Exchange.StateDir, c.Exchange.PresentationsDir, c.stationStateDir()}
	for i, a := range dirs {
		for j, b := range dirs {
			if i != j && (a == b || strings.HasPrefix(a, b+string(filepath.Separator))) {
				return errConfig
			}
		}
	}
	x := c.Exchange
	if x.PowBits < 1 || x.PowBits > 32 || x.MaxClients < 1 || x.MaxClients > 64 || x.QueueSize < 1 || x.QueueSize > 128 || x.Burst < 1 || x.Burst > 64 || x.MaxReplay < x.Burst || x.MaxReplay > 64 || x.RefillSeconds < 1 || x.RefillSeconds > 3600 || x.KnownSeconds < 1 || x.KnownSeconds > 86400 || x.MessageAgeSeconds < 1 || x.MessageAgeSeconds > 600 || x.PollMilliseconds < 10 || x.PollMilliseconds > 60000 || x.CallMilliseconds < 1 || x.CallMilliseconds > 5000 {
		return errConfig
	}
	switch c.Station.Driver {
	case "local-test":
		if c.Mode != "test" || c.Station.Manager != nil || !absPath(c.StationSocket) || len(c.StationSocket) > 100 {
			return errConfig
		}
	case "manager":
		m := c.Station.Manager
		if m == nil || c.Station.Root != "" || c.StationSocket != "" || c.Station.StubAgent {
			return errConfig
		}
		if !pinDigest(m.PayloadSHA256) || len(m.PayloadID) < 1 || len(m.PayloadID) > 64 || m.SlotMin < 0 || m.SlotMax > 9999 || m.SlotMin > m.SlotMax || m.StartMilliseconds < 1 || m.StartMilliseconds > 5000 || !listenAddress(m.Listen) || !listenAddress(m.PayloadListen) || m.Listen == m.PayloadListen {
			return errConfig
		}
		for _, ch := range m.PayloadID {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-_", ch)) {
				return errConfig
			}
		}
		if !pinDigest(m.TLS.CertSHA256) || !pinDigest(m.TLS.ManagerCertSHA256) {
			return errConfig
		}
		for _, p := range []string{m.TLS.CertFile, m.TLS.KeyFile, m.TLS.ManagerCAFile} {
			if !absPath(p) {
				return errConfig
			}
		}
	default:
		return errConfig
	}
	return nil
}
func (c serveConfig) exchangeConfig(backend exchange.Backend, grants exchange.GrantSource) exchange.Config {
	x := c.Exchange
	return exchange.Config{StateDir: x.StateDir, AgentName: c.Kernel.AgentName, LandlordName: c.Kernel.LandlordName, Backend: backend, Grants: grants, PowBits: x.PowBits, MaxClients: x.MaxClients, QueueSize: x.QueueSize, Burst: x.Burst, MaxReplay: x.MaxReplay, RefillSeconds: x.RefillSeconds, KnownSeconds: x.KnownSeconds, MessageAgeSeconds: x.MessageAgeSeconds, PollInterval: time.Duration(x.PollMilliseconds) * time.Millisecond, CallTimeout: time.Duration(x.CallMilliseconds) * time.Millisecond, Now: time.Now}
}

// File boundaries reject symlink leaves and noncanonical parents before opening;
// protected files must also have the exact expected private permission bits.
func readFile(path string, max int64, perm os.FileMode) ([]byte, error) {
	if !absPath(path) {
		return nil, errConfig
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil || parent != filepath.Dir(path) {
		return nil, errConfig
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errConfig
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max || st.Mode().Perm()&0022 != 0 || (perm != 0 && st.Mode().Perm() != perm) {
		return nil, errConfig
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errConfig
	}
	return b, nil
}
func loadConfig(path string, allowTest bool) (serveConfig, error) {
	var c serveConfig
	b, e := readFile(path, 64<<10, 0)
	if e != nil || booking.Strict(b, &c) != nil {
		return c, errConfig
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return c, errConfig
	}
	if v, ok := fields["model_proxy"]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		return c, errConfig
	}
	return c, c.validate(allowTest)
}
