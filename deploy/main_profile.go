package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

func deploymentNetwork(network, genesis string) bool {
	return network == "main" && genesis == mainGenesis || network == "regtest" && (genesis == "" || genesis == regtestGenesis)
}

// Main needs a native public configuration as well as the descriptor. Every
// nested chain marker must agree; a descriptor cannot relabel regtest bytes.
// Product startup still verifies actual keys, route credentials and node state.
func validateMainInputs(p Policy, inputs [][]byte) error {
	want := 1
	if p.Service == "payload" {
		want = 2
	}
	if len(inputs) != want {
		return ErrPolicy
	}
	for _, raw := range inputs {
		if err := ValidatePublicJSON(raw); err != nil {
			return err
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return ErrPolicy
		}
		var check func(any) error
		check = func(v any) error {
			switch object := v.(type) {
			case map[string]any:
				for key, val := range object {
					if strings.EqualFold(key, "network") && val != "main" {
						return ErrNetwork
					}
					if strings.EqualFold(key, "genesis") && val != mainGenesis {
						return ErrNetwork
					}
					if err := check(val); err != nil {
						return err
					}
				}
			case []any:
				for _, val := range object {
					if err := check(val); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := check(value); err != nil {
			return err
		}
	}
	switch p.Service {
	case "store":
		return validateMainStore(inputs[0])
	case "relay":
		return validateMainRelay(inputs[0])
	case "issuer":
		var c issuerConfig
		if json.Unmarshal(inputs[0], &c) != nil || c.Config.Policy.Policy.Network != "main" || c.Config.Policy.Policy.Genesis != mainGenesis {
			return ErrNetwork
		}
	case "wallet":
		var c walletServiceConfig
		if json.Unmarshal(inputs[0], &c) != nil || c.Network != "main" || c.Genesis != mainGenesis {
			return ErrNetwork
		}
	case "booking":
		return validateMainBooking(inputs[0])
	case "gateway":
		return validateMainGateway(inputs[0])
	}
	return nil
}

type mainBooking struct {
	ServiceVersion int `json:"service_version"`
	Config         struct {
		Network                     string          `json:"network,omitempty"`
		Genesis                     string          `json:"genesis,omitempty"`
		StateDir                    string          `json:"state_dir"`
		AgentPubkey                 string          `json:"agent_pubkey"`
		ProviderPubkey              string          `json:"provider_pubkey"`
		HoldSeconds                 int64           `json:"hold_seconds"`
		MinStartNowRemainingSeconds int64           `json:"min_start_now_remaining_seconds"`
		PriceUSDCents               int64           `json:"price_usd_cents"`
		Template                    bookingTemplate `json:"template"`
		ModelCaps                   *modelCaps      `json:"model_caps,omitempty"`
		TemplateSHA256              string          `json:"template_sha256"`
		Slots                       []struct {
			ID            string `json:"id"`
			StationName   string `json:"station_name"`
			NotBefore     int64  `json:"not_before"`
			NotAfter      int64  `json:"not_after"`
			PaymentPolicy string `json:"payment_policy"`
		} `json:"slots"`
		Coins map[string]struct {
			PublicBranch       string `json:"public_branch"`
			PublicBranchSHA256 string `json:"public_branch_sha256"`
			USDMicrosPerCoin   int64  `json:"usd_micros_per_coin"`
			RateAsOf           int64  `json:"rate_as_of"`
			MaxRateAgeSeconds  int64  `json:"max_rate_age_seconds"`
			MinConfirmations   int64  `json:"min_confirmations"`
		} `json:"coins"`
		Limits paymentLimits `json:"limits"`
	} `json:"config"`
	PaymentRouteFiles map[string]string `json:"payment_route_files"`
}

func validateMainBooking(raw []byte) error {
	var b mainBooking
	if err := serviceDecode(raw, &b, false); err != nil {
		return err
	}
	c := b.Config
	if b.ServiceVersion != 2 || c.Network != "main" || c.Genesis != mainGenesis {
		return ErrNetwork
	}
	if c.StateDir != "/var/lib/swarma-booking" || !digestPin(c.AgentPubkey) || !digestPin(c.ProviderPubkey) || c.HoldSeconds < 1200 || c.HoldSeconds > 1800 || c.MinStartNowRemainingSeconds < 1 || c.MinStartNowRemainingSeconds > 3600 || c.PriceUSDCents < 1 || !templateCapsMatch(c.Template, c.ModelCaps) || !label(c.Template.ID) || !label(c.Template.ProfileID) || !label(c.Template.ProfileVersion) || !digestPin(c.Template.ProfileSHA256) || !digestPin(c.TemplateSHA256) || c.Template.BudgetSat < 1 || c.Template.BudgetSat > maxMoney || len(c.Template.Allowed) == 0 || len(c.Template.Forbidden) == 0 || len(c.Slots) < 1 || len(c.Slots) > 1000 || len(c.Coins) != 1 || len(b.PaymentRouteFiles) != 1 || b.PaymentRouteFiles["nmc"] != "/etc/swarma/booking/payment-nmc.json" {
		return ErrPolicy
	}
	coin, ok := c.Coins["nmc"]
	branchHash := sha256.Sum256([]byte(coin.PublicBranch))
	if !ok || !strings.HasPrefix(coin.PublicBranch, "xpub") || coin.PublicBranchSHA256 != hex.EncodeToString(branchHash[:]) || coin.USDMicrosPerCoin < 1 || coin.RateAsOf < 1 || coin.MaxRateAgeSeconds < 1 || coin.MinConfirmations < 1 || coin.MinConfirmations > 2016 {
		return ErrPolicy
	}
	seen := map[string]bool{}
	for _, slot := range c.Slots {
		if !label(slot.ID) || seen[slot.ID] || !identityName(slot.StationName) || slot.NotBefore < 1 || slot.NotAfter <= slot.NotBefore || slot.NotAfter-slot.NotBefore > 3600 || (slot.PaymentPolicy != "advance" && slot.PaymentPolicy != "start_now") {
			return ErrPolicy
		}
		seen[slot.ID] = true
	}
	l := c.Limits
	if l.MaxBlocks < 1 || l.MaxBlocks > 2016 || l.MaxMempool < 1 || l.MaxMempool > 100000 || l.MaxCalls < 1 || l.MaxCalls > 200000 || l.MaxBytes < 1 || l.MaxBytes > 512<<20 {
		return ErrPolicy
	}
	return nil
}

func validateMainGateway(raw []byte) error {
	var c mainServeConfig
	if err := serviceDecode(raw, &c, false); err != nil {
		return err
	}
	if !digestPin(c.AgentPubkey) || !digestPin(c.Kernel.IssuerPubkey) || !identityName(c.Kernel.AgentName) || !identityName(c.Kernel.LandlordName) || c.Kernel.AgentName == c.Kernel.LandlordName || !p2pkhScript(c.Kernel.SealScript) || !localEndpoint(net.JoinHostPort(c.Kernel.RPCHost, strconv.Itoa(c.Kernel.RPCPort))) {
		return ErrPolicy
	}
	if c.RelayMaxEventBytes <= 0 || c.RelayMaxEventBytes > 131072 {
		return ErrPolicy
	}
	if c.AgentKeyFile != "/etc/swarma/gateway/agent.key" || c.Kernel.RPCRouteFile != "/etc/swarma/gateway/observer.json" || !localURL(c.RelayURL, "ws") || !localURL(c.Exchange.BookingURL, "http") || c.StationSocket != "" || c.Station.Root != "" || c.Station.Manager == nil {
		return ErrPolicy
	}
	x, manager := c.Exchange, c.Station.Manager
	if !digestPin(x.PrivacySHA256) || !digestPin(x.TemplateSHA256) || !digestPin(x.ProfileSHA256) || x.PowBits < 1 || x.PowBits > 32 || x.MaxClients < 1 || x.MaxClients > 64 || x.QueueSize < 1 || x.QueueSize > 128 || x.Burst < 1 || x.Burst > 64 || x.MaxReplay < x.Burst || x.MaxReplay > 64 || x.RefillSeconds < 1 || x.RefillSeconds > 3600 || x.KnownSeconds < 1 || x.KnownSeconds > 86400 || x.MessageAgeSeconds < 1 || x.MessageAgeSeconds > 600 || x.PollMilliseconds < 10 || x.PollMilliseconds > 60000 || x.CallMilliseconds < 1 || x.CallMilliseconds > 5000 {
		return ErrPolicy
	}
	if c.RelayReplayLimit != 0 && (c.RelayReplayLimit < 2 || c.RelayReplayLimit > 4096) {
		return ErrPolicy
	}
	if !digestPin(manager.PayloadSHA256) || !label(manager.PayloadID) || manager.SlotMin < 0 || manager.SlotMax > 9999 || manager.SlotMin > manager.SlotMax || manager.StartMilliseconds < 1 || manager.StartMilliseconds > 5000 || !stationEndpoint(manager.Listen) || !stationEndpoint(manager.PayloadListen) || manager.Listen == manager.PayloadListen || !digestPin(manager.TLS.CertSHA256) || !digestPin(manager.TLS.ManagerCertSHA256) || manager.TLS.CertFile != "/etc/swarma/gateway/server.pem" || manager.TLS.KeyFile != "/etc/swarma/gateway/server.key" || manager.TLS.ManagerCAFile != "/etc/swarma/gateway/manager-ca.pem" {
		return ErrPolicy
	}
	dirs := []string{c.JournalDir, c.Kernel.StateDir, x.StateDir, x.PresentationsDir, manager.StateDir}
	for i, a := range dirs {
		if filepath.Clean(a) != a || !strings.HasPrefix(a, "/var/lib/swarma-gateway/") {
			return ErrPolicy
		}
		for j, b := range dirs {
			if i != j && (a == b || strings.HasPrefix(a, b+"/")) {
				return ErrPolicy
			}
		}
	}
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&m) != nil || m["version"] != json.Number("1") || m["mode"] != "main" || m["screening"] != "off" {
		return ErrPolicy
	}
	k, ok := m["kernel"].(map[string]any)
	if !ok || k["construction_profile"] != "W" || k["network"] != "main" || k["genesis"] != mainGenesis || k["kind"] != "real" || k["stub_verdict"] != "" {
		return ErrNetwork
	}
	station, ok := m["station"].(map[string]any)
	if !ok || station["driver"] != "manager" || station["stub_agent"] != false {
		return ErrPolicy
	}
	if _, ok := m["model_proxy"].(map[string]any); !ok {
		return ErrPolicy
	}
	exchange, ok := m["exchange"].(map[string]any)
	if !ok || exchange["booking_version"] != json.Number("2") {
		return ErrPolicy
	}
	coins, ok := exchange["payment_coins"].([]any)
	if !ok || len(coins) != 1 || coins[0] != "nmc" {
		return ErrNetwork
	}
	return gatewayOptions(m)
}

func validateMainStore(raw []byte) error {
	var c mainStore
	if err := serviceDecode(raw, &c, false); err != nil {
		return err
	}
	if c.Root != "/var/lib/swarma-store" || !localURL(c.PublicURL, "http") || c.MaxBlobBytes < 1 || c.MaxBlobBytes > 64<<20 || c.MaxBlobs < 1 || c.MaxBlobs > 4096 || c.MaxTotalBytes < c.MaxBlobBytes || c.MaxTotalBytes > 1<<30 || c.MaxReplay < 2 || c.MaxReplay > 512 || c.MaxReplayPerKey < 1 || c.MaxReplayPerKey >= c.MaxReplay || c.SkewSeconds < 1 || c.SkewSeconds > 60 || len(c.Writers) < 1 || len(c.Writers) > 64 {
		return ErrPolicy
	}
	seen := map[string]bool{}
	for _, k := range c.Writers {
		if !digestPin(k) || seen[k] {
			return ErrPolicy
		}
		seen[k] = true
	}
	return nil
}

func validateMainRelay(raw []byte) error {
	var c mainRelay
	if err := serviceDecode(raw, &c, false); err != nil {
		return err
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Host == "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "wss" && !(u.Scheme == "ws" && u.Hostname() == "127.0.0.1")) || c.StateDir != "/var/lib/swarma-relay" {
		return ErrPolicy
	}
	if c.TrustedProxyIP != "" {
		ip := net.ParseIP(c.TrustedProxyIP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != c.TrustedProxyIP {
			return ErrPolicy
		}
	}
	if c.UnknownPowBits < 0 || c.UnknownPowBits > 32 || len(c.KnownPubkeys) > 256 || c.MaxEventBytes < 1024 || int64(c.MaxEventBytes)+1024 < 2+(2+6*3)+(2+6*64)+5+4*16384 || c.MaxEventBytes > 131072 || c.MaxEvents < 1 || c.MaxEvents > 4096 || c.MaxStoreBytes < c.MaxEventBytes+1024 || c.MaxStoreBytes > 64<<20 || c.RetentionSeconds < 1 || c.RetentionSeconds > 30*86400 || c.FutureSeconds < 0 || c.FutureSeconds > 600 || c.MaxConnections < 1 || c.MaxConnections > 128 || c.MaxConnectionsPerIP < 1 || c.MaxConnectionsPerIP > c.MaxConnections || c.MaxIPs < c.MaxConnections || c.MaxIPs > 8192 || c.FramesPerMinute < 1 || c.FramesPerMinute > 10000 || c.FramesPerIPMinute < c.FramesPerMinute || c.FramesPerIPMinute > 100000 || c.Subscriptions < 1 || c.Subscriptions > 32 || c.Queue < 3 || c.Queue > 1024 || c.Backlog < 1 || c.Backlog > c.Queue-2 || int64(c.MaxConnections)*int64(c.Queue)*int64(c.MaxEventBytes) > 256<<20 {
		return ErrPolicy
	}
	read, ping := c.ReadTimeoutMilliseconds, c.PingIntervalMilliseconds
	if read == 0 {
		read = 90000
	}
	if ping == 0 {
		ping = 30000
	}
	if read < 100 || read > 300000 || ping < 10 || ping > 300000 || ping >= read {
		return ErrPolicy
	}
	seen := map[string]bool{}
	for _, k := range c.KnownPubkeys {
		if !exactHex(k, 32) || seen[k] {
			return ErrPolicy
		}
		seen[k] = true
	}
	return nil
}

func localURL(raw, scheme string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == scheme && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && localEndpoint(u.Host) && u.String() == raw
}
