package wallet

import (
	"bytes"
	"testing"

	"encoding/json"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// privateRouteFixture is a test-only legacy config writer. Generic Route JSON
// intentionally redacts; genuine private fixture files need their original
// credentials. Never use this projection in logging or production output.
func privateRouteFixture(value any) any {
	type legacy struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	switch r := value.(type) {
	case su.Route:
		return legacy{r.Host, r.Port, r.Username, r.Password.RevealForBasicAuth()}
	default:
		return value
	}
}

func privateRouteFixtureJSON(value any) []byte {
	raw, err := json.Marshal(privateRouteFixture(value))
	if err != nil {
		panic("private route fixture refused")
	}
	return raw
}

// Preserve private wallet fixture inputs; automatic Config JSON stays redacted.
func privateWalletFixture(value any) any {
	if crash, ok := value.(actionCrashFixture); ok {
		return struct {
			Service ServiceConfig `json:"service"`
			Wallet  any           `json:"wallet"`
			Stage   string        `json:"stage"`
		}{crash.Service, privateWalletFixture(crash.Wallet), crash.Stage}
	}
	c, ok := value.(Config)
	if !ok {
		return value
	}
	type legacyConfig struct {
		Version       int           `json:"version"`
		Network       string        `json:"network"`
		Genesis       string        `json:"genesis"`
		Policy        rental.Policy `json:"policy"`
		Observer      any           `json:"observer"`
		Wallet        any           `json:"wallet"`
		Broadcast     any           `json:"broadcast"`
		StateDir      string        `json:"state_dir"`
		ObjectsDir    string        `json:"objects_dir"`
		ChangeAddress string        `json:"change_address"`
		FeeRate       int64         `json:"fee_rate_sat_vb"`
		WalletDir     string        `json:"wallet_dir"`
		MemoryZone    string        `json:"memory_zone"`
	}
	return legacyConfig{
		Version:  c.Version,
		Network:  c.Network,
		Genesis:  c.Genesis,
		Policy:   c.Policy,
		Observer: privateRouteFixture(c.Observer),
		Wallet: struct {
			Route  any    `json:"route"`
			Wallet string `json:"wallet"`
		}{privateRouteFixture(c.Wallet.Route), c.Wallet.Wallet},
		Broadcast:     privateRouteFixture(c.Broadcast),
		StateDir:      c.StateDir,
		ObjectsDir:    c.ObjectsDir,
		ChangeAddress: c.ChangeAddress,
		FeeRate:       c.FeeRate,
		WalletDir:     c.WalletDir,
		MemoryZone:    c.MemoryZone,
	}
}

// Nested private config fixtures retain legacy route/password bytes, while the
// ordinary Config projection remains redacted. This runs without Core or I/O.
func TestPrivateWalletRouteFixtureBytes(t *testing.T) {
	const marker = "synthetic-wallet-fixture-password"
	const golden = `{"host":"127.0.0.1","port":18443,"username":"w3-observer","password":"synthetic-wallet-fixture-password"}`
	route := su.Route{Host: "127.0.0.1", Port: 18443, Username: "w3-observer", Password: su.NewRPCPassword(marker)}
	config := Config{Observer: route, Wallet: WalletRoute{Route: route, Wallet: "agent"}, Broadcast: route}
	private := canonical(privateWalletFixture(config))
	public := canonical(config)
	if !bytes.Contains(private, []byte(marker)) || bytes.Contains(public, []byte(marker)) {
		t.Fatal("private/public fixture credential boundary changed")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(private, &object) != nil {
		t.Fatal("private fixture refused")
	}
	if string(object["observer"]) != golden || string(object["broadcast"]) != golden || string(object["wallet"]) != `{"route":`+golden+`,"wallet":"agent"}` {
		t.Fatal("nested private fixture bytes changed")
	}
	crash := actionCrashFixture{Wallet: config, Stage: "fixture"}
	crashPrivate := canonical(privateWalletFixture(crash))
	if !bytes.Contains(crashPrivate, []byte(marker)) || bytes.Contains(canonical(crash), []byte(marker)) {
		t.Fatal("nested crash fixture credential boundary changed")
	}
	var crashObject map[string]json.RawMessage
	if json.Unmarshal(crashPrivate, &crashObject) != nil || !bytes.Equal(crashObject["wallet"], private) {
		t.Fatal("crash fixture wallet bytes changed")
	}
	var decoded su.Route
	if su.StrictInput(object["observer"], &decoded) != nil || decoded.Password.RevealForBasicAuth() != marker {
		t.Fatal("legacy nested fixture did not load unchanged")
	}
}
