package wallet

import (
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
