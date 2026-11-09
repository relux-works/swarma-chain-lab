package main

import (
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Main admission needs a real manager/kernel and explicit model caps, with
// network/genesis agreement and only NMC payments. These are preflight tests;
// no gateway, node, model provider or station is contacted.
func TestMainConfig(t *testing.T) {
	c := remoteConfig(t)
	c.Mode, c.Kernel.Network, c.Kernel.Genesis = "main", "main", su.MainGenesis
	c.ModelProxy = modelConfig(t)
	uid := uint32(1200)
	c.ModelProxy.ServerUID = &uid
	if err := c.validate(false); err != nil { t.Fatal("complete main config", err) }
	for _, mutate := range []func(*serveConfig){
		func(c *serveConfig) { c.Kernel.Genesis = su.RegtestGenesis },
		func(c *serveConfig) { c.Mode = "regtest" },
		func(c *serveConfig) { c.ModelProxy = nil },
		func(c *serveConfig) { c.Exchange.PaymentCoins = []exchange.Coin{exchange.BTC} },
		func(c *serveConfig) { c.Exchange.PaymentCoins = []exchange.Coin{exchange.LTC} },
		func(c *serveConfig) { c.Kernel.Kind = "stub"; c.Kernel.StubVerdict = "live" },
	} {
		bad := c; mutate(&bad)
		if bad.validate(false) == nil { t.Fatal("incomplete main config admitted") }
	}
}
