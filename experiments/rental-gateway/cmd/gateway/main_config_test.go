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
	if err := c.validate(false); err != nil {
		t.Fatal("complete main config", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*serveConfig)
	}{
		{"genesis", func(c *serveConfig) { c.Kernel.Genesis = su.RegtestGenesis }},
		{"mode", func(c *serveConfig) { c.Mode = "regtest" }},
		{"model-missing", func(c *serveConfig) { c.ModelProxy = nil }},
		{"root-model-uid", func(c *serveConfig) {
			model := *c.ModelProxy
			uid := uint32(0)
			model.ServerUID = &uid
			c.ModelProxy = &model
		}},
		{"btc", func(c *serveConfig) { c.Exchange.PaymentCoins = []exchange.Coin{exchange.BTC} }},
		{"ltc", func(c *serveConfig) { c.Exchange.PaymentCoins = []exchange.Coin{exchange.LTC} }},
		{"stub", func(c *serveConfig) { c.Kernel.Kind = "stub"; c.Kernel.StubVerdict = "live" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := c
			tc.mutate(&bad)
			if bad.validate(false) != errConfig && tc.name != "stub" {
				t.Fatal("incomplete main config admitted")
			}
			if tc.name == "stub" && bad.validate(false) != errMode {
				t.Fatal("incomplete main config admitted")
			}
		})
	}
}
