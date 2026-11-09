package main

import (
	"encoding/json"
	"errors"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
)

// A flat legacy Config selects v1. V2 is explicit and carries a trusted route
// file for every configured payment coin; unknown or mixed layouts refuse.
type configV2 struct {
	ServiceVersion    int               `json:"service_version"`
	Config            booking.ConfigV2  `json:"config"`
	PaymentRouteFiles map[string]string `json:"payment_route_files"`
}
type selectedConfig struct {
	v1 booking.Config
	v2 *configV2
}

func parseConfig(raw []byte) (selectedConfig, error) {
	var fields map[string]json.RawMessage
	if booking.Strict(raw, &fields) != nil || fields == nil {
		return selectedConfig{}, errConfig
	}
	if _, ok := fields["service_version"]; !ok {
		var c booking.Config
		if booking.Strict(raw, &c) != nil {
			return selectedConfig{}, errConfig
		}
		return selectedConfig{v1: c}, nil
	}
	var c configV2
	if booking.Strict(raw, &c) != nil || c.ServiceVersion != 2 || len(c.Config.Coins) < 1 || len(c.Config.Coins) > 3 || len(c.PaymentRouteFiles) != len(c.Config.Coins) {
		return selectedConfig{}, errConfig
	}
	for coin := range c.Config.Coins {
		if _, e := pc.ParseCoin(coin); e != nil || c.PaymentRouteFiles[coin] == "" {
			return selectedConfig{}, errConfig
		}
	}
	return selectedConfig{v2: &c}, nil
}

var errConfig = errors.New("CONFIG_SCHEMA")

func (c selectedConfig) stateDir() string {
	if c.v2 != nil {
		return c.v2.Config.StateDir
	}
	return c.v1.StateDir
}
