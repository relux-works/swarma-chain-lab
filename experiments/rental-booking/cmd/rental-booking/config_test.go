package main

import (
	"encoding/json"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"strings"
	"testing"
)

// The actual CLI selector keeps flat v1 and requires an explicit, closed v2
// layout with an exact payment-route set. This is schema selection, not node
// admission or private-key loading; those occur only after selection succeeds.
func TestServiceConfigSelection(t *testing.T) {
	v2 := configV2{ServiceVersion: 2, Config: booking.ConfigV2{StateDir: "/fixture/v2", Slots: []booking.Slot{}, Template: booking.Template{Allowed: []string{}, Forbidden: []string{}}, Coins: map[string]booking.CoinConfig{"nmc": {}}}, PaymentRouteFiles: map[string]string{"nmc": "/fixture/payment-route.json"}}
	raw, _ := json.Marshal(v2)
	c, e := parseConfig(raw)
	if e != nil || c.v2 == nil || c.stateDir() != "/fixture/v2" {
		t.Fatal("explicit v2 not selected")
	}
	legacy, _ := json.Marshal(booking.Config{StateDir: "/fixture/v1", Slots: []booking.Slot{}, Template: booking.Template{Allowed: []string{}, Forbidden: []string{}}})
	c, e = parseConfig(legacy)
	if e != nil || c.v2 != nil || c.stateDir() != "/fixture/v1" {
		t.Fatal("legacy v1 not preserved")
	}
	cases := map[string][]byte{
		"unknown-version": []byte(strings.Replace(string(raw), `"service_version":2`, `"service_version":3`, 1)),
		"null-version":    []byte(strings.Replace(string(raw), `"service_version":2`, `"service_version":null`, 1)),
		"duplicate":       []byte(strings.Replace(string(raw), `"service_version":2`, `"service_version":2,"service_version":2`, 1)),
		"unknown":         []byte(strings.Replace(string(raw), `"service_version":2`, `"service_version":2,"extra":true`, 1)),
		"alias":           []byte(strings.Replace(string(raw), "service_version", "Service_version", 1)),
		"missing-version": []byte(strings.Replace(string(raw), `"service_version":2,`, "", 1)),
		"null":            []byte("null"),
	}
	for _, mode := range []string{"missing-route", "extra-route", "wrong-coin", "empty-route"} {
		var x configV2
		_ = json.Unmarshal(raw, &x)
		switch mode {
		case "missing-route":
			delete(x.PaymentRouteFiles, "nmc")
		case "extra-route":
			x.PaymentRouteFiles["btc"] = "/fixture/extra"
		case "wrong-coin":
			delete(x.Config.Coins, "nmc")
			x.Config.Coins["other"] = booking.CoinConfig{}
		case "empty-route":
			x.PaymentRouteFiles["nmc"] = ""
		}
		cases[mode], _ = json.Marshal(x)
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := parseConfig(raw); e == nil || e.Error() != "CONFIG_SCHEMA" {
				t.Fatal("ambiguous service config accepted")
			}
		})
	}
	if _, e = parseConfig(raw); e != nil {
		t.Fatal("valid neighbor refused", e)
	}
}
