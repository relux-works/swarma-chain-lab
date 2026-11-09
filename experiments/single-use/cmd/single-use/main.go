package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	singleuse "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"time"
)

func main() { os.Exit(run()) }
func run() int {
	f := flag.NewFlagSet("single-use", flag.ContinueOnError)
	policy := f.String("policy", "", "independent public policy file")
	route := f.String("route", "", "private regtest HTTP or mainnet operator CLI route")
	cert := f.String("certificate", "", "exact signed certificate file")
	req := f.String("request", "", "exact signed request envelope file")
	atFlag := f.String("test-at", "", "regtest-only observation timestamp")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	var p singleuse.Policy
	raw, e := singleuse.PublicFile(*policy, 65536)
	if e != nil || singleuse.StrictInput(raw, &p) != nil || !singleuse.NetworkPinned(p.Network, p.Genesis) {
		fmt.Fprintln(os.Stderr, "policy refused")
		return 2
	}
	override := false
	f.Visit(func(v *flag.Flag) {
		if v.Name == "test-at" {
			override = true
		}
	})
	if p.Network == "main" && override {
		fmt.Fprintln(os.Stderr, "mainnet test-at refused")
		return 2
	}
	at := time.Now()
	if override {
		at, e = time.Parse(time.RFC3339, *atFlag)
		if e != nil {
			return 2
		}
	}
	raw, e = singleuse.PublicFile(*route, 65536)
	if e != nil {
		fmt.Fprintln(os.Stderr, "route refused")
		return 2
	}
	var node singleuse.Node
	if p.Network == "main" {
		var r singleuse.OperatorRoute
		if singleuse.StrictInput(raw, &r) != nil {
			return 2
		}
		node, e = singleuse.NewOperatorRPC(r, p.Network, p.Genesis, p.StateDir)
	} else {
		var r singleuse.Route
		if singleuse.StrictInput(raw, &r) != nil {
			return 2
		}
		node, e = singleuse.NewRPC(r)
	}
	if e != nil {
		return 2
	}
	c, e := singleuse.PublicFile(*cert, 98304)
	if e != nil {
		return 2
	}
	q, e := singleuse.PublicFile(*req, 12288)
	if e != nil {
		return 2
	}
	receipt := singleuse.Execute(context.Background(), node, p, c, q, at, nil)
	if json.NewEncoder(os.Stdout).Encode(receipt) != nil {
		return 1
	}
	if receipt.Status == "refused" {
		return 1
	}
	return 0
}
