package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"time"

	rental "relux.works/swarma-chain-lab/experiments/rental"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

func die(reason string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"verdict": "refused", "reason": reason})
	os.Exit(1)
}
func read(path string) []byte {
	b, e := su.PublicFile(path, 16384)
	if e != nil {
		die("PUBLIC_INPUT")
	}
	return b
}
func main() {
	if len(os.Args) < 2 || (os.Args[1] != "check" && os.Args[1] != "admit-issuance") {
		die("COMMAND")
	}
	fs := flag.NewFlagSet("rental-kernel", flag.ContinueOnError)
	policy := fs.String("policy", "", "trusted policy JSON (issuer policy for admit-issuance)")
	route := fs.String("route", "", "private loopback observer route JSON")
	operator := fs.Bool("operator-route", false, "use hash-pinned CLI operator route")
	cert := fs.String("certificate", "", "canonical signed envelope")
	station := fs.String("station", "", "station name")
	sender := fs.String("sender", "", "authenticated inner-seal public key")
	request := fs.String("request", "", "M3 issuance request")
	publication := fs.String("package-event", "", "signed M3 package publication")
	at := fs.Int64("at", -1, "regtest clock override in UTC Unix seconds")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 {
		die("ARGUMENTS")
	}
	now := time.Now().Unix()
	if *at >= 0 {
		now = *at
	}
	var p rental.Policy
	var ip rental.IssuerPolicy
	if os.Args[1] == "check" {
		if su.StrictInput(read(*policy), &p) != nil {
			die("POLICY_INPUT")
		}
	} else {
		if su.StrictInput(read(*policy), &ip) != nil {
			die("POLICY_INPUT")
		}
		p = ip.Policy
	}
	// Check this before constructing any node adapter: no mainnet calls in M1.
	if p.Network != "regtest" || p.Genesis != su.RegtestGenesis {
		die("REGTEST_ONLY")
	}
	var node su.Node
	if *operator {
		var r su.OperatorRoute
		if su.StrictInput(read(*route), &r) != nil {
			die("ROUTE_INPUT")
		}
		n, e := su.NewOperatorRPC(r, p.Network, p.Genesis, p.StateDir)
		if e != nil {
			die("ROUTE_INPUT")
		}
		node = n
	} else {
		var r su.Route
		if su.StrictInput(read(*route), &r) != nil {
			die("ROUTE_INPUT")
		}
		n, e := su.NewRPC(r)
		if e != nil {
			die("ROUTE_INPUT")
		}
		node = n
	}
	if os.Args[1] == "admit-issuance" {
		r := rental.AdmitIssuance(context.Background(), node, ip, read(*request), read(*publication), now)
		if json.NewEncoder(os.Stdout).Encode(r) != nil {
			os.Exit(1)
		}
		if r.Verdict != "admit" {
			os.Exit(1)
		}
		return
	}
	r := rental.Check(context.Background(), node, p, read(*cert), *station, *sender, now)
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		os.Exit(1)
	}
	if r.Verdict == "pending" {
		os.Exit(2)
	}
	if r.Verdict != "live" {
		os.Exit(1)
	}
}
