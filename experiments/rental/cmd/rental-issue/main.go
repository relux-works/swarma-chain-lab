// rental-issue creates detached regtest certificates, never chain transactions.
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
	fs := flag.NewFlagSet("rental-issue", flag.ContinueOnError)
	policy := fs.String("policy", "", "trusted issuer policy JSON")
	route := fs.String("route", "", "private loopback read-only route JSON")
	request := fs.String("request", "", "authenticated issuance request bytes")
	publication := fs.String("package-event", "", "signed package event bytes")
	seal := fs.String("seal", "", "public pool outpoint JSON")
	key := fs.String("grant-key-file", "", "private 0600 binary grant scalar file")
	at := fs.Int64("at", -1, "regtest trusted clock override")
	if fs.Parse(os.Args[1:]) != nil || fs.NArg() != 0 {
		die("ARGUMENTS")
	}
	var p rental.IssuerPolicy
	var point rental.Point
	if su.StrictInput(read(*policy), &p) != nil || su.StrictInput(read(*seal), &point) != nil {
		die("ISSUER_INPUT")
	}
	if p.Policy.Network != "regtest" || p.Policy.Genesis != su.RegtestGenesis {
		die("REGTEST_ONLY")
	}
	var r su.Route
	if su.StrictInput(read(*route), &r) != nil {
		die("ROUTE_INPUT")
	}
	node, e := su.NewRPC(r)
	if e != nil {
		die("ROUTE_INPUT")
	}
	now := time.Now().Unix()
	if *at >= 0 {
		now = *at
	}
	result := rental.IssueDetached(context.Background(), node, p, read(*request), read(*publication), point, *key, now)
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
	if result.Verdict != "issued" {
		os.Exit(1)
	}
}
