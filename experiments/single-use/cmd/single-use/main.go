package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	singleuse "relux.works/swarma-chain-lab/experiments/single-use"
)

func main() { os.Exit(run()) }
func run() int {
	f := flag.NewFlagSet("single-use", flag.ContinueOnError)
	policy := f.String("policy", "", "independent public policy file")
	route := f.String("route", "", "private read-only observer route")
	cert := f.String("certificate", "", "exact signed certificate file")
	req := f.String("request", "", "exact signed request envelope file")
	atFlag := f.String("test-at", "", "regtest-only observation timestamp")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	at := time.Now()
	var e error
	if *atFlag != "" {
		at, e = time.Parse(time.RFC3339, *atFlag)
		if e != nil {
			return 2
		}
	}
	var p singleuse.Policy
	var r singleuse.Route
	for _, input := range []struct {
		path string
		dst  any
	}{{*policy, &p}, {*route, &r}} {
		b, e := singleuse.PublicFile(input.path, 65536)
		if e != nil || singleuse.StrictInput(b, input.dst) != nil {
			fmt.Fprintln(os.Stderr, "input refused")
			return 2
		}
	}
	c, e := singleuse.PublicFile(*cert, 98304)
	if e != nil {
		return 2
	}
	q, e := singleuse.PublicFile(*req, 12288)
	if e != nil {
		return 2
	}
	node, e := singleuse.NewRPC(r)
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
