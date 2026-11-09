package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	singleuse "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func main() { os.Exit(run()) }
func run() int {
	f := flag.NewFlagSet("single-use-plan", flag.ContinueOnError)
	spec := f.String("spec", "", "public offline plan parameters")
	request := f.String("request", "", "exact signed envelope; required for a use plan")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	raw, e := singleuse.PublicFile(*spec, 65536)
	if e != nil {
		return 2
	}
	var s singleuse.PlanSpec
	if singleuse.StrictInput(raw, &s) != nil {
		return 2
	}
	var req []byte
	if *request != "" {
		req, e = singleuse.PublicFile(*request, 12288)
		if e != nil {
			return 2
		}
	}
	plan, e := singleuse.MakePlan(s, req)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	if json.NewEncoder(os.Stdout).Encode(plan) != nil {
		return 1
	}
	return 0
}
