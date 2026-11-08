package main

import (
	"encoding/json"
	"flag"
	"os"
	rental "relux.works/swarma-chain-lab/experiments/rental"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"time"
)

func die(reason string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"verdict": "refused", "reason": reason})
	os.Exit(1)
}
func read(path string) []byte {
	if path == "" {
		return nil
	}
	b, e := su.PublicFile(path, 16384)
	if e != nil {
		die("PUBLIC_INPUT")
	}
	return b
}
func main() {
	if len(os.Args) < 2 {
		die("COMMAND")
	}
	kind := os.Args[1]
	fs := flag.NewFlagSet("rental-plan", flag.ContinueOnError)
	policy := fs.String("policy", "", "issuer policy JSON")
	spec := fs.String("spec", "", "offline funding and pool facts")
	cert := fs.String("certificate", "", "canonical signed certificate")
	request := fs.String("request", "", "M3 issuance request")
	event := fs.String("package-event", "", "signed M3 package publication")
	at := fs.Int64("at", -1, "regtest clock override")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 {
		die("ARGUMENTS")
	}
	var p rental.IssuerPolicy
	var s rental.PlanSpec
	if su.StrictInput(read(*policy), &p) != nil || su.StrictInput(read(*spec), &s) != nil || s.Kind != kind {
		die("PLAN_INPUT")
	}
	now := time.Now().Unix()
	if *at >= 0 {
		now = *at
	}
	plan, e := rental.MakePlan(p, s, read(*cert), read(*request), read(*event), now)
	if e != nil {
		die(e.Error())
	}
	if json.NewEncoder(os.Stdout).Encode(plan) != nil {
		os.Exit(1)
	}
}
