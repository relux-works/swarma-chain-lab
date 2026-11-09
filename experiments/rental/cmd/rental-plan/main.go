package main

import (
	"encoding/json"
	"flag"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
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
	grant := fs.String("grant", "", "canonical signed v3 grant")
	request := fs.String("request", "", "M3 issuance request")
	event := fs.String("package-event", "", "signed M3 package publication")
	ids := fs.String("ids", "", "JSON array of signed grant ids for optional batch")
	enableBatch := fs.Bool("enable-batch", false, "explicitly enable offline batch anchoring")
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
	if kind == "batch-anchor" {
		var leaves []string
		if su.StrictInput(read(*ids), &leaves) != nil {
			die("BATCH_IDS")
		}
		plan, e := rental.MakeBatchAnchorPlan(p.Policy, s, leaves, *enableBatch)
		if e != nil {
			die(e.Error())
		}
		if json.NewEncoder(os.Stdout).Encode(plan) != nil {
			os.Exit(1)
		}
		return
	}
	if kind == "grant-issue" {
		plan, e := rental.MakeGrantIssuancePlan(p.Policy, s, read(*grant))
		if e != nil {
			die(e.Error())
		}
		if json.NewEncoder(os.Stdout).Encode(plan) != nil {
			os.Exit(1)
		}
		return
	}
	plan, e := rental.MakePlan(p, s, read(*cert), read(*request), read(*event), now)
	if e != nil {
		die(e.Error())
	}
	if json.NewEncoder(os.Stdout).Encode(plan) != nil {
		os.Exit(1)
	}
}
