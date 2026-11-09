package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	wallet "relux.works/swarma-chain-lab/experiments/agent-wallet"
)

func main()      { os.Exit(run(os.Args[1:])) }
func emit(v any) { json.NewEncoder(os.Stdout).Encode(v) }
func refused(code string) int {
	emit(wallet.Receipt{Status: "refused", Reason: code, Message: wallet.Explain(code)})
	return 2
}
func run(args []string) int {
	fs := flag.NewFlagSet("agent-wallet", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	config := fs.String("config", "", "private operator configuration file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "agent-wallet --config FILE balance|receive|history|budget|spend|name-register\nMutations require --grant FILE_OR_SHA256 --request FILE; one-off use proof: --use-txid TXID.")
	}
	if e := fs.Parse(args); e != nil {
		if e == flag.ErrHelp {
			return 0
		}
		return refused("CLI_ARGUMENTS")
	}
	rest := fs.Args()
	if *config == "" || len(rest) < 1 {
		return refused("CLI_ARGUMENTS")
	}
	command := rest[0]
	cf := flag.NewFlagSet(command, flag.ContinueOnError)
	cf.SetOutput(os.Stderr)
	grant := cf.String("grant", "", "public signed grant file or exact SHA256")
	request := cf.String("request", "", "public grantee-signed request file")
	use := cf.String("use-txid", "", "confirmed W3 use transaction locator")
	if cf.Parse(rest[1:]) != nil || len(cf.Args()) != 0 {
		return refused("CLI_ARGUMENTS")
	}
	switch command {
	case "balance", "receive", "history":
		if *grant != "" || *request != "" || *use != "" {
			return refused("CLI_ARGUMENTS")
		}
	case "budget":
		if *grant == "" || *request != "" || *use != "" {
			return refused("CLI_ARGUMENTS")
		}
	case "spend", "name-register":
		if *grant == "" || *request == "" {
			return refused("CLI_ARGUMENTS")
		}
	default:
		return refused("CLI_COMMAND")
	}
	c, e := wallet.LoadConfig(*config)
	if e != nil {
		return refused(e.Error())
	}
	w, e := wallet.Open(c)
	if e != nil {
		return refused(e.Error())
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch command {
	case "balance":
		v, e := w.Balance(ctx)
		if e != nil {
			return refused(e.Error())
		}
		emit(v)
		return 0
	case "receive":
		v, e := w.Receive(ctx)
		if e != nil {
			return refused(e.Error())
		}
		emit(map[string]string{"address": v})
		return 0
	case "history":
		v, e := w.History(ctx)
		if e != nil {
			return refused(e.Error())
		}
		emit(v)
		return 0
	}
	raw, e := wallet.LoadGrant(c, *grant)
	if e != nil {
		return refused(e.Error())
	}
	g, e := w.Grant(raw)
	if e != nil {
		return refused(e.Error())
	}
	terms, e := wallet.LoadTerms(c, g)
	if e != nil {
		return refused(e.Error())
	}
	if command == "budget" {
		v, e := w.Budget(ctx, raw, terms)
		if e != nil {
			return refused(e.Error())
		}
		emit(v)
		return 0
	}
	req, e := wallet.PublicObject(*request)
	if e != nil {
		return refused(e.Error())
	}
	signed, e := wallet.ParseRequest(req)
	if e != nil {
		return refused(e.Error())
	}
	want := "pay"
	if command == "name-register" {
		want = "names.register"
	}
	if signed.Request.Action != want {
		return refused("CLI_ACTION_MISMATCH")
	}
	r := w.Execute(ctx, raw, terms, req, *use)
	emit(r)
	switch r.Status {
	case "executed", "already-executed":
		return 0
	case "pending":
		return 3
	case "uncertain":
		return 4
	default:
		return 2
	}
}
