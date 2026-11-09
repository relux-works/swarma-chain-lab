// agent-wallet is a signing socket client. It has no wallet RPC credential.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	wallet "github.com/relux-works/swarma-chain-lab/experiments/agent-wallet"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
func run(args []string, out io.Writer) int {
	f := flag.NewFlagSet("agent-wallet", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "client pins JSON")
	request := f.String("request", "", "unsigned canonical LIP-0006 request JSON")
	use := f.String("use-txid", "", "optional single-use proof locator")
	refuse := func(code string) int {
		json.NewEncoder(out).Encode(struct {
			Error string `json:"error"`
		}{code})
		return 2
	}
	if e := f.Parse(args); e != nil {
		if e == flag.ErrHelp {
			fmt.Fprintln(out, "agent-wallet --config CLIENT.json --request REQUEST.json [--use-txid TXID]")
			return 0
		}
		return refuse("CLI_ARGUMENTS")
	}
	if f.NArg() != 0 || *config == "" || *request == "" {
		return refuse("CLI_ARGUMENTS")
	}
	c, e := wallet.LoadActionClientConfig(*config)
	if e != nil {
		return refuse(wallet.ActionErrorReason(e))
	}
	raw, e := wallet.PublicObject(*request)
	if e != nil {
		return refuse(wallet.ActionErrorReason(e))
	}
	network, genesis := c.NetworkPins()
	r, e := wallet.ParseActionRequestForNetwork(raw, network, genesis)
	if e != nil {
		return refuse(wallet.ActionErrorReason(e))
	}
	key, e := wallet.LoadActionKey(c.KeyFile)
	if e != nil {
		return refuse(wallet.ActionErrorReason(e))
	}
	var proof *wallet.ActionProof
	if *use != "" {
		proof = &wallet.ActionProof{UseTxID: *use}
	}
	signed, e := wallet.SignActionForNetwork(r, key, proof, network, genesis)
	if e != nil {
		return refuse(wallet.ActionErrorReason(e))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	reply, e := wallet.ExchangeActionForNetwork(ctx, c.Socket, c.ServiceUID, c.ReceiptKey, signed, network, genesis)
	if e != nil {
		return refuse(wallet.ActionErrorReason(e))
	}
	if _, e = fmt.Fprintln(out, string(reply)); e != nil {
		return 2
	}
	var receipt wallet.SignedActionReceipt
	json.Unmarshal(reply, &receipt)
	switch receipt.Receipt.Verdict {
	case "executed":
		return 0
	case "pending":
		return 3
	case "uncertain":
		return 4
	default:
		return 2
	}
}
