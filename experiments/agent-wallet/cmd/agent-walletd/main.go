package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"io"
	"os"
	"os/signal"
	"syscall"

	wallet "github.com/relux-works/swarma-chain-lab/experiments/agent-wallet"
)

func main() {
	configguard.CheckMain("wallet")
	os.Exit(run())
}
func run() int {
	f := flag.NewFlagSet("agent-walletd", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("config", "", "private service config")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 || *path == "" {
		fmt.Fprintln(os.Stderr, "SERVICE_ARGUMENTS")
		return 2
	}
	c, e := wallet.LoadServiceConfig(*path)
	if e != nil {
		fmt.Fprintln(os.Stderr, wallet.ActionErrorReason(e))
		return 2
	}
	s, e := wallet.OpenActionService(c)
	if e != nil {
		fmt.Fprintln(os.Stderr, wallet.ActionErrorReason(e))
		return 2
	}
	defer s.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e = s.Serve(ctx); e != nil {
		fmt.Fprintln(os.Stderr, wallet.ActionErrorReason(e))
		return 1
	}
	return 0
}
