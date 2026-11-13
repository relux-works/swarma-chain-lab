package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-chain-lab/experiments/agent-wallet/alertforwarder"
)

func main() { os.Exit(run()) }
func run() int {
	f := flag.NewFlagSet("agent-wallet-alert-forwarder", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("config", "", "private forwarder config")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 || *path == "" {
		fmt.Fprintln(os.Stderr, "FORWARDER_ARGUMENTS")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := alertforwarder.Run(ctx, *path); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		return 2
	}
	return 0
}
