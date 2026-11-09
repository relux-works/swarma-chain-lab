package main

import (
	"context"
	"flag"
	"fmt"
	ss "github.com/relux-works/swarma-chain-lab/experiments/signer-service"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg := flag.String("config", "", "absolute private configuration file")
	once := flag.Bool("once", false, "perform one intake/processing/refill cycle")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := ss.RunFile(ctx, *cfg, *once, func(r ss.Result) { fmt.Println(string(ss.EncodeResult(r))) }); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
