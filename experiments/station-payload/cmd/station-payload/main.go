package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	proxy "relux.works/swarma-chain-lab/experiments/model-proxy"
	payload "relux.works/swarma-chain-lab/experiments/station-payload"
)

func run(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("station-payload", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	bootstrap := f.String("bootstrap", "", "private canonical bootstrap file (0600)")
	ca := f.String("ca", "", "operator CA PEM file (0600), shared by fixture gateway/proxy")
	address := f.String("gateway", "", "gateway payload IP:port")
	pin := f.String("gateway-pin", "", "gateway leaf DER SHA256")
	model := f.String("model", "", "exact operator model ID (v2)")
	max := f.Uint64("max-tokens", 0, "operator per-request output limit (v2)")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return payload.ErrConfig
	}
	raw, e := proxy.ReadPrivateFile(*bootstrap, 0600, 4096)
	if e != nil {
		return payload.ErrBootstrap
	}
	cert, e := proxy.ReadPrivateFile(*ca, 0600, 65536)
	if e != nil {
		return payload.ErrConfig
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return payload.ErrConfig
	}
	c, e := payload.New(raw, payload.Options{Model: *model, MaxTokens: *max, Roots: roots})
	if e != nil {
		return e
	}
	defer c.Close()
	return c.Run(ctx, *address, *pin, roots)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
