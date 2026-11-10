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

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	payload "github.com/relux-works/swarma-chain-lab/experiments/station-payload"
)

func run(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("station-payload", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	bootstrap := f.String("bootstrap", "", "private canonical bootstrap file (0600)")
	ca := f.String("ca", "", "root-owned0640 static operator CA PEM, shared by fixture gateway/proxy")
	address := f.String("gateway", "", "gateway payload IP:port")
	pin := f.String("gateway-pin", "", "gateway leaf DER SHA256")
	model := f.String("model", "", "exact operator model ID (v2)")
	max := f.Uint64("max-tokens", 0, "operator per-request output limit (v2)")
	dialect := f.String("dialect", "", "operator-pinned messages or responses; omitted only for legacy tests")
	modelConfig := f.String("model-config", "", "root-owned0640 static canonical proxy config copy; referenced paths are never opened")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return payload.ErrConfig
	}
	if (*dialect == "") != (*modelConfig == "") || (*dialect != "" && *dialect != payload.DialectMessages && *dialect != payload.DialectResponses) {
		return payload.ErrConfig
	}
	raw, e := proxy.ReadPrivateFile(*bootstrap, 0600, 4096)
	if e != nil {
		return payload.ErrBootstrap
	}
	cert, e := installedRead(*ca, 65536)
	if e != nil {
		return e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return payload.ErrConfig
	}
	options := payload.Options{Model: *model, MaxTokens: *max, Roots: roots}
	var c *payload.Client
	if *dialect == "" {
		c, e = payload.New(raw, options)
	} else {
		var config proxy.FileConfig
		configRaw, readErr := installedRead(*modelConfig, proxy.MaxBody)
		if readErr != nil {
			return readErr
		}
		config, e = proxy.ParseConfig(configRaw)
		if e != nil {
			return payload.ErrConfig
		}
		c, e = payload.NewPinned(raw, options, *dialect, config)
	}
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
