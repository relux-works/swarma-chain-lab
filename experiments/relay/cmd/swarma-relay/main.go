package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	relay "github.com/relux-works/swarma-chain-lab/experiments/relay"
)

func run(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("swarma-relay", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "public config")
	listen := f.String("listen", "127.0.0.1:18818", "loopback listener")
	check := f.Bool("check", false, "validate only")
	if f.Parse(args) != nil || f.NArg() != 0 || *config == "" {
		return fmt.Errorf("USAGE")
	}
	host, port, e := net.SplitHostPort(*listen)
	n, pe := strconv.Atoi(port)
	if e != nil || pe != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || host != "127.0.0.1" {
		return fmt.Errorf("LISTEN")
	}
	raw, e := installedRead(*config, 65536)
	if e != nil {
		return e
	}
	c, e := relay.ParseConfig(raw)
	if e != nil {
		return e
	}
	if *check {
		return nil
	}
	r, e := relay.New(c, time.Now)
	if e != nil {
		return e
	}
	defer r.Close()
	ln, e := net.Listen("tcp4", *listen)
	if e != nil {
		return fmt.Errorf("LISTEN")
	}
	server := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	select {
	case <-ctx.Done():
		return nil
	case <-done:
		return fmt.Errorf("SERVE")
	}
}
func main() {
	configguard.CheckMain("relay")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := run(ctx, os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "relay:", e)
		os.Exit(1)
	}
}
