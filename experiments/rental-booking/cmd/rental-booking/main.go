package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	singleuse "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func run() error {
	config := flag.String("config", "", "configuration JSON file")
	profile := flag.String("profile", "", "profile bytes")
	keyfile := flag.String("provider-key", "", "private regtest Nostr key file (hex)")
	routefile := flag.String("route", "", "read-only OperatorRoute JSON")
	listen := flag.String("listen", "", "numeric loopback host:port")
	relayURL := flag.String("relay", "", "loopback ws:// relay URL")
	poll := flag.Duration("poll", 0, "explicit watcher interval")
	flag.Parse()
	if !booking.LoopbackAddress(*listen) || *poll < time.Second || *poll > time.Minute {
		return fmt.Errorf("LISTEN_OR_POLL")
	}
	read := func(path string, max int64) ([]byte, error) { return singleuse.PublicFile(path, max) }
	raw, e := read(*config, 1<<20)
	if e != nil {
		return fmt.Errorf("CONFIG_FILE")
	}
	cfg, e := parseConfig(raw)
	if e != nil {
		return fmt.Errorf("CONFIG_SCHEMA")
	}
	prof, e := read(*profile, 1<<20)
	if e != nil {
		return fmt.Errorf("PROFILE_FILE")
	}
	f, e := os.OpenFile(*keyfile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return fmt.Errorf("PROVIDER_KEY_FILE")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 65 {
		return fmt.Errorf("PROVIDER_KEY_FILE")
	}
	keyRaw := make([]byte, st.Size())
	if _, e = f.Read(keyRaw); e != nil {
		return fmt.Errorf("PROVIDER_KEY_READ")
	}
	keyBytes, e := hex.DecodeString(strings.TrimSpace(string(keyRaw)))
	if e != nil || len(keyBytes) != 32 {
		return fmt.Errorf("PROVIDER_KEY")
	}
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(keyBytes) || scalar.IsZero() {
		return fmt.Errorf("PROVIDER_KEY")
	}
	key := btcec.PrivKeyFromScalar(&scalar)
	defer key.Zero()
	raw, e = read(*routefile, 64<<10)
	if e != nil {
		return fmt.Errorf("ROUTE_FILE")
	}
	var route singleuse.OperatorRoute
	if booking.Strict(raw, &route) != nil {
		return fmt.Errorf("ROUTE_SCHEMA")
	}
	network, genesis := "regtest", singleuse.RegtestGenesis
	if cfg.v2 != nil {
		network, genesis = cfg.v2.Config.NetworkPins()
	}
	node, e := singleuse.NewOperatorRPC(route, network, genesis, cfg.stateDir())
	if e != nil {
		return fmt.Errorf("READ_ONLY_ROUTE")
	}
	relay, e := booking.NewRelayPublisher(*relayURL)
	if e != nil {
		return e
	}
	var service interface {
		Close()
		PublishPending(context.Context) error
		Refresh(context.Context) error
	}
	var makeHandler func(string) (http.Handler, error)
	if cfg.v2 != nil {
		nodes := map[string]booking.Node{}
		for coin, path := range cfg.v2.PaymentRouteFiles {
			raw, e := read(path, 64<<10)
			if e != nil {
				return fmt.Errorf("PAYMENT_ROUTE_FILE")
			}
			var route pc.Route
			if booking.Strict(raw, &route) != nil {
				return fmt.Errorf("PAYMENT_ROUTE_SCHEMA")
			}
			rpc, e := pc.NewRPC(route)
			if e != nil {
				return fmt.Errorf("PAYMENT_READ_ONLY_ROUTE")
			}
			nodes[coin] = rpc
		}
		v2, e := booking.NewServiceV2(cfg.v2.Config, prof, key, nodes, node, relay, time.Now)
		if e != nil {
			return e
		}
		service = v2
		makeHandler = func(origin string) (http.Handler, error) { return booking.NewHTTPHandlerV2(v2, origin) }
	} else {
		v1, e := booking.NewService(cfg.v1, prof, key, node, relay, time.Now)
		if e != nil {
			return e
		}
		service = v1
		makeHandler = func(origin string) (http.Handler, error) { return booking.NewHTTPHandler(v1, origin) }
	}
	defer service.Close()
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		return fmt.Errorf("LISTEN")
	}
	defer listener.Close()
	handler, e := makeHandler("http://" + listener.Addr().String())
	if e != nil {
		return e
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(listener) }()
	fmt.Printf("listening http://%s\n", listener.Addr())
	ticker := time.NewTicker(*poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			stop, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			return server.Shutdown(stop)
		case e := <-errs:
			if e == http.ErrServerClosed {
				return nil
			}
			return fmt.Errorf("HTTP_SERVER")
		case <-ticker.C:
			step, c := context.WithTimeout(ctx, 30*time.Second)
			if e := service.PublishPending(step); e != nil {
				fmt.Fprintln(os.Stderr, e.Error())
			}
			if e := service.Refresh(step); e != nil {
				fmt.Fprintln(os.Stderr, e.Error())
			}
			c()
		}
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
