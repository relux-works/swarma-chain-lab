package main

import (
	"context"
	"flag"
	"fmt"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run() error {
	listen := flag.String("listen", "", "numeric loopback host:port")
	state := flag.String("state", "", "existing private state directory")
	flag.Parse()
	if !booking.LoopbackAddress(*listen) {
		return fmt.Errorf("LOOPBACK_REQUIRED")
	}
	relay, e := booking.NewLocalRelay(*state)
	if e != nil {
		return e
	}
	defer relay.Close()
	l, e := net.Listen("tcp", *listen)
	if e != nil {
		return fmt.Errorf("LISTEN")
	}
	defer l.Close()
	srv := &http.Server{Handler: relay, ReadHeaderTimeout: 3 * time.Second, MaxHeaderBytes: 8192}
	ctx, c := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer c()
	ch := make(chan error, 1)
	go func() { ch <- srv.Serve(l) }()
	fmt.Printf("listening ws://%s\n", l.Addr())
	select {
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(stop)
	case e := <-ch:
		if e == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("RELAY_SERVER")
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
