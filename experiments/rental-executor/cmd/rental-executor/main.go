package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	executor "github.com/relux-works/swarma-chain-lab/experiments/rental-executor"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type config struct {
	Executor    executor.Config   `json:"executor"`
	StateDir    string            `json:"state_dir"`
	Socket      string            `json:"socket"`
	Observer    singleuse.Route   `json:"observer"`
	Broadcast   singleuse.Route   `json:"broadcast"`
	TrackBState string            `json:"trackb_state"`
	TrackBAdmin string            `json:"trackb_admin_socket"`
	TrackBClaim string            `json:"trackb_claim_socket"`
	Prizes      map[string]string `json:"prize_b_keys"`
}

func run() error {
	path := flag.String("config", "", "private JSON configuration file")
	prizeCheck := flag.Bool("prize-check", false, "report pinned prize outpoint using own node, then exit")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		return fmt.Errorf("CONFIG_REQUIRED")
	}
	f, e := os.OpenFile(*path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return fmt.Errorf("CONFIG_READ")
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || i.Size() > 1<<20 {
		return fmt.Errorf("CONFIG_FILE")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() || st.Nlink != 1 {
		return fmt.Errorf("CONFIG_OWNER")
	}
	raw := make([]byte, i.Size())
	if _, e = f.ReadAt(raw, 0); e != nil {
		return fmt.Errorf("CONFIG_READ")
	}
	var c config
	if executor.Strict(raw, &c) != nil {
		return fmt.Errorf("CONFIG_SCHEMA")
	}
	node, e := singleuse.NewRPC(c.Observer)
	if e != nil {
		return e
	}
	if *prizeCheck {
		v, e := executor.WatchPrize(context.Background(), node, c.Executor.Prize)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(v)
	}
	if c.Observer.Host != c.Broadcast.Host || c.Observer.Port != c.Broadcast.Port {
		return fmt.Errorf("NODE_ROUTE_MISMATCH")
	}
	broadcaster, e := executor.NewBroadcaster(c.Broadcast)
	if e != nil {
		return e
	}
	x, e := executor.Open(c.StateDir, c.Executor, node, broadcaster)
	if e != nil {
		return e
	}
	defer x.Close()
	b, e := executor.OpenTrackB(c.TrackBState, "regtest", c.Prizes)
	if e != nil {
		return e
	}
	defer b.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var servers []*http.Server
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	defer func() {
		for _, s := range servers {
			_ = s.Close()
		}
		wg.Wait()
	}()
	for _, endpoint := range []struct {
		path    string
		handler http.Handler
	}{{c.Socket, executor.ExecutorHandler(x)}, {c.TrackBAdmin, executor.TrackBHandler(b, true)}, {c.TrackBClaim, executor.TrackBHandler(b, false)}} {
		l, e := executor.ListenUnix(endpoint.path)
		if e != nil {
			return e
		}
		s := executor.HTTPServer(endpoint.handler)
		servers = append(servers, s)
		wg.Go(func() {
			e := s.Serve(l)
			if e != nil && e != http.ErrServerClosed {
				errs <- fmt.Errorf("HTTP_SERVE")
			}
		})
	}
	fmt.Println(`{"status":"ready","network":"regtest"}`)
	select {
	case <-ctx.Done():
	case e := <-errs:
		return e
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
