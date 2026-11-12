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
	"time"

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
	// G2 profile only (a "g2" block in the service config): the operator
	// status socket, its group, and the observation tick interval.
	statusSocket := f.String("status-socket", "", "G2 operator status socket")
	statusGID := f.Uint("status-gid", 0, "G2 operator status socket group")
	tickSeconds := f.Int("tick-seconds", 30, "G2 observation tick interval")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 || *path == "" || *statusGID > 1<<31 || *tickSeconds < 1 || *tickSeconds > 3600 {
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
	statusErrors := make(<-chan error)
	if s.PX1Profile() != nil {
		// G2: the startup pass (canary, wallet-versus-journal reconciliation)
		// must pass before the first request is served.
		if *statusSocket != "" && *statusGID == 0 {
			fmt.Fprintln(os.Stderr, "SERVICE_ARGUMENTS")
			return 2
		}
		errs, e := s.RunPX1Observers(ctx, *statusSocket, uint32(*statusGID), time.Duration(*tickSeconds)*time.Second, func(code string) { fmt.Fprintln(os.Stderr, "PX1_TICK "+code) })
		if e != nil {
			fmt.Fprintln(os.Stderr, wallet.ActionErrorReason(e))
			return 2
		}
		statusErrors = errs
	} else if *statusSocket != "" || *statusGID != 0 {
		// W2 has no status socket; a G2 flag without a g2 block is a misconfiguration.
		fmt.Fprintln(os.Stderr, "SERVICE_ARGUMENTS")
		return 2
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx) }()
	statusDone := *statusSocket == ""
	select {
	case e = <-served:
	case e = <-statusErrors:
		statusDone = true
		cancel()
		<-served
	}
	if !statusDone {
		// The status directory (A8) is not removed when the service stops:
		// wait until the listener has closed and unlinked status.sock.
		cancel()
		<-statusErrors
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, wallet.ActionErrorReason(e))
		return 1
	}
	return 0
}
