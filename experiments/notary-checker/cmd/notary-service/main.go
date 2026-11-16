package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-chain-lab/experiments/notary-checker/internal/service"
)

func run(ctx context.Context, args []string, out io.Writer) int {
	fail := func(code string) int { fmt.Fprintln(out, code); return 1 }
	if len(args) < 1 {
		return fail("ARGUMENTS")
	}
	flags := flag.NewFlagSet("notary-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var path string
	switch args[0] {
	case "keygen":
		flags.StringVar(&path, "out", "", "new host key file")
	case "serve":
		flags.StringVar(&path, "config", "", "strict service config")
	default:
		return fail("ARGUMENTS")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || path == "" {
		return fail("ARGUMENTS")
	}
	if args[0] == "keygen" {
		pub, e := service.Keygen(path)
		if e != nil {
			return fail("KEY_FILE")
		}
		fmt.Fprintln(out, pub)
		return 0
	}
	s, e := service.Load(path)
	if e != nil {
		return fail(e.Error())
	}
	defer s.Close()
	if e = s.Run(ctx); e != nil {
		return fail(e.Error())
	}
	return 0
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout))
}
