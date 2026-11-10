// Command gateway runs the configured regtest gateway and provides the
// scripted station stub used only by the explicit local test mode:
//
//	gateway keygen -out agent.key
//	gateway serve -config /absolute/path/to/gateway.json
//	gateway validate -config /absolute/path/to/gateway.json
//	gateway station-stub   (env GATEWAY_SOCKET, SLOT_ID, STATION_NAME)
//
// Stop it by PID. Config pins the local routes and separate remote TLS
// listeners; Unix station sockets are restricted to explicit local-test mode.
package main

import (
	"flag"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"os"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

func main() {
	configguard.CheckMain("gateway")
	if len(os.Args) < 2 {
		fatal("usage: gateway <keygen|serve|validate|station-stub> [flags]")
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "validate":
		err = runValidate(os.Args[2:])
	case "station-stub":
		err = runStationStub()
	default:
		fatal("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gateway: "+format+"\n", args...)
	os.Exit(1)
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "agent key file to create (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	key, err := nostr.GeneratePrivKey()
	if err != nil {
		return err
	}
	if err := gateway.SaveAgentKey(*out, key); err != nil {
		return err
	}
	fmt.Println(key.PubKeyHex())
	return nil
}
