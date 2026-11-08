// Command gateway runs the rental gateway locally (regtest/stub
// kernel) and provides the scripted station stub used by the
// local-test driver:
//
//	gateway keygen -out agent.key
//	gateway serve -key agent.key -journal ./journal -relay ws://127.0.0.1:7777 -station-unix ./gateway.sock -slot-file slot.json
//	gateway station-stub   (env GATEWAY_SOCKET, SLOT_ID, STATION_NAME)
//
// Stop it by PID. It binds only what flags name; station sockets are
// unix paths and relays in tests are 127.0.0.1.
package main

import (
	"flag"
	"fmt"
	"os"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: gateway <keygen|serve|station-stub> [flags]")
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
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
