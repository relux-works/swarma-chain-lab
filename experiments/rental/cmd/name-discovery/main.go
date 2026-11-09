// name-discovery builds/checks local public snapshots, never reads a node or
// publishes a name. Exit 1 means validly parsed drift; exit 2 means invalid input.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/relux-works/swarma-chain-lab/experiments/rental/discovery"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func run(args []string, out io.Writer) int {
	f := flag.NewFlagSet("name-discovery", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	inv := f.String("inventory", "", "public inventory JSON")
	record := f.String("record", "", "optional public d/ record JSON")
	refuse := func() int { fmt.Fprintln(out, `{"error":"INPUT"}`); return 2 }
	if f.Parse(args) != nil || f.NArg() != 0 || *inv == "" {
		return refuse()
	}
	raw, e := su.PublicFile(*inv, 65536)
	var i discovery.Inventory
	if e != nil || su.StrictInput(raw, &i) != nil {
		return refuse()
	}
	if *record == "" {
		r, e := discovery.Expected(i)
		if e != nil {
			return refuse()
		}
		json.NewEncoder(out).Encode(r)
		return 0
	}
	raw, e = su.PublicFile(*record, 4096)
	var r discovery.Record
	if e != nil || su.StrictInput(raw, &r) != nil {
		return refuse()
	}
	d, e := discovery.Check(r, i)
	if e != nil {
		return refuse()
	}
	json.NewEncoder(out).Encode(d)
	if !d.OK {
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
