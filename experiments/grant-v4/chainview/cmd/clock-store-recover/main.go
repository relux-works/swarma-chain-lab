// clock-store-recover performs an explicit audited continuity recovery. Stop all
// users of the store and inspect both records before invoking this command.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/chainview"
)

func main() {
	snapshot := flag.String("snapshot", "", "existing snapshot file")
	sentinel := flag.String("sentinel", "", "sentinel in a disjoint directory")
	audit := flag.String("audit", "", "durable recovery audit file")
	flag.Parse()
	if *snapshot == "" || *sentinel == "" || *audit == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "snapshot, sentinel and audit paths are required")
		os.Exit(2)
	}
	if _, err := chainview.RecoverFileStoreAt(*snapshot, *sentinel, *audit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := chainview.RecoveryAudit(*audit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
