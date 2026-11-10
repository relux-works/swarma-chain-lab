// Compare two completed same-scenario public E2E1 interim reports.
package main

import (
	"bytes"
	"fmt"
	rehearsal "github.com/relux-works/swarma-chain-lab/experiments/m5-rehearsal"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "USAGE: compare-canonical first-result.json second-result.json")
		os.Exit(2)
	}
	projections := make([][]byte, 2)
	for i, path := range os.Args[1:] {
		info, e := os.Stat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			fmt.Fprintln(os.Stderr, "CANONICAL_INPUT")
			os.Exit(2)
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			fmt.Fprintln(os.Stderr, "CANONICAL_INPUT")
			os.Exit(2)
		}
		projections[i], e = rehearsal.CanonicalProjection(raw)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
	}
	if !bytes.Equal(projections[0], projections[1]) {
		fmt.Fprintln(os.Stderr, "CANONICAL_OUTCOME_MISMATCH")
		os.Exit(1)
	}
	fmt.Println("CANONICAL_OUTCOMES_EQUAL")
	fmt.Println(string(projections[0]))
}
