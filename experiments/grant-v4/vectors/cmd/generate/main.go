// Command generate writes deterministic laboratory primitive vectors to stdout.
package main

import (
	"fmt"
	vectors "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/vectors"
	"os"
)

func main() {
	b, err := vectors.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(b); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
