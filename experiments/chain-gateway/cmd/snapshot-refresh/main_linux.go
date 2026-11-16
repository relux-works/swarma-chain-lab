package main

import (
	gateway "github.com/relux-works/swarma-chain-lab/experiments/chain-gateway"
	"os"
)

func main() { os.Exit(gateway.Main(os.Args[1:], os.Stderr)) }
