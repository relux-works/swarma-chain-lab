package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	deploy "relux.works/swarma-chain-lab/deploy"
)

func checkCoins(args []string) error {
	flags := flag.NewFlagSet("check-coins", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	g := flags.String("gateway", "", "public gateway config")
	b := flags.String("booking", "", "public ServiceV2 config")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return deploy.ErrPolicy
	}
	read := func(path string) ([]byte, error) {
		f, e := os.Open(path)
		if e != nil {
			return nil, deploy.ErrPolicy
		}
		defer f.Close()
		raw, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if e != nil {
			return nil, deploy.ErrPolicy
		}
		return raw, nil
	}
	gr, e := read(*g)
	if e != nil {
		return e
	}
	br, e := read(*b)
	if e != nil {
		return e
	}
	if e = deploy.ComparePaymentCoins(gr, br); e != nil {
		return e
	}
	fmt.Println("COIN_SETS_MATCH")
	return nil
}
