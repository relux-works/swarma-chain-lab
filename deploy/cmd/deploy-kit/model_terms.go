package main

import (
	"flag"
	"fmt"
	deploy "github.com/relux-works/swarma-chain-lab/deploy"
	"io"
	"os"
)

func checkModelTerms(args []string) error {
	f := flag.NewFlagSet("check-model-terms", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	paths := []*string{f.String("booking", "", "public ServiceV2 config"), f.String("profile", "", "exact public booking profile bytes"), f.String("gateway", "", "public gateway config"), f.String("model", "", "public model config"), f.String("payload", "", "public payload pairing")}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return deploy.ErrPolicy
	}
	var inputs [][]byte
	for _, path := range paths {
		file, e := os.Open(*path)
		if e != nil {
			return deploy.ErrPolicy
		}
		raw, e := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		closed := file.Close()
		if e != nil || closed != nil || len(raw) > 1<<20 {
			return deploy.ErrPolicy
		}
		inputs = append(inputs, raw)
	}
	if e := deploy.CompareModelTerms(inputs[0], inputs[1], inputs[2], inputs[3], inputs[4]); e != nil {
		return e
	}
	fmt.Println("MODEL_TERMS_MATCH")
	return nil
}
