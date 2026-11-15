package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

func run(args []string, out, errs io.Writer) int {
	f := flag.NewFlagSet("notary-check", flag.ContinueOnError)
	f.SetOutput(errs)
	var in check.Input
	var paths [10]string
	names := []string{"parent", "child", "parent-contract", "child-contract", "request", "policy", "notary-value", "statement", "parent-text", "child-text"}
	for i, n := range names {
		f.StringVar(&paths[i], n, "", "exact input octets (see DESIGN.md)")
	}
	f.Int64Var(&in.At, "at", 0, "required explicit Unix time")
	if f.Parse(args) != nil || f.NArg() != 0 {
		fmt.Fprintln(out, "REFUSED ARGUMENTS")
		return 2
	}
	targets := []*[]byte{&in.Parent, &in.Child, &in.ParentContract, &in.ChildContract, &in.Request, &in.Policy, &in.NotaryValue, &in.Statement, &in.ParentText, &in.ChildText}
	for i, p := range paths {
		if p == "" {
			if i < 8 {
				fmt.Fprintln(out, "REFUSED INPUT_REQUIRED")
				return 2
			}
			continue
		}
		file, e := os.Open(p)
		if e != nil {
			fmt.Fprintln(out, "REFUSED INPUT_READ")
			return 2
		}
		b, e := io.ReadAll(io.LimitReader(file, 65537))
		closeErr := file.Close()
		if e != nil || closeErr != nil || len(b) > 65536 {
			fmt.Fprintln(out, "REFUSED INPUT_READ")
			return 2
		}
		*targets[i] = b
	}
	r, e := check.Check(in)
	if e != nil {
		fmt.Fprintln(out, "REFUSED", e)
		return 1
	}
	fmt.Fprintln(out, "ATTEST", r.Digest)
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
