package main

import (
	"encoding/json"
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
	var offlinePath string
	f.StringVar(&offlinePath, "offline-name-fixture", "", "LAB/OFFLINE pinned name observations; never running chain evidence")
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
	offline := offlinePath != ""
	if offline {
		fmt.Fprintln(errs, "LAB/OFFLINE: pinned name fixture; no chain read or live authority")
		file, e := os.Open(offlinePath)
		if e != nil {
			fmt.Fprintln(out, "REFUSED INPUT_READ")
			return 2
		}
		raw, e := io.ReadAll(io.LimitReader(file, 65537))
		closeErr := file.Close()
		var source offlineNames
		if e != nil || closeErr != nil || len(raw) > 65536 || json.Unmarshal(raw, &source) != nil {
			fmt.Fprintln(out, "REFUSED INPUT_READ")
			return 2
		}
		in.Names = source
	}
	var r check.Result
	var e error
	if offline {
		r, e = check.Check(in)
	} else {
		r, e = check.CheckRunning(in)
	}
	if e != nil {
		fmt.Fprintln(out, "REFUSED", e)
		return 1
	}
	if offline {
		fmt.Fprintln(out, "ATTEST", r.Digest, "offline-fixture")
	} else {
		fmt.Fprintln(out, "ATTEST", r.Digest)
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// offlineNames is confined to the explicit CLI fixture path; CheckRunning
// refuses any injected NameSource, including this unexported type.
type offlineName struct {
	Name         string      `json:"name"`
	Registration check.Point `json:"registration"`
	Value        string      `json:"value"`
	Height       int64       `json:"height"`
	BlockHash    string      `json:"blockhash"`
	Unreadable   bool        `json:"unreadable,omitempty"`
}
type offlineNames []offlineName

func (f offlineNames) Lookup(name string, height int64, blockhash string) (check.NameObservation, error) {
	for _, n := range f {
		if n.Name == name && !n.Unreadable {
			return check.NameObservation{Registration: n.Registration, Value: []byte(n.Value), Height: n.Height, BlockHash: n.BlockHash}, nil
		}
	}
	return check.NameObservation{}, check.Refusal("MVP_NAME_UNREADABLE")
}
