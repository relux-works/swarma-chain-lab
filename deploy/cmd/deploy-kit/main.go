package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: deploy-kit build|validate|check-coins|check-model-terms|render-install-anchor|g2-render|g2-host-flow|g2-agent-groups|g2-custody-probe|g2-custody-verify|g2-funded-preflight|g2-custody-hash [flags]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "g2-render":
		return g2Render(args[1:], os.Stdout)
	case "g2-host-flow":
		return g2HostFlow(args[1:], os.Stdout)
	case "g2-agent-groups":
		return g2AgentGroups(args[1:], os.Stdout)
	case "g2-custody-probe":
		return g2CustodyProbe(args[1:], os.Stdout)
	case "g2-custody-verify":
		return g2CustodyVerify(args[1:], os.Stdout)
	case "g2-custody-hash":
		return g2CustodyHash(args[1:], os.Stdout)
	case "g2-funded-preflight":
		return g2FundedPreflight(args[1:], os.Stdout)
	case "render-install-anchor":
		return renderInstallAnchor(args[1:], os.Stdout)
	case "check-model-terms":
		return checkModelTerms(args[1:])
	case "check-coins":
		return checkCoins(args[1:])
	case "build":
		repo := f.String("repo", "", "canonical clean repository root")
		commit := f.String("commit", "", "exact HEAD commit SHA")
		out := f.String("out", "", "new absolute release directory outside repository")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if f.NArg() != 0 {
			return deploy.ErrInput
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		m, e := deploy.BuildRelease(ctx, deploy.ReleaseInput{Repo: *repo, Commit: *commit, Out: *out})
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(m)
	case "validate":
		path := f.String("config", "", "public deploy policy JSON (not credential file)")
		var publicFiles paths
		f.Var(&publicFiles, "public", "additional native public JSON file; repeat for each file, never credentials")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if f.NArg() != 0 {
			return deploy.ErrInput
		}
		file, e := os.Open(*path)
		if e != nil {
			return deploy.ErrPolicy
		}
		defer file.Close()
		raw, e := io.ReadAll(io.LimitReader(file, 16385))
		if e != nil {
			return deploy.ErrPolicy
		}
		p, e := deploy.Validate(raw)
		if e != nil {
			return e
		}
		var publicInputs [][]byte
		for _, path := range publicFiles {
			file, e := os.Open(path)
			if e != nil {
				return deploy.ErrPolicy
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil {
				return deploy.ErrPolicy
			}
			publicInputs = append(publicInputs, raw)
		}
		if e := deploy.ValidateServiceInputs(p, publicInputs); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(struct{ Status, Service, Network string }{"valid-public-policy", p.Service, p.Network})
	default:
		return errors.New("unknown deploy-kit command")
	}
}

type paths []string

func (p *paths) String() string { return "public JSON paths" }
func (p *paths) Set(value string) error {
	if len(*p) >= 8 {
		return deploy.ErrInput
	}
	*p = append(*p, value)
	return nil
}
