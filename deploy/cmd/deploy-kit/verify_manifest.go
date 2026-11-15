package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

func verifyManifest(args []string, out io.Writer) error {
	f := flag.NewFlagSet("verify-manifest", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("manifest", "", "release manifest JSON file")
	commit := f.String("commit", "", "expected full 40-hex release commit")
	if f.Parse(args) != nil || f.NArg() != 0 || *path == "" || len(*commit) != 40 {
		return errors.New("VERIFY_MANIFEST_INPUT")
	}
	if _, e := hex.DecodeString(*commit); e != nil {
		return errors.New("VERIFY_MANIFEST_INPUT")
	}
	file, e := os.Open(*path)
	if e != nil {
		return errors.New("VERIFY_MANIFEST_READ")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return errors.New("VERIFY_MANIFEST_READ")
	}
	// The builder and g2-ledger use this same contract, including the complete
	// binary linkage inventory and every module's StrictParseCommit verdict.
	m, e := deploy.ValidateManifest(raw)
	if e != nil {
		return errors.New("VERIFY_MANIFEST_INVALID")
	}
	if m.Commit != *commit {
		return errors.New("VERIFY_MANIFEST_COMMIT")
	}
	if _, e = fmt.Fprintf(out, "verified manifest commit=%s binaries=%d strict=%s\n", m.Commit, len(m.Linkage), deploy.StrictParseCommit); e != nil {
		return errors.New("VERIFY_MANIFEST_OUTPUT")
	}
	return nil
}
