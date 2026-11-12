// Command paygrant-v2 is the G2 pay-grant ceremony CLI (PX1 stream S4). It
// holds no private key: signatures come from external signers through the
// offline file exchange. See experiments/rental/PAYGRANT-V2.md.
//
//	paygrant-v2 terms -terms FILE [-out-dir DIR]
//	paygrant-v2 check-request -request FILE
//	paygrant-v2 issue -input FILE -outbox DIR -inbox DIR -out-dir DIR [-timeout 2h] [-poll 2s]
//	paygrant-v2 present -grant FILE -txid HEX -out FILE
//
// Every command prints one JSON object. Exit 0 means the command's own check
// passed; it never means a grant is live (only rental.Check on an own node
// decides that).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const inputLimit = 16384

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func emit(w io.Writer, v any) {
	e := json.NewEncoder(w)
	e.SetEscapeHTML(false)
	_ = e.Encode(v)
}

func refuse(w io.Writer, reason string) int {
	emit(w, map[string]string{"verdict": "refused", "reason": reason})
	return 1
}

// readInput reads a bounded, non-group/world-writable regular file.
func readInput(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("INPUT_PATH")
	}
	return su.PublicFile(path, inputLimit)
}

// writeOutput refuses to overwrite: a ceremony artifact is written once.
func writeOutput(path string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return errors.New("OUTPUT_EXISTS_OR_UNWRITABLE")
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		_ = os.Remove(path)
		return errors.New("OUTPUT_WRITE")
	}
	return nil
}

func run(args []string, stdout io.Writer) int {
	if len(args) < 1 {
		return refuse(stdout, "COMMAND")
	}
	fs := flag.NewFlagSet("paygrant-v2 "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	switch args[0] {
	case "terms":
		termsPath := fs.String("terms", "", "terms v2 JSON (PayTermsV2 members)")
		outDir := fs.String("out-dir", "", "optional directory for <contract_sha256>.json")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
			return refuse(stdout, "ARGUMENTS")
		}
		raw, e := readInput(*termsPath)
		if e != nil {
			return refuse(stdout, "TERMS_INPUT")
		}
		var t rental.PayTermsV2
		if su.StrictInput(raw, &t) != nil {
			return refuse(stdout, "TERMS_INPUT")
		}
		b, e := rental.EncodePayTermsV2(t)
		if e != nil {
			return refuse(stdout, e.Error())
		}
		contract := rental.Hash(b)
		if *outDir != "" {
			if e := writeOutput(filepath.Join(*outDir, contract+".json"), b, 0644); e != nil {
				return refuse(stdout, e.Error())
			}
		}
		emit(stdout, map[string]any{"verdict": "ok", "contract_sha256": contract, "booking_ref": rental.PayGrantBookingRef(b), "terms": json.RawMessage(b)})
		return 0
	case "check-request":
		reqPath := fs.String("request", "", "<purpose>-<digest>.request.json")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
			return refuse(stdout, "ARGUMENTS")
		}
		raw, e := readInput(*reqPath)
		if e != nil {
			return refuse(stdout, "REQUEST_INPUT")
		}
		var req rental.PayGrantSigningRequest
		if su.StrictInput(raw, &req) != nil {
			return refuse(stdout, "REQUEST_INPUT")
		}
		t, e := rental.VerifyPayGrantSigningRequest(req)
		if e != nil {
			return refuse(stdout, e.Error())
		}
		// Shown to the key holder before signing; the signer signs Digest only
		// after this check passed on its own machine.
		emit(stdout, map[string]any{"verdict": "ok", "purpose": req.Purpose, "signer_key": req.SignerKey, "digest": req.Digest, "contract_sha256": rental.Hash(req.Terms), "terms": t})
		return 0
	case "issue":
		inPath := fs.String("input", "", "PayGrantV2Input JSON")
		outbox := fs.String("outbox", "", "directory the signers read requests from")
		inbox := fs.String("inbox", "", "directory the signers write signatures to")
		outDir := fs.String("out-dir", "", "directory for the issued artifacts")
		timeout := fs.Duration("timeout", 2*time.Hour, "overall wait for the three signatures")
		poll := fs.Duration("poll", 2*time.Second, "inbox poll interval")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *outbox == "" || *inbox == "" || *outDir == "" || *timeout <= 0 {
			return refuse(stdout, "ARGUMENTS")
		}
		raw, e := readInput(*inPath)
		if e != nil {
			return refuse(stdout, "ISSUE_INPUT")
		}
		var in rental.PayGrantV2Input
		if su.StrictInput(raw, &in) != nil {
			return refuse(stdout, "ISSUE_INPUT")
		}
		if e := rental.ValidatePayGrantV2Input(in); e != nil {
			return refuse(stdout, e.Error())
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		grantee := rental.NewFileExchangeSigner(*outbox, *inbox, in.GranteeKey, *poll)
		landlord := rental.NewFileExchangeSigner(*outbox, *inbox, in.IssuerKey, *poll)
		r, e := rental.IssuePayGrantV2(ctx, in, grantee, landlord)
		if e != nil {
			return refuse(stdout, e.Error())
		}
		result, _ := json.Marshal(r)
		for _, f := range []struct {
			name string
			body []byte
		}{{r.ContractSHA256 + ".json", r.Terms}, {"signed-grant.json", r.SignedGrant}, {"result.json", result}} {
			if e := writeOutput(filepath.Join(*outDir, f.name), f.body, 0644); e != nil {
				return refuse(stdout, e.Error())
			}
		}
		emit(stdout, map[string]string{"verdict": "issued", "grant_id": r.GrantID, "contract_sha256": r.ContractSHA256, "issuance_commitment": r.IssuanceCommitment})
		return 0
	case "present":
		grantPath := fs.String("grant", "", "signed-grant.json")
		txid := fs.String("txid", "", "confirmed issuance txid")
		out := fs.String("out", "", "presentation output (<grant_id>.json)")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *out == "" {
			return refuse(stdout, "ARGUMENTS")
		}
		raw, e := readInput(*grantPath)
		if e != nil {
			return refuse(stdout, "GRANT_INPUT")
		}
		p, e := rental.PresentIssuedGrant(raw, *txid)
		if e != nil {
			return refuse(stdout, e.Error())
		}
		if e := writeOutput(*out, p, 0644); e != nil {
			return refuse(stdout, e.Error())
		}
		s, _ := rental.ParseSignedGrant(raw)
		emit(stdout, map[string]string{"verdict": "ok", "grant_id": s.ID(), "txid": *txid})
		return 0
	}
	return refuse(stdout, "COMMAND")
}
