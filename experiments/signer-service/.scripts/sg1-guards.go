// Run from signer-service: go run .scripts/sg1-guards.go -out .temp/sg1-guards [-core]
// Mutations use a private module copy; dependencies are read-only symlink targets.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct {
	Name, File, Old, New, Package, Test, Witness string
	Core                                         bool
}

var plants = []plant{
	{"presentation_conflict", "presentation.go", "!bytes.Equal(b, raw)", "false && !bytes.Equal(b, raw)", ".", "TestPresentationRefusals/conflict", "unsafe presentation published or overwritten", false},
	{"presentation_confirmation", "presentation.go", "return fail(\"PRESENTATION_UNCONFIRMED\")", "return publishPresentation(ctx,x.cfg.PresentationDir,op.Intent.BookingID,r.Presentation)", ".", "TestCoreBookingComposition", "unconfirmed publication gate", true},
	{"presentation_stability", "presentation.go", "if e = o.Stable(); e != nil {", "if e = nil; e != nil {", ".", "TestCoreBookingComposition", "untrusted confirmation published", true},
	{"mainnet", "types.go", "if p.Network != \"regtest\" || p.Genesis != su.RegtestGenesis {", "if (p.Network != \"regtest\" || p.Genesis != su.RegtestGenesis) && false {", ".", "TestStartupNetwork", "want REGTEST_ONLY", false},
	{"key_pin", "keys.go", "e != nil || actual != script", "e != nil || (actual != script && false)", ".", "TestKeyCustody/wrong-key", "unsafe key accepted", false},
	{"cursor_zero", "outbox.go", "c = fileCursor{}", "// removed zero initialization", ".", "TestFileSource", "want OUTBOX_CURSOR", false},
	{"outbox_hash", "outbox.go", "if hash(raw) != index[i] {", "if hash(raw) != index[i] && false {", ".", "TestFileSource", "want OUTBOX_HASH", false},
	{"issuance_cap", "engine.go", "if hc >= c.CountHour || dc >= c.CountDay || i.BudgetSat > c.BudgetHour-hv || i.BudgetSat > c.BudgetDay-dv {", "if (hc >= c.CountHour || dc >= c.CountDay || i.BudgetSat > c.BudgetHour-hv || i.BudgetSat > c.BudgetDay-dv) && false {", ".", "TestPreflightNoEffects", "want ISSUANCE_CAP", false},
	{"pending_cap", "engine.go", "pending := r.Phase != \"stored\"", "pending := false; _ = r", ".", "TestCapsAcrossRecovery", "want ISSUANCE_CAP", false},
	{"clock", "engine.go", "now < 1 || now < x.state.LastTime", "now < 1 || (now < x.state.LastTime && false)", ".", "TestCapsAcrossRecovery", "want CLOCK_ROLLBACK", false},
	{"unknown_template", "process.go", "return Result{}, fail(\"TEMPLATE_REFUSED\")", "return Result{}, nil", ".", "TestPreflightNoEffects", "want TEMPLATE_REFUSED", false},
	{"source_authority", "process.go", "if source == BookingSource {", "if source == BookingSource && r.Reason != \"operator\" {", ".", "TestRevokeSourceAndSuppression", "want REVOKE_AUTHORITY", false},
	{"funding_script", "engine.go", "if in.Script != p.FundingScript || in.Script == p.SealScript {", "if (in.Script != p.FundingScript || in.Script == p.SealScript) && false {", ".", "TestPreflightNoEffects", "unexpected node call", false},
	{"signed_template", "keys.go", "func verifySignedPlan(plan rental.Plan, raw []byte) error {", "func verifySignedPlan(plan rental.Plan, raw []byte) error {\n return nil", ".", "TestSignedTemplateRecovery", "changed signed transaction accepted", false},
	{"fee_cap", "process.go", "if fee > x.cfg.Caps.FeePerTx {", "if fee > x.cfg.Caps.FeePerTx && false {", ".", "TestFeeCapNoEffects", "unexpected node call", false},
	{"signing_uncertainty", "process.go", "if r.Phase == \"signing_uncertain\" {\n\t\treturn result(), fail(\"SIGNING_UNCERTAIN\")\n\t}", "if r.Phase == \"signing_uncertain\" { r.Phase=\"prepared\" }", ".", "TestCoreCrashRecovery/signing_uncertain", "uncertainty signed again", true},
	{"own_payment_gate", "issuer_v2.go", "if result.Verdict != \"admit\" {", "if result.Verdict != \"admit\" && false {", ".", "TestCoreV2Payments/btc", "reorg allocated authority", true},
	{"durable_tx_verify", "engine.go", "verifySignedPlan(want, raw) != nil", "(verifySignedPlan(want, raw) != nil && false)", ".", "TestCoreService", "corrupt durable transaction accepted", true},
}

type result struct {
	Plant                        plant
	Exit                         int
	Detected                     bool
	OriginalSHA256, MutantSHA256 string
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/sg1-guards", "evidence directory")
	core := flag.Bool("core", false, "also run genuine isolated Core controls; requires SG1_CORE_* and SG1_BTC_*")
	only := flag.String("only", "", "run only a named plant and its baseline")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module relux.works/swarma-chain-lab/experiments/signer-service\n")) {
		return errors.New("run from signer-service module")
	}
	evidence, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(evidence, 0700); e != nil {
		return e
	}
	runDir, e := os.MkdirTemp(evidence, "run-")
	if e != nil {
		return e
	}
	fmt.Println("evidence:", runDir)
	if e = os.MkdirAll(filepath.Join(root, ".temp"), 0700); e != nil {
		return e
	}
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "sg1-guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"single-use", "sealwatch", "payment-chain", "rental-booking", "rental", "grant-store", "rental-gateway"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	module := filepath.Join(work, "module")
	if e = copyModule(root, module); e != nil {
		return e
	}
	runTest := func(name, pkg, test string, useCore bool) (int, []byte, error) {
		name = strings.ReplaceAll(name, "/", "-")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = module
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "SG1_REGTEST=0")
		if useCore {
			cmd.Env = append(cmd.Env, "SG1_REGTEST=1", "SG1_RUN_ROOT="+filepath.Join(runDir, name+"-core"))
		}
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if e := cmd.Start(); e != nil {
			return -1, nil, e
		}
		pid := cmd.Process.Pid
		e := cmd.Wait()
		b := append([]byte(fmt.Sprintf("owned test-command PID %d\n", pid)), output.Bytes()...)
		code := 0
		if e != nil {
			var x *exec.ExitError
			if !errors.As(e, &x) {
				return -1, b, e
			}
			code = x.ExitCode()
		}
		if ctx.Err() != nil {
			return code, b, ctx.Err()
		}
		if e = os.WriteFile(filepath.Join(runDir, name+".log"), b, 0600); e != nil {
			return code, b, e
		}
		return code, b, nil
	}
	if code, _, e := runTest("baseline", "./...", "Test.*", false); e != nil || code != 0 {
		return fmt.Errorf("baseline exit %d: %v", code, e)
	}

	if *core {
		seen := map[string]bool{}
		for _, p := range plants {
			if !p.Core || (*only != "" && p.Name != *only) || seen[p.Test] {
				continue
			}
			seen[p.Test] = true
			code, b, e := runTest("baseline-"+p.Test, p.Package, p.Test, true)
			if e != nil || code != 0 || !bytes.Contains(b, []byte("--- PASS: "+strings.Split(p.Test, "/")[0])) {
				return fmt.Errorf("Core baseline %s exit %d: %v", p.Test, code, e)
			}
		}
	}

	results := []result{}
	for _, p := range plants {
		if (p.Core && !*core) || (*only != "" && p.Name != *only) {
			continue
		}
		file := filepath.Join(module, p.File)
		original, e := os.ReadFile(file)
		if e != nil {
			return e
		}
		if n := strings.Count(string(original), p.Old); n != 1 {
			return fmt.Errorf("plant %s applies %d times", p.Name, n)
		}
		mutant := []byte(strings.Replace(string(original), p.Old, p.New, 1))
		if e = os.WriteFile(file, mutant, 0600); e != nil {
			return e
		}
		code, b, runErr := runTest(p.Name, p.Package, p.Test, p.Core)
		restoreErr := os.WriteFile(file, original, 0600)
		if runErr != nil {
			return runErr
		}
		if restoreErr != nil {
			return restoreErr
		}
		detected := code == 1 && bytes.Contains(b, []byte("--- FAIL: "+p.Test)) && bytes.Contains(b, []byte(p.Witness)) && !bytes.Contains(b, []byte("[build failed]")) && !bytes.Contains(b, []byte("panic:"))
		results = append(results, result{p, code, detected, hash(original), hash(mutant)})
		raw, _ := json.MarshalIndent(results, "", "  ")
		if e = os.WriteFile(filepath.Join(runDir, "results.json"), append(raw, '\n'), 0600); e != nil {
			return e
		}
		fmt.Printf("%s exit=%d detected=%v\n", p.Name, code, detected)
		if !detected {
			return fmt.Errorf("plant %s did not reach intended assertion", p.Name)
		}
	}
	if len(results) == 0 {
		return errors.New("no selected controls")
	}
	fmt.Printf("%d/%d intended guard failures (core=%v)\n", len(results), len(results), *core)
	return nil
}
func copyModule(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".temp" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0700)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected module symlink")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0600)
	})
}
