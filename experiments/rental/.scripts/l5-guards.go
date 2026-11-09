// Run from rental: go run .scripts/l5-guards.go -out .temp/l5-guards [-core]
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
	{"writer_frame", "grant_plan.go", "return makeGrantIssuancePlan(p, s, raw, false)", "return makeGrantIssuancePlan(p, s, raw, true)", ".", "TestGrantPlans", "plan commitment or conservation", false},
	{"fee_projection", "grant_plan.go", "size := oplocator.IssuanceBlobScriptBytes", "size := 34", ".", "TestFramedFundingProjection", "framed pre-sign fee undercount", false},
	{"parser_header", "oplocator/oplocator.go", "!bytes.Equal(script[:4], []byte{0x6a, 3, 0x53, 0x4c}) || ", "", "./oplocator", "TestMalformedFrames/wrong_protocol", "malformed framing admitted", false},
	{"parser_action", "oplocator/oplocator.go", " || !actionKnown(script[4])", "", "./oplocator", "TestMalformedFrames/unknown_action", "malformed framing admitted", false},
	{"parser_length", "oplocator/oplocator.go", " || len(script) != 6+n", "", "./oplocator", "TestMalformedFrames/short_length", "malformed framing admitted", false},
	{"parser_version", "oplocator/oplocator.go", "if payload[0] != Version1 {", "if payload[0] != Version1 && false {", "./oplocator", "TestMalformedFrames/unknown_version", "malformed framing admitted", false},
	{"parser_location", "oplocator/oplocator.go", "if !known || len(payload) != 34+length {", "if (!known && false) || len(payload) != 34+length {", "./oplocator", "TestMalformedFrames/unknown_without_pointer", "malformed framing admitted", false},
	{"parser_pointer_length", "oplocator/oplocator.go", "if !known || len(payload) != 34+length {", "if !known || (len(payload) != 34+length && false) {", "./oplocator", "TestMalformedFrames/v1_with_32", "malformed framing admitted", false},
	{"legacy_exact_length", "oplocator/oplocator.go", "len(script) == 34 && script[1] == 32", "len(script) >= 34 && script[1] == 32", "./oplocator", "TestMalformedFrames/legacy_trailing", "malformed framing admitted", false},
	{"legacy_direct_push", "oplocator/oplocator.go", "len(script) == 34 && script[1] == 32", "len(script) == 34", "./oplocator", "TestMalformedFrames/legacy_wrong_push", "malformed framing admitted", false},
	{"builder_action", "oplocator/oplocator.go", "if !actionKnown(action) || !known || len(loc.Pointer) != n {", "if !known || len(loc.Pointer) != n {", "./oplocator", "TestBuilderRejects/action", "invalid builder input accepted", false},
	{"builder_location", "oplocator/oplocator.go", "if !actionKnown(action) || !known || len(loc.Pointer) != n {", "if !actionKnown(action) || (!known && false) || len(loc.Pointer) != n {", "./oplocator", "TestBuilderRejects/unknown_empty", "invalid builder input accepted", false},
	{"builder_pointer_length", "oplocator/oplocator.go", "if !actionKnown(action) || !known || len(loc.Pointer) != n {", "if !actionKnown(action) || !known || (len(loc.Pointer) != n && false) {", "./oplocator", "TestBuilderRejects/blob_short", "invalid builder input accepted", false},
	{"kernel_commitment", "grant_kernel.go", "e != nil || hex.EncodeToString(m.Commitment[:]) != commitment", "e != nil", ".", "TestIssuanceLocatorBinding/commitment", "invalid issuance locator admitted", false},
	{"kernel_pointer", "grant_kernel.go", " && hex.EncodeToString(m.Locator.Pointer) == grantID", "", ".", "TestIssuanceLocatorBinding/pointer", "invalid issuance locator admitted", false},
	{"kernel_action", "grant_kernel.go", "m.Action == oplocator.ActionGrantIssuance && ", "", ".", "TestIssuanceLocatorBinding/batch", "invalid issuance locator admitted", false},
	{"kernel_location", "grant_kernel.go", "m.Locator.Type == oplocator.LocationBlob && ", "", ".", "TestIssuanceLocatorBinding/torrent_v2", "invalid issuance locator admitted", false},
	{"replay_whole_plan", "grant_plan.go", "e == nil && sameJSON(plan, *stored)", "e == nil && (sameJSON(plan, *stored) || true)", ".", "TestCompletedPlanShapes/pointer", "corrupt completed plan admitted", false},
	{"replay_legacy", "grant_plan.go", "[]bool{false, true}", "[]bool{false}", ".", "TestCompletedPlanShapes", "exact completed plan refused", false},
	{"kernel_return_count", "grant_kernel.go", "returns != 1 || matches != 1", "(returns != 1 && false) || matches != 1", ".", "TestCoreGrantLocator/two_returns", "two_returns: want refused/ISSUANCE_COMMITMENT", true},
	{"issuer_replay_gate", "grant_issuer.go", "if !matchesIssuedGrantPlan(p.Policy, spec, old.SignedGrant, old.Plan) {", "if !matchesIssuedGrantPlan(p.Policy, spec, old.SignedGrant, old.Plan) && false {", ".", "TestCoreGrantLocatorReplay", "corrupt completed record escaped replay gate", true},
	{"issuer_fresh_fee", "grant_issuer.go", "if _, _, e := grantFunding(p.Policy, spec, pool); e != nil {", "if _, _, e := grantFunding(p.Policy, spec, pool); e != nil && false {", ".", "TestCoreGrantLocatorReplay", "fresh fee boundary passed pre-sign gate", true},
	{"issuer_old_fee", "grant_issuer.go", "grantFundingShape(p.Policy, spec, pool, true)", "grantFundingShape(p.Policy, spec, pool, false)", ".", "TestCoreGrantLocatorReplay", "FUNDING_OR_DUST_RESERVE", true},
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
	out := flag.String("out", ".temp/l5-guards", "evidence directory")
	core := flag.Bool("core", false, "also run genuine isolated Core controls; requires M1_CORE_* and L5_OLD_ISSUER")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module relux.works/swarma-chain-lab/experiments/rental\n")) {
		return errors.New("run from rental module")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "l5-guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"single-use", "sealwatch"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	module := filepath.Join(work, "module")
	if e = copyModule(root, module); e != nil {
		return e
	}
	runTest := func(name, pkg, test string, useCore bool) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = module
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "M1_REGTEST=0")
		if useCore {
			cmd.Env = append(cmd.Env, "M1_REGTEST=1", "M1_RUN_ROOT="+filepath.Join(runDir, name+"-core"))
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
		for _, test := range []string{"TestCoreGrantLocator", "TestCoreGrantLocatorReplay"} {
			if code, b, e := runTest("baseline-"+test, ".", test, true); e != nil || code != 0 || !bytes.Contains(b, []byte("--- PASS: "+test)) {
				return fmt.Errorf("Core baseline %s exit %d: %v", test, code, e)
			}
		}
	}
	results := []result{}
	for _, p := range plants {
		if p.Core && !*core {
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
