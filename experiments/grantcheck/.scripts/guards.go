// Run from grantcheck: go run .scripts/guards.go -out .temp/guards [-core]
// Each plant changes only an isolated copy. A compile error, skip, panic or
// unrelated failed assertion never counts as detecting the intended violation.
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
	Name, File, Old, New, Test, Witness string
	Core                                bool
}

var plants = []plant{
	{"foreign_grantee", "checker.go", "g.GranteeKey != peer || ", "", "TestInputBoundary/foreign", "verdict contract", false},
	{"explicit_invalid_fallback", "checker.go", "g, code = c.parse(p, peer)\n\t\tif code != CodeLive {\n\t\t\treturn fail(code)", "g, code = c.parse(p, peer)\n\t\tif code != CodeLive {\n\t\t\treturn c.check(ctx, peer, nil, inbound)", "TestInputBoundary", "verdict contract", false},
	{"proof_bound", "checker.go", "const MaxPresentationBytes = 16384", "const MaxPresentationBytes = 32768", "TestInputBoundary/oversize", "verdict contract", false},
	{"receipt_id", "checker.go", "r.GrantID != p.GrantID || ", "", "TestInconsistentReceipts/grant", "verdict contract", false},
	{"receipt_agent", "checker.go", "r.AgentName != g.AgentName || ", "", "TestInconsistentReceipts/agent", "verdict contract", false},
	{"receipt_landlord", "checker.go", "r.LandlordName != g.LandlordName || ", "", "TestInconsistentReceipts/landlord", "verdict contract", false},
	{"receipt_clock", "checker.go", " || r.CheckedAt != now", "", "TestInconsistentReceipts/clock", "verdict contract", false},
	{"backend_error", "checker.go", "if err != nil {\n\t\treturn fail(CodeCheckFailed)", "if err != nil && false {\n\t\treturn fail(CodeCheckFailed)", "TestInconsistentReceipts/error-live", "verdict contract", false},
	{"receipt_scope", "checker.go", "v.Decision == Live && !slices.Equal(r.Scope, g.Scope)", "v.Decision == Live && !slices.Equal(r.Scope, g.Scope) && false", "TestInconsistentReceipts/scope", "verdict contract", false},
	{"state_identity", "checker.go", " || m.Binding != c.binding", "", "TestStateBinding", "state relabeled", false},
	{"clock_rollback", "checker.go", "now < m.High || ", "", "TestClockBoundaries/rollback", "verdict contract", false},
	{"expiry_after_check", "checker.go", "if end >= g.NotAfter {", "if end >= g.NotAfter && false {", "TestClockBoundaries/expiry", "verdict contract", false},
	{"outbound_exchange", "checker.go", "return c.check(ctx, recipient, nil, false)", "return c.check(ctx, recipient, nil, true)", "TestFreshCacheAndOutbound", "verdict contract", false},
	{"retryable", "verdict.go", "v.Retryable = true", "v.Retryable = false", "TestRoutingContract", "routing contract", false},
	{"not_yet", "reasons.go", "code = CodeNotYet", "code = CodeNoGrant", "TestProductionWindow/not_yet", "verdict contract", false},
	{"expiry_routing", "reasons.go", "code = CodeExpired", "code = CodeNoGrant", "TestProductionWindow/expired", "verdict contract", false},
	{"cache_fresh", "checker.go", "r, err = c.backend.Check(ctx, p.Bytes, c.config.AgentName, peer, now)", "r = kernel.Receipt{Verdict: kernel.Live, Reason: \"LIVE\", GrantID:p.GrantID, AgentName:g.AgentName, LandlordName:g.LandlordName, CheckedAt:now, Scope:g.Scope}", "TestFreshCacheAndOutbound", "cache bypassed fresh check", false},
	{"nonlive_scope", "checker.go", "if v.Decision != Live {\n\t\treturn v", "if v.Decision != Live {\n\t\tv.Scope = slices.Clone(g.Scope)\n\t\treturn v", "TestFreshCacheAndOutbound", "refusal leaked actionable scope", false},
	{"read_failure", "reasons.go", "code = CodeVerifierUnavailable", "code = CodeLive", "TestCoreVectors", "want refused/verifier_unavailable", true},
	{"mempool_closure", "reasons.go", "code := CodeCheckFailed", "if r.Reason == \"SEAL_SPENT\" { r.Verdict = kernel.Live; r.Reason = \"LIVE\"; r.Closed = false }; code := CodeCheckFailed", "TestCoreVectors", "want exchange/seal_spent", true},
	{"confirmed_rotation", "reasons.go", "code := CodeCheckFailed", "if r.Reason == \"LANDLORD_KEY_ROTATED\" { r.Verdict = kernel.Live; r.Reason = \"LIVE\"; r.Closed = false }; code := CodeCheckFailed", "TestCoreVectors", "want exchange/landlord_rotated", true},
	{"pending_rotation", "reasons.go", "code = CodeIdentityPending", "code = CodeNoGrant", "TestCoreVectors", "want refused/identity_pending", true},
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
	out := flag.String("out", ".temp/guards", "evidence directory")
	core := flag.Bool("core", false, "include pinned Core controls; CG1_CORE_* required")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module relux.works/swarma-chain-lab/experiments/grantcheck\n")) {
		return errors.New("run from grantcheck module")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"rental", "rental-gateway", "single-use", "sealwatch", "rental-booking", "payment-chain"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	module := filepath.Join(work, "grantcheck")
	if e = copyModule(root, module); e != nil {
		return e
	}
	runTest := func(name, test string, useCore bool) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", ".")
		cmd.Dir = module
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "CG1_REGTEST=0")
		if useCore {
			cmd.Env = append(cmd.Env, "CG1_REGTEST=1", "CG1_RUN_ROOT="+filepath.Join(runDir, name+"-core"))
		}
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if e := cmd.Start(); e != nil {
			return -1, nil, e
		}
		pid := cmd.Process.Pid
		e := cmd.Wait()
		code := 0
		if e != nil {
			var x *exec.ExitError
			if !errors.As(e, &x) {
				return -1, output.Bytes(), e
			}
			code = x.ExitCode()
		}
		b := append([]byte(fmt.Sprintf("owned test-command PID %d\n", pid)), output.Bytes()...)
		if e = os.WriteFile(filepath.Join(runDir, name+".log"), b, 0600); e != nil {
			return code, b, e
		}
		if ctx.Err() != nil {
			return code, b, ctx.Err()
		}
		return code, b, nil
	}
	for _, useCore := range []bool{false, true} {
		if useCore && !*core {
			continue
		}
		name, test := "baseline-unit", "Test.*"
		if useCore {
			name, test = "baseline-core", "TestCoreVectors"
		}
		code, b, e := runTest(name, test, useCore)
		if e != nil || code != 0 || !bytes.Contains(b, []byte("--- PASS:")) {
			return fmt.Errorf("baseline %s exit%d: %v", name, code, e)
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
		code, b, runErr := runTest(p.Name, p.Test, p.Core)
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
