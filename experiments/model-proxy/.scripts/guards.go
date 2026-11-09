// Run from model-proxy: go run .scripts/guards.go -out .temp/guards.
// Mutations touch only copied modules; each must reach its named assertion.
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
	"github.com/relux-works/swarma-chain-lab/deploy/workspace"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct{ Name, Module, File, Old, New, Package, Test, Witness string }

var plants = []plant{
	{"bearer", "proxy", "registry.go", "subtle.ConstantTimeCompare([]byte(r.Bearer), []byte(bearer)) != 1", "(false && subtle.ConstantTimeCompare([]byte(r.Bearer), []byte(bearer)) != 1)", ".", "TestBearerRefusals/unknown", "unauthorized forwarded/leaked"},
	{"expiry", "proxy", "registry.go", "now >= r.Binding.NotAfter", "(false && now >= r.Binding.NotAfter)", ".", "TestBearerRefusals/expired", "unauthorized forwarded/leaked"},
	{"active", "proxy", "registry.go", "|| r.Phase != \"active\" || now < r.Binding.NotBefore", "|| (false && r.Phase != \"active\") || now < r.Binding.NotBefore", ".", "TestBearerRefusals/revoked", "unauthorized forwarded/leaked"},
	{"input_cap", "proxy", "registry.go", "next.Input > c.InputTokens", "(false && next.Input > c.InputTokens)", ".", "TestCaps/input", "cap overrun forwarded"},
	{"output_cap", "proxy", "registry.go", "next.Output > c.OutputTokens", "(false && next.Output > c.OutputTokens)", ".", "TestCaps/output", "cap overrun forwarded"},
	{"request_cap", "proxy", "registry.go", "next.Requests > c.Requests", "(false && next.Requests > c.Requests)", ".", "TestCaps/requests", "cap overrun forwarded"},
	{"cost_cap", "proxy", "registry.go", "next.Cost > c.CostNanoUSD", "(false && next.Cost > c.CostNanoUSD)", ".", "TestCaps/cost", "cap overrun forwarded"},
	{"per_request", "proxy", "registry.go", "p.MaxTokens > c.MaxTokens", "(false && p.MaxTokens > c.MaxTokens)", ".", "TestCaps/per-request", "cap overrun forwarded"},
	{"write_before_forward", "proxy", "registry.go", "if e = s.save(); e != nil {\n\t\treturn nil, nil, e\n\t}", "// planted: omit durable reservation", ".", "TestWriteBeforeForward", "failed state write forwarded"},
	{"uncertain_retention", "proxy", "registry.go", "\tr.Pending = nil\n\ts.state.Records[id] = r", "\tif u == nil { r.Exposure.Input -= p.Usage.Input; r.Exposure.Output -= p.Usage.Output; r.Exposure.Cost -= p.Cost }\n\tr.Pending = nil\n\ts.state.Records[id] = r", ".", "TestUncertainReservation/http-error", "uncertain exposure refunded"},
	{"cumulative_usage", "proxy", "messages.go", "u.Output = n", "u.Output += n", ".", "TestStreamAccounting/valid", "cumulative stream not settled"},
	{"auth_stripping", "proxy", "http.go", "s.cfg.Dialect.Headers(req.Header, s.cfg.APIKey)", "s.cfg.Dialect.Headers(req.Header, s.cfg.APIKey); req.Header.Set(\"x-api-key\", r.Header.Get(\"x-api-key\"))", ".", "TestRegistryAndUsage", "client auth/header escaped"},
	{"paid_profile", "proxy", "messages.go", "m[\"service_tier\"] = json.RawMessage(`\"standard_only\"`)", "m[\"service_tier\"] = json.RawMessage(`\"auto\"`)", ".", "TestRegistryAndUsage", "priced upstream profile not pinned"},
	{"body_log", "proxy", "http.go", "p, e := s.cfg.Dialect.Parse(raw)", "s.audit(id, 200, string(raw), Usage{}); p, e := s.cfg.Dialect.Parse(raw)", ".", "TestStreamAccounting/valid", "private content logged"},
	{"peer", "proxy", "admin.go", "if valid, ok := r.Context().Value(peerKey{}).(bool); !ok || !valid {", "if valid, ok := r.Context().Value(peerKey{}).(bool); (!ok || !valid) && false {", ".", "TestAdminBoundary", "unverified peer accepted"},
	{"activate_order", "binding", "driver.go", "e = d.cfg.ModelRegistrar.Activate(call, binding)", "_ = call; _ = binding; e = nil", ".", "TestModelLifecycle", "start omitted model activation"},
	{"revoke", "binding", "driver.go", "revokeErr = d.cfg.ModelRegistrar.Revoke(call, binding)", "_ = call; _ = binding; revokeErr = nil", ".", "TestModelLifecycle", "end omitted model revoke"},
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
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module github.com/relux-works/swarma-chain-lab/experiments/model-proxy\n")) {
		return errors.New("run from model-proxy")
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
	for _, name := range []string{"single-use", "sealwatch", "rental", "rental-booking", "payment-chain", "rental-gateway"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"station-lifecycle", "model-proxy"} {
		if e = copyModule(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	modules := map[string]string{"proxy": filepath.Join(work, "model-proxy"), "binding": filepath.Join(work, "station-lifecycle", "gatewaybind")}
	fixtureWork, e := workspace.Isolate(root, work)
	if e != nil {
		return e
	}
	runTest := func(name, module, pkg, test string) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = modules[module]
		cmd.Env = append(os.Environ(), "GOWORK="+fixtureWork, "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
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
		if e = os.WriteFile(filepath.Join(runDir, name+".log"), b, 0600); e != nil {
			return code, b, e
		}
		if ctx.Err() != nil {
			return code, b, ctx.Err()
		}
		return code, b, nil
	}
	// Every named negative control must first pass unmodified, not merely compile.
	for _, p := range plants {
		code, b, e := runTest("baseline-"+p.Name, p.Module, p.Package, p.Test)
		if e != nil || code != 0 || !bytes.Contains(b, []byte("--- PASS: "+p.Test)) {
			return fmt.Errorf("baseline %s missing/pass failure: exit=%d error=%v", p.Name, code, e)
		}
	}
	results := []result{}
	for _, p := range plants {
		file := filepath.Join(modules[p.Module], p.File)
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
		code, b, runErr := runTest(p.Name, p.Module, p.Package, p.Test)
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
	fmt.Printf("%d/%d intended guard failures\n", len(results), len(plants))
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
