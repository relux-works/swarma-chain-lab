// Run from rental-gateway: go run .scripts/ga1-guards.go -out .temp/ga1-guards
// Each mutation is isolated in a copied module; original sources are untouched.
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
	Name, Module, File, Old, New, Package, Test, Witness string
}

var plants = []plant{
	{"auth_relay", "gateway", "gateway/relayclient.go", "{\"relay\", c.URL}", "{\"relay\", c.URL + \"/wrong\"}", "./gateway", "TestRelayAuthReconnect", "auth binding invalid"},
	{"auth_challenge", "gateway", "gateway/relayclient.go", "{\"challenge\", challenge}", "{\"challenge\", challenge + \"wrong\"}", "./gateway", "TestRelayAuthReconnect", "auth binding invalid"},
	{"auth_positive_ack", "gateway", "gateway/relayclient.go", "if !ok {\n\t\t\t\t\tc.mu.Unlock()", "if !ok && false {\n\t\t\t\t\tc.mu.Unlock()", "./gateway", "TestRelayAuthRefusals/rejected", "auth refusal"},
	{"auth_key_preflight", "gateway", "gateway/relayclient.go", "c.Auth == RelayAuthRequired && c.AgentKey == nil", "c.Auth == RelayAuthRequired && c.AgentKey == nil && false", "./gateway", "TestRelayAuthRefusals/missing-key", "missing key dialed relay"},
	{"auth_required_gate", "gateway", "gateway/relayclient.go", "c.awaitAuth(ctx, s, 0, c.Auth == RelayAuthRequired)", "c.awaitAuth(ctx, s, 0, false)", "./gateway", "TestRelayAuthRefusals/no-challenge", "unauthenticated REQ escaped"},
	{"auth_closed_code", "gateway", "gateway/relayclient.go", "return ErrRelayRejected\n}", "return errors.New(reason)\n}", "./gateway", "TestRelayAuthRetry/EVENT/off/restricted:", "closed refusal"},
	{"registrar_pin", "gateway", "cmd/gateway/model_proxy.go", "credential.Endpoint != r.endpoint", "(credential.Endpoint != r.endpoint && false)", "./cmd/gateway", "TestModelConfiguredLifecycle/wrong-pin", "endpoint pin guard missing"},
	{"registrar_wiring", "gateway", "cmd/gateway/model_proxy.go", "if p := c.ModelProxy; p != nil {", "if p := c.ModelProxy; p != nil && false {", "./cmd/gateway", "TestModelRuntimeWiring", "runtime omitted registrar"},
	{"registrar_caps", "gateway", "cmd/gateway/model_proxy.go", " && m.Caps.Valid()", " && (m.Caps.Valid() || true)", "./cmd/gateway", "TestModelProxyConfig", "partial model config accepted"},
	{"deploy_partial", "deploy", "policy.go", "return gatewayOptions(v.(map[string]any))", "return nil", ".", "TestGatewayOptions", "partial model section accepted"},
	{"presentation_root", "gateway", "presentationdir/directory.go", "path == string(filepath.Separator)", "(path == string(filepath.Separator) && false)", "./presentationdir", "TestOpenPathBoundary/root", "forbidden source path accepted"},
	{"presentation_control", "gateway", "presentationdir/directory.go", "strings.ContainsAny(path, \"\\x00\\r\\n\")", "(strings.ContainsAny(path, \"\\x00\\r\\n\") && false)", "./presentationdir", "TestOpenPathBoundary/lf", "forbidden source path accepted"},
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
	out := flag.String("out", ".temp/ga1-guards", "evidence directory")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module relux.works/swarma-chain-lab/experiments/rental-gateway\n")) {
		return errors.New("run from rental-gateway module")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "ga1-guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"rental", "single-use", "sealwatch", "payment-chain", "station-lifecycle", "model-proxy", "signer-service", "grant-store"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	if e = copyModule(filepath.Join(filepath.Dir(filepath.Dir(root)), "deploy"), filepath.Join(work, "deploy")); e != nil {
		return e
	}
	for _, name := range []string{"rental-gateway", "rental-booking"} {
		if e = copyModule(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	modules := map[string]string{"deploy": filepath.Join(work, "deploy"), "gateway": filepath.Join(work, "rental-gateway"), "binding": filepath.Join(work, "rental-gateway", "kernelbind"), "booking": filepath.Join(work, "rental-booking")}
	runTest := func(name, module, pkg, test string) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = modules[module]
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GW1_REGTEST=0")
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
		if e = os.WriteFile(filepath.Join(runDir, name+".log"), b, 0600); e != nil {
			return code, b, e
		}
		if ctx.Err() != nil {
			return code, b, ctx.Err()
		}
		return code, b, nil
	}
	for _, b := range []struct{ module, pkg, test string }{{"gateway", "./gateway", "TestRelay.*"}, {"gateway", "./cmd/gateway", "TestModel.*"}, {"deploy", ".", "TestGatewayOptions"}, {"gateway", "./presentationdir", "TestOpenPathBoundary"}} {
		code, _, e := runTest("baseline-"+b.module+strings.ReplaceAll(b.pkg, "/", "-"), b.module, b.pkg, b.test)
		if e != nil || code != 0 {
			return fmt.Errorf("baseline %s exit %d: %v", b.module, code, e)
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
	fmt.Printf("%d/%d intended guard failures\n", len(results), len(results))
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
