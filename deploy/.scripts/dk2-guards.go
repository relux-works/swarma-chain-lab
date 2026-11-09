// Command dk2-guards checks that bounded deploy violations reach their intended
// assertion. It copies only this public module and never reads staged secrets.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct{ Name, File, Before, After, Package, Test, Witness string }
type result struct {
	Name                                 string
	BaselineExit, Exit, BaselinePID, PID int
	Detected                             bool
	Before, After                        string
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func copyModule(from, to string) error {
	return filepath.WalkDir(from, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(from, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".temp" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(to, rel), 0700)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in module")
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular input")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0600)
	})
}
func command(root, pkg, test, log string) (int, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", test, "-v", pkg)
	c.Dir = root
	c.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
	f, e := os.OpenFile(log, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	defer f.Close()
	c.Stdout = f
	c.Stderr = f
	if e = c.Start(); e != nil {
		return -1, 0
	}
	pid := c.Process.Pid
	e = c.Wait()
	if ctx.Err() != nil {
		return -2, pid
	}
	if e == nil {
		return 0, pid
	}
	if ex, ok := e.(*exec.ExitError); ok {
		return ex.ExitCode(), pid
	}
	return -1, pid
}
func main() {
	out := flag.String("out", ".temp/dk2-guards", "new evidence parent")
	flag.Parse()
	root, e := os.Getwd()
	must(e)
	if _, e = os.Stat(filepath.Join(root, "services.go")); e != nil {
		panic("run from deploy module")
	}
	must(os.MkdirAll(*out, 0700))
	run, e := os.MkdirTemp(*out, "run-")
	must(e)
	run, e = filepath.Abs(run)
	must(e)
	must(os.MkdirAll(filepath.Join(root, ".temp"), 0700))
	scratch, e := os.MkdirTemp(filepath.Join(root, ".temp"), "dk2-plants-")
	must(e)
	defer os.RemoveAll(scratch)
	plants := []plant{
		{"main_model_precision", "model_terms.go", "n > (1<<53)-1", "false", ".", "^TestMainModelIntegerPrecision$", "browser-inexact cap accepted"},
		{"main_missing_native", "main_profile.go", "if len(inputs) != want {\n\t\treturn ErrPolicy", "if len(inputs) != want {\n\t\treturn nil", ".", "^TestMainServiceProfiles$/^store$", "incomplete native accepted"},
		{"main_daily_cap", "issuer_config.go", "c.MovedDay >= c.MovedPerTx", "true", ".", "^TestMainNativeRefusals$", "want deploy: invalid policy got <nil>"},
		{"main_gateway_model", "gateway_config.go", "!c.valid()", "(false && !c.valid())", ".", "^TestMainNativeRefusals$/^gateway$/^model_proxy.caps.requests$", "got <nil>"},
		{"main_store_bound", "main_profile.go", "c.MaxBlobs < 1", "false", ".", "^TestMainNativeRefusals$/^store$/^max_blobs$", "got <nil>"},
		{"main_booking_depth", "main_profile.go", "coin.MinConfirmations < 1", "false", ".", "^TestMainNativeRefusals$/^booking$/^config.coins.nmc.min_confirmations$", "got <nil>"},
		{"payload_pinned_required", "services.go", "return validatePayloadInputs(inputs)", "return nil", ".", "^TestPayloadPairing$/^messages$/^missing-config$", "unpinned payload deployment accepted"},
		{"payload_dialect", "payload_pair.go", "p.Dialect != want", "false && p.Dialect != want", ".", "^TestPayloadPairing$/^responses$/^legacy$", "unpinned payload deployment accepted"},
		{"payload_profile", "payload_pair.go", "p.Dialect != want", "false && p.Dialect != want", ".", "^TestPayloadPairing$/^messages$/^dialect$", "unpinned payload deployment accepted"},
		{"payload_model", "payload_pair.go", "m, ok := c.Models[p.Model]", "m, ok := c.Models[p.Model]; if !ok {m = modelSpec{ContextTokens: 100}; ok = true}", ".", "^TestPayloadPairing$/^messages$/^model$", "unpinned payload deployment accepted"},
		{"payload_endpoint", "payload_pair.go", "p.Endpoint != c.Endpoint.URL", "false && p.Endpoint != c.Endpoint.URL", ".", "^TestPayloadPairing$/^responses$/^endpoint$", "unpinned payload deployment accepted"},
		{"payload_pin", "payload_pair.go", "p.CertSHA256 != c.Endpoint.CertSHA256", "false && p.CertSHA256 != c.Endpoint.CertSHA256", ".", "^TestPayloadPairing$/^responses$/^pin$", "unpinned payload deployment accepted"},
		{"model_upstream_pair", "services.go", "upstreamValid = modelResponsesURL(c.Upstream)", "upstreamValid = true", ".", "^TestModelResponsesProfiles$/^mismatch$", "Responses public config guard missing"},
		{"model_profile", "services.go", "p.Profile != \"openai-responses-functions-default-v1\"", "false", ".", "^TestModelResponsesProfiles$/^profile$", "Responses public config guard missing"},
		{"model_profile_id", "services.go", "!exists || p.Profile", "(false && !exists) || p.Profile", ".", "^TestModelResponsesProfiles$/^model$", "Responses public config guard missing"},
		{"model_profile_endpoint", "services.go", "!modelResponsesURL(p.Upstream)", "false", ".", "^TestModelResponsesProfiles$/^http$", "Responses public config guard missing"},
		{"wallet_peer", "wallet_config.go", "c.PeerUID == 0", "false", ".", "^TestWalletDeployment$/^peer_root$", "wallet deploy guard"},
		{"wallet_key", "wallet_config.go", `c.ReceiptKeyFile != "/etc/swarma/wallet/receipt.key"`, "false", ".", "^TestWalletDeployment$/^key$", "wallet deploy guard"},
		{"wallet_socket", "wallet_config.go", `c.Socket != "/run/swarma-wallet/wallet.sock"`, "false", ".", "^TestWalletDeployment$/^socket$", "wallet deploy guard"},
		{"wallet_unit", "templates/systemd/swarma-wallet.service.in", "NoNewPrivileges=true", "NoNewPrivileges=false", ".", "^TestWalletDeployment$", "wallet unit boundary"},
		{"coin_version", "coins.go", "g.Exchange.Version != 2", "false", ".", "^TestPaymentCoinProvisioning$", "coin mismatch accepted"},
		{"issuer_budget", "issuer_config.go", "caps.BudgetDay < caps.BudgetHour", "false", ".", "^TestIssuerConfigBoundaries$/^partial-caps$", "issuer guard missing"},
		{"model_key", "services.go", `c.TLSKey != "/etc/swarma/model/tls.key"`, "false", ".", "^TestModelConfigBoundaries$/^tls-key$", "model guard missing"},
		{"manager_payload", "services.go", "!digestPin(c.PayloadSHA256)", "false", ".", "^TestStationsConfigBoundaries$/^payload$", "manager guard missing"},
		{"descriptor_path", "services.go", "p != want", "false", ".", "^TestNewServicePolicies$/^issuer$/^foreign-state$", "descriptor guard missing"},
		{"cli_dispatch", "cmd/deploy-kit/main.go", "deploy.ValidateServiceInputs(p, publicInputs)", "func() error { return nil }()", "./cmd/deploy-kit", "^TestValidateModelInputs$", "missing new native config accepted"},
		{"canonical_model", "services.go", "serviceDecode(raw, &c, true)", "serviceDecode(raw, &c, false)", ".", "^TestNewNativeFraming$/^model$", "noncanonical native input accepted"},
		{"unit_write_path", "templates/systemd/swarma-model.service.in", "ReadWritePaths=/run/swarma-model", "ReadWritePaths=/run/swarma-model\nReadWritePaths=/etc", ".", "^TestDK2UnitWritePaths$", "foreign or duplicate writable path"},
	}
	results := []result{}
	for _, p := range plants {
		dir := filepath.Join(scratch, p.Name)
		must(copyModule(root, dir))
		before, e := os.ReadFile(filepath.Join(dir, p.File))
		must(e)
		count := bytes.Count(before, []byte(p.Before))
		if count != 1 && !(p.Name == "canonical_model" && count == 2) {
			panic("plant must match exactly")
		}
		baseline, bpid := command(dir, p.Package, p.Test, filepath.Join(run, "baseline-"+p.Name+".log"))
		after := bytes.Replace(before, []byte(p.Before), []byte(p.After), 1)
		must(os.WriteFile(filepath.Join(dir, p.File), after, 0600))
		log := filepath.Join(run, p.Name+".log")
		code, pid := command(dir, p.Package, p.Test, log)
		b, e := os.ReadFile(log)
		must(e)
		detected := baseline == 0 && code == 1 && strings.Contains(string(b), p.Witness) && !bytes.Contains(b, []byte("build failed")) && !bytes.Contains(b, []byte("panic:")) && !bytes.Contains(b, []byte("--- SKIP"))
		results = append(results, result{p.Name, baseline, code, bpid, pid, detected, fmt.Sprintf("%x", sha256.Sum256(before)), fmt.Sprintf("%x", sha256.Sum256(after))})
		encoded, e := json.MarshalIndent(results, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(run, "results.json"), encoded, 0600))
		fmt.Printf("%s baseline=%d exit=%d detected=%t\n", p.Name, baseline, code, detected)
		if !detected {
			must(os.RemoveAll(scratch))
			os.Exit(1)
		}
	}
	fmt.Println("evidence:", run)
}
