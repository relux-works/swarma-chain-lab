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
