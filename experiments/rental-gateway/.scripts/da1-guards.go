// Run from rental-gateway: go run .scripts/da1-guards.go -out .temp/da1-guards
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
	{"input_persist", "gateway", "journal/delivery.go", "if e := st.persistDeliveryLocked(next); e != nil {\n\t\treturn false, e", "if e := error(nil); e != nil {\n\t\treturn false, e", "./journal", "TestDeliveryJournal", "input not durable before screening"},
	{"input_checksum", "gateway", "journal/delivery.go", "d.Checksum != deliveryChecksum(d) || ", "", "./gateway", "TestDeliveryCorruptOutbox", "corrupt outbox admitted"},
	{"reply_immutable", "gateway", "gateway/delivery.go", "if d.Reply != content {", "if false && d.Reply != content {", "./gateway", "TestDeliveryCrashRetry", "different reply admitted"},
	{"accepted_dedup", "gateway", "gateway/delivery.go", "if d.Phase == journal.DeliveryAccepted {", "if false && d.Phase == journal.DeliveryAccepted {", "./gateway", "TestDeliveryCrashRetry", "accepted reply published again"},
	{"exact_wire", "gateway", "gateway/delivery.go", "event, e := nostr.ParseEvent(d.Wire)", "event, _, e := nostr.WrapDM(g.cfg.AgentKey, slot.RenterPubKey, content, [][]string{{\"e\", id}}, g.cfg.Now().Unix())", "./gateway", "TestDeliveryCrashRetry", "retry regenerated signed bytes"},
	{"write_before_publish", "gateway", "gateway/delivery.go", "e = g.cfg.Journal.ChangeDelivery(slot.ID, id, journal.DeliveryReady, content, wire)", "e = nil", "./gateway", "TestDeliveryWriteBeforePublish", "publish preceded durable outbox"},
	{"receive_required", "gateway", "journal/delivery.go", "allowed = d.Phase == DeliveryReceived", "allowed = d.Phase == DeliveryReceived || d.Phase == DeliveryQueued", "./journal", "TestDeliveryJournal", "reply before receive ACK"},
	{"screening_boundary", "gateway", "journal/delivery.go", "case DeliveryQueued, DeliveryReceived, DeliveryReady:", "case DeliveryScreening, DeliveryQueued, DeliveryReceived, DeliveryReady:", "./gateway", "TestDeliveryScreeningUncertain", "uncertain input dispatched"},
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
	out := flag.String("out", ".temp/da1-guards", "evidence directory")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module github.com/relux-works/swarma-chain-lab/experiments/rental-gateway\n")) {
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "da1-guard-work-")
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
	for _, b := range []struct{ module, pkg, test string }{{"gateway", "./gateway", "TestDelivery.*"}, {"gateway", "./journal", "TestDelivery.*"}} {
		code, _, e := runTest("baseline-"+strings.ReplaceAll(b.pkg, "/", "-"), b.module, b.pkg, b.test)
		if e != nil || code != 0 {
			return fmt.Errorf("baseline %s exit %d: %v", b.pkg, code, e)
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

// Copied-fixture instrumentation only; these strings are never linked into the CLI.
