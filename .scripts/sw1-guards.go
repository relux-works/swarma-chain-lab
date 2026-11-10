// SW1 witness controls use Go overlays: no source or live state is modified.
// Run at repository root: go run .scripts/sw1-guards.go -out /absolute/new-dir.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type plant struct{ Name, Module, File, Before, After, Test, Witness, Package string }
type result struct {
	Name, SourceSHA256, MutantSHA256     string
	BaselinePID, PID, BaselineExit, Exit int
	Detected                             bool
}

var plants = []plant{
	{"linkage_script", "experiments/single-use", "witness_observation.go", "!NativeP2WPKH(t.body.Outputs[in.Vout].Script)", "false", "^TestWitnessLinkageScript$", "W linkage script guard", "."},
	{"profile", "experiments/single-use", "witness.go", "if profile != WitnessProfile {", "if false && profile != WitnessProfile {", "^TestWitnessCodecAndProfile$", "W profile fallback", "."},
	{"native_prevout", "experiments/single-use", "witness.go", "if !NativeP2WPKH(prev.Script) || len(in.Script) != 0 {", "if false && (!NativeP2WPKH(prev.Script) || len(in.Script) != 0) {", "^TestWitnessInputProfile$/legacy", "W input guard W_NATIVE_P2WPKH_REQUIRED", "."},
	{"every_input", "experiments/single-use", "witness.go", "for i, in := range w.Body.Inputs {", "for i, in := range w.Body.Inputs[:1] {", "^TestWitnessInputProfile$/none", "W input guard W_SIGHASH_ALL_REQUIRED", "."},
	{"all_only", "experiments/single-use", "witness.go", "if sigbytes[len(sigbytes)-1] != 1 {", "if false && sigbytes[len(sigbytes)-1] != 1 {", "^TestWitnessInputProfile$/anyonecanpay", "W input guard W_SIGHASH_ALL_REQUIRED", "."},
	{"signature", "experiments/single-use", "witness.go", "if !sig.Verify(digest, pub) {", "if false && !sig.Verify(digest, pub) {", "^TestWitnessInputProfile$/wrong-amount", "W input guard W_SIGNATURE_INVALID", "."},
	{"ordinary_confirmation", "experiments/single-use", "witness_observation.go", "if parent.height == 0 || (tx.height > 0 && parent.height >= tx.height) {", "if false && (parent.height == 0 || (tx.height > 0 && parent.height >= tx.height)) {", "^TestWitnessAdditionalParentRefusal$/unconfirmed-payment", "extra parent accepted/wrong refusal", "."},
	{"body_binding", "experiments/single-use", "witness_observation.go", "tx.ID() != id ||", "false ||", "^TestWitnessConstructionGraph$/changed-T-body", "W graph guard W_BODY_BINDING", "."},
	{"dependency_order", "experiments/single-use", "witness_observation.go", "ti < 0 || ai < 0 || ti >= ai", "ti < 0 || ai < 0", "^TestWitnessConstructionGraph$/reversed-order", "W graph guard W_DEPENDENCY_ORDER", "."},
	{"signer_pin", "experiments/signer-service", "types.go", "if e := su.RequireWitnessProfile(p.ConstructionProfile); e != nil {", "if e := su.RequireWitnessProfile(p.ConstructionProfile); false && e != nil {", "^TestWitnessProfileStartup$", "want W_PROFILE_REQUIRED", "."},
	{"adapter_pin", "experiments/grantcheck", "checker.go", "if e := su.RequireWitnessProfile(config.ConstructionProfile); e != nil {", "if e := su.RequireWitnessProfile(config.ConstructionProfile); false && e != nil {", "^TestWitnessProfileConfig$", "W config refusal", "."},
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func hash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func main() {
	out := flag.String("out", "", "new absolute output directory")
	flag.Parse()
	root, e := os.Getwd()
	must(e)
	if !filepath.IsAbs(*out) || flag.NArg() != 0 {
		panic("absolute new output required")
	}
	must(os.Mkdir(*out, 0700))
	var rows []result
	for _, p := range plants {
		module := filepath.Join(root, p.Module)
		source := filepath.Join(module, p.File)
		raw, e := os.ReadFile(source)
		must(e)
		if bytes.Count(raw, []byte(p.Before)) != 1 {
			panic("non-unique plant: " + p.Name)
		}
		mutant := bytes.Replace(raw, []byte(p.Before), []byte(p.After), 1)
		changed := filepath.Join(*out, p.Name+".go")
		must(os.WriteFile(changed, mutant, 0600))
		overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: changed}})
		op := filepath.Join(*out, p.Name+".json")
		must(os.WriteFile(op, overlay, 0600))
		pkg := p.Package
		run := func(plant bool) (int, int, []byte) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			args := []string{"test", "-count=1", "-v", "-run", p.Test}
			name := p.Name + "-baseline.log"
			if plant {
				args = append(args, "-overlay", op)
				name = p.Name + "-plant.log"
			}
			args = append(args, pkg)
			cmd := exec.CommandContext(ctx, "go", args...)
			cmd.Dir = module
			var log bytes.Buffer
			cmd.Stdout = &log
			cmd.Stderr = &log
			must(cmd.Start())
			pid := cmd.Process.Pid
			e := cmd.Wait()
			code := 0
			if e != nil {
				if x, ok := e.(*exec.ExitError); ok {
					code = x.ExitCode()
				} else {
					code = -1
				}
			}
			if ctx.Err() != nil {
				code = -2
			}
			must(os.WriteFile(filepath.Join(*out, name), log.Bytes(), 0600))
			return pid, code, log.Bytes()
		}
		row := result{Name: p.Name, SourceSHA256: hash(raw), MutantSHA256: hash(mutant)}
		var baseline, output []byte
		row.BaselinePID, row.BaselineExit, baseline = run(false)
		if row.BaselineExit != 0 || !bytes.Contains(baseline, []byte("--- PASS:")) {
			panic("baseline not passing: " + p.Name)
		}
		row.PID, row.Exit, output = run(true)
		row.Detected = row.Exit == 1 && bytes.Contains(output, []byte("--- FAIL:")) && bytes.Contains(output, []byte(p.Witness)) && !bytes.Contains(output, []byte("panic:")) && !bytes.Contains(output, []byte("[build failed]"))
		rows = append(rows, row)
		encoded, _ := json.MarshalIndent(rows, "", "  ")
		must(os.WriteFile(filepath.Join(*out, "results.json"), append(encoded, '\n'), 0600))
		fmt.Printf("%s detected=%v baseline=%d plant=%d\n", p.Name, row.Detected, row.BaselineExit, row.Exit)
		if !row.Detected {
			os.Exit(1)
		}
	}
}
