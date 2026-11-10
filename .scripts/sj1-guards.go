// SJ1 JSON controls use Go overlays: no source or live state is modified.
// Run at repository root: go run .scripts/sj1-guards.go -out /absolute/new-dir.
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
	{"typed_map_alias", "experiments/single-use", "policy.go", "if t.Kind() == reflect.Map {", "if false && t.Kind() == reflect.Map {", "^TestSJ1TypedMapKeys$", "SJ1 typed key alias admitted", "."},
	{"shared_duplicate", "experiments/sealwatch", "watch.go", "!ok || keys[s]", "!ok", "^TestSJ1KeyAdmission$/right-valid", "SJ1 ambiguous key admitted", "."},
	{"shared_escape", "experiments/sealwatch", "watch.go", "bytes.IndexByte(data[start:d.InputOffset()], '\\\\') >= 0", "false && start >= 0", "^TestSJ1KeyAdmission$/escaped-single", "SJ1 ambiguous key admitted", "."},
	{"wallet_effect_duplicate", "experiments/agent-wallet", "../sealwatch/watch.go", "!ok || keys[s]", "!ok", "^TestSJ1ReceiptKeys$", "SJ1 ambiguous receipt admitted", "."},
	{"signer_request_duplicate", "experiments/signer-service", "../sealwatch/watch.go", "!ok || keys[s]", "!ok", "^TestSJ1EmbeddedRequest$", "ISSUE_REQUEST", "."},
	{"kernel", "experiments/rental-gateway", "kernel/presentation.go", "su.StrictInput(raw, &p)", "func() error { _ = su.StrictInput; return json.Unmarshal(raw, &p) }()", "^TestSJ1PresentationKeys$", "SJ1 ambiguous presentation admitted", "./kernel"},
	{"nostr", "experiments/rental-gateway", "nostr/event.go", "su.StrictInput(raw, &e)", "func() error { _ = su.StrictInput; return json.Unmarshal(raw, &e) }()", "^TestSJ1EventKeys$", "SJ1 ambiguous event admitted", "./nostr"},
	{"journal", "experiments/rental-gateway", "journal/journal.go", "sw.DecodeJSON(raw, &slot)", "func() error { _ = sw.DecodeJSON; return json.Unmarshal(raw, &slot) }()", "^TestSJ1JournalKeys$", "SJ1 ambiguous journal admitted", "./journal"},
	{"stationlink", "experiments/rental-gateway", "stationlink/stationlink.go", "su.StrictInput(body, &f)", "func() error { _ = su.StrictInput; return json.Unmarshal(body, &f) }()", "^TestSJ1FrameKeys$", "SJ1 ambiguous frame admitted", "./stationlink"},
	{"mint", "experiments/rental-gateway", "station/trackbadmin.go", "su.StrictInput(raw, out)", "func() error { _ = su.StrictInput; return json.Unmarshal(raw, out) }()", "^TestSJ1MintKeys$", "SJ1 ambiguous mint admitted", "./station"},
	{"proxy_duplicate", "experiments/model-proxy", "messages.go", "!ok || seen[s] ||", "!ok || false ||", "^TestSJ1KeyAdmission$", "SJ1 ambiguous key admitted", "."},
	{"proxy_escape", "experiments/model-proxy", "messages.go", "bytes.IndexByte(raw[start:d.InputOffset()], '\\\\') >= 0", "false && start >= 0", "^TestSJ1KeyAdmission$", "SJ1 ambiguous key admitted", "."},
	{"deploy_duplicate", "deploy", "policy.go", "!ok || seen[s] ||", "!ok || false ||", "^TestSJ1KeyAdmission$/right-valid", "SJ1 ambiguous key admitted", "."},
	{"deploy_escape", "deploy", "policy.go", "bytes.IndexByte(raw[start:d.InputOffset()], '\\\\') >= 0", "false && start >= 0", "^TestSJ1KeyAdmission$/escaped-single", "SJ1 ambiguous key admitted", "."},
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
