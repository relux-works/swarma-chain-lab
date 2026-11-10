// DK5b consumer API controls use Go overlays: no source or live state is modified.
// Run at repository root: go run .scripts/dk5b-api-guards.go -out /absolute/new-dir.
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
	{"bootstrap_version", "experiments/single-use", "payloadbootstrap/codec/codec.go", "(b.V != 1 && b.V != 2)", "false", "^TestGolden$", "bootstrap verdict", "./payloadbootstrap"},
	{"bootstrap_channel", "experiments/single-use", "payloadbootstrap/codec/codec.go", "len(b.ChannelSecret) != 32", "false", "^TestGolden$", "bootstrap verdict", "./payloadbootstrap"},
	{"bootstrap_station", "experiments/single-use", "payloadbootstrap/codec/codec.go", "len(b.StationName) > 255", "false", "^TestGolden$", "bootstrap verdict", "./payloadbootstrap"},
	{"bootstrap_bearer", "experiments/single-use", "payloadbootstrap/codec/codec.go", "len(b) == 32", "true", "^TestGolden$", "bootstrap verdict", "./payloadbootstrap"},
	{"bootstrap_origin", "experiments/single-use", "payloadbootstrap/codec/codec.go", "u.Path == \"\"", "true", "^TestGolden$", "bootstrap verdict", "./payloadbootstrap"},
	{"bootstrap_canonical", "experiments/single-use", "payloadbootstrap/codec/codec.go", "!bytes.Equal(raw, encoded)", "false && !bytes.Equal(raw, encoded)", "^TestGolden$", "bootstrap verdict", "./payloadbootstrap"},
	{"bootstrap_hash", "experiments/single-use", "payloadbootstrap/bootstrap.go", "sha256.Sum256(b)", "sha256.Sum256(nil)", "^TestGolden$", "bootstrap public projection changed", "./payloadbootstrap"},
	{"bootstrap_mutation", "experiments/single-use", "payloadbootstrap/bootstrap.go", "h := sha256.Sum256(b)", "h := sha256.Sum256(b); b[0] ^= 1", "^TestGolden$", "bootstrap input mutated", "./payloadbootstrap"},
	{"bootstrap_secret_field", "experiments/single-use", "payloadbootstrap/bootstrap.go", "type Bootstrap struct {", "type Bootstrap struct {\n ChannelSecret string `json:\"channel_secret\"`", "^TestPublicFields$", "public bootstrap field set changed", "./payloadbootstrap"},
	{"model_canonical", "experiments/single-use", "modelprofile/profile.go", "!bytes.Equal(b, canonical)", "false && !bytes.Equal(b, canonical)", "^TestGolden$", "model verdict", "./modelprofile"},
	{"model_tokens", "experiments/single-use", "modelprofile/profile.go", "p.MaxTokens > m.ContextTokens", "false", "^TestGolden$", "model verdict", "./modelprofile"},
	{"model_dialect", "experiments/single-use", "modelprofile/profile.go", "p.Dialect != want", "false && p.Dialect != want", "^TestGolden$", "model verdict", "./modelprofile"},
	{"model_endpoint", "experiments/single-use", "modelprofile/profile.go", "p.Endpoint != c.Endpoint.URL", "false", "^TestGolden$", "model verdict", "./modelprofile"},
	{"model_pin", "experiments/single-use", "modelprofile/profile.go", "p.CertSHA256 != c.Endpoint.CertSHA256", "false", "^TestGolden$", "model verdict", "./modelprofile"},
	{"model_profile", "experiments/single-use", "modelprofile/profile.go", "profile.Profile != OpenAIResponsesProfile", "false", "^TestGolden$", "model verdict", "./modelprofile"},
	{"model_length", "experiments/single-use", "modelprofile/profile.go", "len(b) > MaxConfigBytes", "false", "^TestGolden$", "model verdict", "./modelprofile"},
	{"model_loader_delegation", "experiments/model-proxy", "files.go", "return modelprofile.DecodeFileConfig(raw)", "_ = raw; _ = modelprofile.DecodeFileConfig; return FileConfig{},nil", "^TestConsumerConfigGolden$", "consumer config", "."},
	{"model_pair_delegation", "experiments/station-payload", "profile.go", "modelprofile.CheckModelPair(p, c) != nil", "false && modelprofile.CheckModelPair(p, c) != nil", "^TestConsumerModelGolden$", "consumer model verdict", "."},
	{"bootstrap_delegation", "experiments/station-lifecycle/gatewaybind", "bootstrap.go", "return codec.Decode[lifecycle.Secret, proxy.Secret](raw)", "_ = codec.Decode[lifecycle.Secret,proxy.Secret]; return PayloadBootstrap{},nil", "^TestConsumerBootstrapGolden$", "consumer", "."},
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
