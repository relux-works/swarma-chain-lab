// CC1 fault controls use Go overlays: no source or live state is modified.
// Run at repository root: go run .scripts/cc1-guards.go -out /absolute/new-dir.
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
	"strings"
	"time"
)

type plant struct{ Name, Module, File, Before, After, Test, Witness string }
type result struct {
	Name, SourceSHA256, MutantSHA256     string
	BaselinePID, PID, BaselineExit, Exit int
	Detected                             bool
}

var plants = []plant{
	{"host_contract_caps", "experiments/m5-host-smoke", "runner.go", "!booking.EqualModelCaps(v.ModelCaps, c.ModelCaps)", "false", "^TestContractModelCapsBinding$", "want CONTRACT_BINDING; got <nil>"},
	{"host_expected_caps", "experiments/m5-host-smoke", "config.go", "c.ModelCaps == nil || !c.ModelCaps.Valid()", "false", "^TestExpectedModelCapsRequired$", "want CONFIG_MODEL_CAPS; got OPERATOR_preflight"},
	{"booking_equality", "experiments/rental-booking", "service_v2.go", "!EqualModelCaps(cfg.ModelCaps, cfg.Template.ModelCaps)", "false", "^TestModelCapsAdmission$/^Requests-larger$", "model config: want MODEL_CAPS_MISMATCH"},
	{"template_required", "experiments/rental-booking", "contract.go", "t.Version == 2 && (t.ModelCaps == nil || !t.ModelCaps.Valid())", "false", "^TestModelCapsAdmission$", "model config: want TEMPLATE_MODEL_CAPS"},
	{"config_snapshot", "experiments/rental-booking", "service_v2.go", "cfg = owned", "// control: retain caller pointer", "^TestModelCapsSnapshotOwnership$", "caller mutated service caps"},
	{"catalogue_snapshot", "experiments/rental-booking", "catalogue_v2.go", "t.ModelCaps = copyModelCaps(t.ModelCaps)", "// control: expose service pointer", "^TestModelCapsSnapshotOwnership$", "catalogue mutated signed terms"},
	{"consumer_caps", "experiments/rental", "issuance_v2.go", "c.ModelCaps != nil && !c.ModelCaps.valid()", "false", "^TestV2ModelCapsAuthentication$", "invalid signed cap accepted"},
	{"proxy_default_bound", "experiments/model-proxy", "types.go", "c.DefaultMaxOutputTokens <= c.MaxTokens", "true", "^TestSignedDefaultBindingWithoutInjection$", "oversized default accepted"},
	{"gateway_catalogue_caps", "experiments/rental-gateway", "cmd/gateway/booking_v2.go", "!booking.EqualModelCaps(out.Template.ModelCaps, c.modelCaps)", "false", "^TestBookingV2ModelCapsBinding$", "catalogue cap mismatch"},
	{"gateway_contract_caps", "experiments/rental-gateway", "cmd/gateway/booking_v2.go", "!booking.EqualModelCaps(b.Contract.ModelCaps, c.modelCaps)", "false", "^TestBookingV2ModelCapsBinding$", "contract cap mismatch"},
	{"exchange_contract_hash", "experiments/rental-gateway", "exchange/engine.go", "if len(h.Contract) < 1 || len(h.Contract) > 8192 || hash(h.Contract) != h.ContractSHA256 {", "if len(h.Contract) < 1 || len(h.Contract) > 8192 {", "^TestIssuedContractHandoff$", "invalid status contract registered"},
	{"exchange_contract_copy", "experiments/rental-gateway", "exchange/engine.go", "bound.Contract = append([]byte(nil), h.Contract...)", "bound.Contract = h.Contract", "^TestIssuedContractHandoff$", "registration shares mutable contract bytes"},
	{"journal_contract_hash", "experiments/rental-gateway", "gateway/exchange.go", "hex.EncodeToString(contractHash[:]) != i.ContractSHA256", "(false && hex.EncodeToString(contractHash[:]) != i.ContractSHA256)", "^TestIssuedContractRegistration$", "wrong registration refusal"},
	{"journal_contract_bytes", "experiments/rental-gateway", "gateway/gateway.go", "ContractB64:    base64.StdEncoding.EncodeToString(spec.Contract)", "ContractB64:    \"\"", "^TestIssuedContractRegistration$", "journal lost original contract"},
	{"slot_caps_equality", "experiments/station-lifecycle/gatewaybind", "driver.go", "b.Caps != caps", "false", "^TestModelContractCapsBeforeAllocation$", "wrong refusal"},
	{"slot_contract_hash", "experiments/station-lifecycle/gatewaybind", "model_contract.go", "c.Hash() != s.ContractSHA256", "false", "^TestModelContractBindingRefusals$/^hash$", "wrong contract refusal"},
	{"cleanup_original_caps", "experiments/station-lifecycle/gatewaybind", "driver.go", "binding, err := boundModelBinding(s)", "binding, err := modelBinding(s, d.cfg.ModelCaps)", "^TestModelConfigChangeRefusesStartPreservesRevoke$", "old binding revoke blocked"},
	{"deploy_caps_equality", "deploy", "model_terms.go", "g.ModelProxy.Caps != *t.ModelCaps", "false", "^TestModelTerms$/^Requests$", "mismatched gateway cap accepted"},
	{"deploy_profile_hash", "deploy", "model_terms.go", "digest(profile) != t.ProfileSHA256", "false", "^TestModelTerms$/^profile$", "mismatch accepted"},
	{"deploy_payload_limit", "deploy", "model_terms.go", "pair.MaxTokens > t.ModelCaps.MaxTokens", "false", "^TestModelTerms$/^payload-cap$", "mismatch accepted"},
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
		pkg := "."
		if strings.Contains(p.File, "/") {
			pkg = "./" + filepath.Dir(p.File)
		}
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
