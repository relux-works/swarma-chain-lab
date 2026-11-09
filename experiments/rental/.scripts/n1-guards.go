// Run from rental: go run .scripts/n1-guards.go -out .temp/n1-guards
// Mutations use a private module copy; dependencies are read-only symlink targets.
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
	Name, File, Old, New, Package, Test, Witness string
}

var plants = []plant{
	{"agent_builder_equality", "landlord_value.go", "if descriptor != nil && descriptor.Names.Root != binding.Nostr {", "if descriptor != nil && descriptor.Names.Root != binding.Nostr && false {", ".", "TestN1Values", "agent mismatch builder accepted"},
	{"agent_parser_equality", "landlord_value.go", "if v.Nostr != nil && v.Nostr.Names.Root != b.Nostr {", "if v.Nostr != nil && v.Nostr.Names.Root != b.Nostr && false {", ".", "TestN1Refusals", "N1 cross-key guard"},
	{"agent_parser_bound", "landlord_value.go", "var v agentBindingValue\n\tif len(raw) > 520 || canonical([]byte(raw), &v) != nil {", "var v agentBindingValue\n\tif canonical([]byte(raw), &v) != nil {", ".", "TestN1ByteBoundary/agent", "N1 521 parser guard"},
	{"agent_parser_schema", "landlord_value.go", "var v agentBindingValue\n\tif len(raw) > 520 || canonical([]byte(raw), &v) != nil {", "var v agentBindingValue\n\tif len(raw) > 520 || json.Unmarshal([]byte(raw), &v) != nil {", ".", "TestN1Refusals/extra", "N1 invalid agent accepted"},
	{"agent_builder_bound", "landlord_value.go", "if len(b) > 520 {\n\t\treturn \"\", bad(\"AGENT_BINDING_VALUE\")", "if len(b) > 520 && false {\n\t\treturn \"\", bad(\"AGENT_BINDING_VALUE\")", ".", "TestN1ByteBoundary/agent", "N1 521 builder guard"},
	{"landlord_parser_bound", "landlord_value.go", "var v landlordBindingValue\n\tif len(raw) > 520 || canonical([]byte(raw), &v) != nil {", "var v landlordBindingValue\n\tif canonical([]byte(raw), &v) != nil {", ".", "TestN1ByteBoundary/landlord", "N1 521 parser guard"},
	{"landlord_parser_schema", "landlord_value.go", "var v landlordBindingValue\n\tif len(raw) > 520 || canonical([]byte(raw), &v) != nil {", "var v landlordBindingValue\n\tif len(raw) > 520 || json.Unmarshal([]byte(raw), &v) != nil {", ".", "TestN1Refusals/extra", "N1 invalid landlord accepted"},
	{"landlord_builder_bound", "landlord_value.go", "if len(b) > 520 {\n\t\treturn \"\", bad(\"LANDLORD_VALUE\")", "if len(b) > 520 && false {\n\t\treturn \"\", bad(\"LANDLORD_VALUE\")", ".", "TestN1ByteBoundary/landlord", "N1 521 builder guard"},
	{"social_key", "nostr_value.go", "if !pubkey(d.Names.Root) {", "if !pubkey(d.Names.Root) && false {", ".", "TestN1DescriptorGuards/key", "N1 descriptor builder guard"},
	{"relay_arity", "nostr_value.go", "if len(d.Relays) != 1 {", "if len(d.Relays) != 1 && false {", ".", "TestN1DescriptorGuards/relay_arity", "N1 descriptor builder guard"},
	{"relay_root", "nostr_value.go", "!ok || len(relays) == 0", "(!ok && false) || (ok && len(relays) == 0)", ".", "TestN1DescriptorGuards/relay_root", "N1 descriptor builder guard"},
	{"relay_nonempty", "nostr_value.go", "!ok || len(relays) == 0", "!ok", ".", "TestN1DescriptorGuards/relay_empty", "N1 descriptor builder guard"},
	{"relay_scheme", "nostr_value.go", " || (u.Scheme != \"ws\" && u.Scheme != \"wss\")", "", ".", "TestN1DescriptorGuards/scheme", "N1 descriptor builder guard"},
	{"relay_host", "nostr_value.go", " || u.Hostname() == \"\"", "", ".", "TestN1DescriptorGuards/host", "N1 descriptor builder guard"},
	{"relay_userinfo", "nostr_value.go", " || u.User != nil", "", ".", "TestN1DescriptorGuards/userinfo", "N1 descriptor builder guard"},
	{"relay_fragment", "nostr_value.go", " || u.Fragment != \"\"", "", ".", "TestN1DescriptorGuards/fragment", "N1 descriptor builder guard"},
	{"relay_duplicate", "nostr_value.go", " || seen[raw]", "", ".", "TestN1DescriptorGuards/duplicate", "N1 descriptor builder guard"},
	{"discovery_root", "discovery/discovery.go", "v.Nostr.Names == nil || !key(v.Nostr.Names[\"_\"])", "v.Nostr.Names == nil", "./discovery", "TestDiscoverySemanticGuards", "discovery root guard"},
	{"discovery_key", "discovery/discovery.go", "if !key(k) {", "if !key(k) && false {", "./discovery", "TestDiscoverySemanticGuards", "discovery key guard"},
	{"discovery_label", "discovery/discovery.go", "if name != \"_\" && !label(name) {", "if name != \"_\" && !label(name) && false {", "./discovery", "TestDiscoveryRefusals", "discovery label guard"},
	{"discovery_reserved", "discovery/discovery.go", "if name == \"_\" {", "if name == \"_\" && false {", "./discovery", "TestDiscoverySemanticGuards", "discovery reserved guard"},
	{"discovery_builder_bound", "discovery/discovery.go", "if len(raw) > 520 {", "if len(raw) > 520 && false {", "./discovery", "TestDiscoveryBytes", "discovery 521 builder guard"},
	{"discovery_parser_bound", "discovery/discovery.go", "len(raw) > 520 || len(raw) == 0", "len(raw) == 0", "./discovery", "TestDiscoveryBytes", "discovery 521 parser guard"},
	{"discovery_canonical", "discovery/discovery.go", "if e != nil || !bytes.Equal(encoded, []byte(raw)) {", "if e != nil || (!bytes.Equal(encoded, []byte(raw)) && false) {", "./discovery", "TestDiscoveryRefusals", "discovery parser guard"},
	{"inventory_nil", "discovery/discovery.go", " || i.Agents == nil", "", "./discovery", "TestInventoryGuards/nil_agents", "inventory independent guard"},
	{"inventory_landlord_namespace", "discovery/discovery.go", "!strings.HasPrefix(i.Landlord, \"id/\") || !label(strings.TrimPrefix(i.Landlord, \"id/\"))", "false", "./discovery", "TestInventoryGuards/landlord_namespace", "inventory independent guard"},
	{"inventory_agent_namespace", "discovery/discovery.go", "!validID(a.Name) || ", "", "./discovery", "TestInventoryGuards/agent_namespace", "inventory independent guard"},
	{"inventory_same_name", "discovery/discovery.go", " || a.Name == i.Landlord", "", "./discovery", "TestInventoryGuards/agent_same_name", "inventory independent guard"},
	{"inventory_duplicate_name", "discovery/discovery.go", " || seen[a.Name]", "", "./discovery", "TestInventoryGuards/duplicate_name", "inventory independent guard"},
	{"inventory_duplicate_label", "discovery/discovery.go", "if _, ok := agents[a.Label]; ok {", "if _, ok := agents[a.Label]; ok && false {", "./discovery", "TestInventoryGuards/duplicate_label", "inventory independent guard"},
	{"inventory_pointer", "discovery/discovery.go", " || binding.Landlord != i.Landlord", "", "./discovery", "TestInventoryGuards/pointer", "inventory independent guard"},
	{"discovery_name", "discovery/discovery.go", "if record.Name != expected.Name {", "if record.Name != expected.Name && false {", "./discovery", "TestDiscovery", "discovery namespace guard"},
	{"drift_missing", "discovery/discovery.go", "out.Missing = append(out.Missing, label)", "out.Missing = out.Missing", "./discovery", "TestDiscovery/missing", "discovery drift guard"},
	{"drift_extra", "discovery/discovery.go", "out.Extra = append(out.Extra, label)", "out.Extra = out.Extra", "./discovery", "TestDiscovery/extra", "discovery drift guard"},
	{"drift_key", "discovery/discovery.go", "out.Mismatched = append(out.Mismatched, label)", "out.Mismatched = out.Mismatched", "./discovery", "TestDiscovery/key", "discovery drift guard"},
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
	out := flag.String("out", ".temp/n1-guards", "evidence directory")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module github.com/relux-works/swarma-chain-lab/experiments/rental\n")) {
		return errors.New("run from rental module")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "n1-guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"single-use", "sealwatch", "payment-chain", "rental-booking"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	module := filepath.Join(work, "module")
	if e = copyModule(root, module); e != nil {
		return e
	}
	runTest := func(name, pkg, test string) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = module
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "M1_REGTEST=0")
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
		if ctx.Err() != nil {
			return code, b, ctx.Err()
		}
		if e = os.WriteFile(filepath.Join(runDir, name+".log"), b, 0600); e != nil {
			return code, b, e
		}
		return code, b, nil
	}
	if code, _, e := runTest("baseline", "./...", "(TestN1.*|TestDiscovery.*|TestInventory.*)"); e != nil || code != 0 {
		return fmt.Errorf("baseline exit %d: %v", code, e)
	}
	results := []result{}
	for _, p := range plants {
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
		code, b, runErr := runTest(p.Name, p.Package, p.Test)
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
