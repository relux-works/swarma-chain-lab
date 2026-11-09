// Run from rental-gateway: go run .scripts/e1-guards.go -out .temp/e1-guards [-core]
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
	Core                                                 bool
}

var plants = []plant{
	{"first_contact", "gateway", "exchange/engine.go", "&& !CheckWork(r, e.cfg.PowBits)", "&& !CheckWork(r, e.cfg.PowBits) && false", "./exchange", "TestExchangePoW/missing", "invalid PoW allocated state or replied", false},
	{"actual_work", "gateway", "exchange/pow.go", "return n >= difficulty", "return n >= 0", "./exchange", "TestExchangePoW/low_actual", "invalid PoW allocated state or replied", false},
	{"committed_target", "gateway", "exchange/pow.go", " || target < difficulty", "", "./exchange", "TestExchangePoW/low_target", "invalid PoW allocated state or replied", false},
	{"duplicate_nonce", "gateway", "exchange/pow.go", "if found || len(tag) != 3 {", "if len(tag) != 3 {", "./exchange", "TestExchangePoW/duplicate", "invalid PoW allocated state or replied", false},
	{"nonce_canonical", "gateway", "exchange/pow.go", " || strconv.FormatUint(nonce, 10) != tag[1]", " || (strconv.FormatUint(nonce, 10) != tag[1] && false)", "./exchange", "TestExchangePoW/bad_nonce", "invalid PoW allocated state or replied", false},
	{"token_debit", "gateway", "exchange/engine.go", "v.Tokens--", "v.Tokens -= 0", "./exchange", "TestExchangeLimitsRestart", "per-key bucket exceeded", false},
	{"idle_eviction", "gateway", "exchange/engine.go", "if e.disk.evictIdle() != nil {", "if true {", "./exchange", "TestExchangeManyKeys", "fresh honest sender starved by idle table", false},
	{"client_capacity", "gateway", "exchange/engine.go", "if len(e.disk.clients) >= e.cfg.MaxClients {", "if len(e.disk.clients) >= e.cfg.MaxClients && false {", "./exchange", "TestExchangeManyKeys", "client cap exceeded", false},
	{"rumor_replay_retention", "gateway", "exchange/engine.go", "v.Seen = retained", "v.Seen = retained[:0]", "./exchange", "TestExchangeReplayWithCapacity", "replay repeated response or debit", false},
	{"known_expiry", "gateway", "exchange/engine.go", "old == nil || old.KnownUntil <= now", "old == nil", "./exchange", "TestExchangeKnownExpiry", "expired known key bypassed work", false},
	{"ambiguous_booking", "gateway", "exchange/engine.go", "if errors.Is(err, ErrRejected) {", "if errors.Is(err, ErrRejected) || true {", "./exchange", "TestExchangeBookingRecovery/true", "uncertain booking repeated", false},
	{"issued_sender", "gateway", "exchange/engine.go", " || issued.Sender != h.Sender", "", "./exchange", "TestExchangeIssuedBinding/sender", "foreign issuance registered", false},
	{"issued_contract", "gateway", "exchange/engine.go", " || issued.ContractSHA256 != h.ContractSHA256", "", "./exchange", "TestExchangeIssuedBinding/contract", "foreign issuance registered", false},
	{"issued_window", "gateway", "exchange/engine.go", " || issued.NotAfter != h.NotAfter", "", "./exchange", "TestExchangeIssuedBinding/window", "foreign issuance registered", false},
	{"ready_time", "gateway", "exchange/engine.go", " && now >= v.Hold.NotBefore", "", "./exchange", "TestExchangeTransitions", "issued before window", false},
	{"ready_live", "gateway", "exchange/engine.go", "if err == nil && live {", "if err == nil && (live || true) {", "./exchange", "TestExchangeIssuedBinding/sender", "non-live grant ready", false},
	{"config_binding", "gateway", "exchange/store.go", " || m.Binding != d.binding", "", "./exchange", "TestExchangeStateRefusals/config", "invalid state accepted", false},
	{"outbox_recipient", "gateway", "exchange/store.go", " || v.Pending.Tags[0][1] != v.Sender", "", "./exchange", "TestExchangeOutboxIdentity", "foreign outbox recipient accepted", false},
	{"gateway_exchange_route", "gateway", "gateway/exchange.go", "res.ExchangeQueued = g.cfg.Exchange.Submit(r)", "res.ExchangeQueued = false", "./gateway", "TestExchangeQueueIsolationAndGranteeBypass", "exchange admission", false},
	{"gateway_live_bypass", "gateway", "gateway/inbound.go", "// (d1) Lazy instance start:", "if g.cfg.Exchange != nil { return g.nonGrantee(rumor, res) }\n\t// (d1) Lazy instance start:", "./gateway", "TestExchangeQueueIsolationAndGranteeBypass", "live grantee throttled by exchange", false},
	{"adapter_canonical", "binding", "bookingbind/bookingbind.go", "!bytes.Equal(bytes.TrimSuffix(buf.Bytes(), []byte{'\\n'}), raw)", "(!bytes.Equal(bytes.TrimSuffix(buf.Bytes(), []byte{'\\n'}), raw) && false)", "./bookingbind", "TestAdapterConsentRefusals/whitespace", "invalid consent not rejected", false},
	{"adapter_identity", "binding", "bookingbind/bookingbind.go", " || c.AgentPubkey != a.AgentPubkey", "", "./bookingbind", "TestAdapterContractIdentity", "wrong agent key relabelled contract", false},
	{"catalogue_hold", "booking", "catalogue.go", "if !busy {", "if !busy || true {", ".", "TestCatalogue", "held slot advertised", false},
	{"catalogue_limit", "booking", "catalogue.go", "if len(c.Slots) > limit {", "if len(c.Slots) > limit && false {", ".", "TestCatalogue", "catalogue alias or bound", false},
	{"catalogue_issued", "booking", "catalogue.go", " || b.Issuance != nil", "", ".", "TestCatalogue", "issued overlap advertised", false},
	{"core_ready_check", "gateway", "gateway/exchange.go", "return err == nil && receipt.Admits(), err", "return err == nil && (receipt.Admits() || true), err", ".", "TestExchangeCoreNonLive", "unexpected exchange text", true},
	{"core_ready_duplicate", "gateway", "gateway/gateway.go", "if g.cfg.Exchange == nil {\n\t\t_ = g.dmRenter(ctx, fresh, \"ready\")", "if true {\n\t\t_ = g.dmRenter(ctx, fresh, \"ready\")", ".", "TestExchangeCoreLifecycle", "lazy instance start duplicated exchange ready", true},
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
	out := flag.String("out", ".temp/e1-guards", "evidence directory")
	core := flag.Bool("core", false, "include pinned genuine Core controls; GW_E2E_CORE_* required")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "e1-guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"rental", "single-use", "sealwatch", "payment-chain"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"rental-gateway", "rental-booking"} {
		if e = copyModule(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	modules := map[string]string{"gateway": filepath.Join(work, "rental-gateway"), "binding": filepath.Join(work, "rental-gateway", "kernelbind"), "booking": filepath.Join(work, "rental-booking")}
	runTest := func(name, module, pkg, test string, useCore bool) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = modules[module]
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GW_E2E_REGTEST=0")
		if useCore {
			cmd.Dir = modules["binding"]
			cmd.Env = append(cmd.Env, "GW_E2E_REGTEST=1", "GW_E2E_RUN_ROOT="+filepath.Join(runDir, name+"-core"))
		}
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
	for _, b := range []struct{ module, pkg, test string }{{"gateway", "./exchange", "TestExchange.*"}, {"gateway", "./gateway", "TestExchange.*"}, {"binding", "./bookingbind", "TestAdapter.*"}, {"booking", ".", "TestCatalogue.*"}} {
		code, _, e := runTest("baseline-"+b.module+strings.ReplaceAll(b.pkg, "/", "-"), b.module, b.pkg, b.test, false)
		if e != nil || code != 0 {
			return fmt.Errorf("baseline %s/%s exit %d: %v", b.module, b.pkg, code, e)
		}
	}
	if *core {
		for _, test := range []string{"TestExchangeCoreLifecycle", "TestExchangeCoreNonLive"} {
			code, b, e := runTest("baseline-"+test, "binding", ".", test, true)
			if e != nil || code != 0 || !bytes.Contains(b, []byte("--- PASS: "+test)) {
				return fmt.Errorf("Core baseline %s exit %d: %v", test, code, e)
			}
		}
	}
	results := []result{}
	for _, p := range plants {
		if p.Core && !*core {
			continue
		}
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
		code, b, runErr := runTest(p.Name, p.Module, p.Package, p.Test, p.Core)
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
	fmt.Printf("%d/%d intended guard failures (core=%v)\n", len(results), len(results), *core)
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
