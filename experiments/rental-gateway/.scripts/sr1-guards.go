// Run from rental-gateway: go run .scripts/sr1-guards.go -out .temp/sr1-guards
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
	{"early_hello", "gateway", "gateway/inbound.go", "if !slot.Started && !(slot.Starting && g.starting[slot.ID] != nil) {\n\t\treturn deny(\"session not started\")", "if !slot.Started {\n\t\treturn deny(\"session not started\")", "./gateway", "TestStartupOrdering", "early Hello refused"},
	{"orphan_hello", "gateway", "gateway/inbound.go", "if !slot.Started && !(slot.Starting && g.starting[slot.ID] != nil) {\n\t\treturn deny(\"session not started\")", "if !slot.Started && !slot.Starting {\n\t\treturn deny(\"session not started\")", "./gateway", "TestStartupRecovery", "orphan start admitted"},
	{"stale_auth", "gateway", "gateway/inbound.go", "if !slot.Started && !(slot.Starting && g.starting[slot.ID] != nil) {\n\t\treturn deny(\"authentication failed\")", "if false {\n\t\treturn deny(\"authentication failed\")", "./gateway", "TestStartupStaleChallenge", "stale challenge admitted"},
	{"application_barrier", "gateway", "gateway/inbound.go", "if done != nil {", "if done != nil && false {", "./gateway", "TestStartupOrdering", "application escaped starting barrier"},
	{"failed_channel_close", "gateway", "gateway/gateway.go", "_ = bound.conn.Close()", "_ = bound.conn.LocalAddr()", "./gateway", "TestStartupFailure/driver", "failed start channel not closed"},
	{"failed_destroy", "gateway", "gateway/gateway.go", "_, destroyErr := g.cfg.Driver.Destroy(cleanup, st)", "_ = cleanup; var destroyErr error", "./gateway", "TestStartupFailure/driver", "failed start escaped cleanup/effect boundary"},
	{"failed_live_attempt", "gateway", "gateway/gateway.go", "delete(g.starting, id)", "// omitted attempt revocation", "./gateway", "TestStartupFailure/all_writes", "failed launch readmitted"},
	{"ended_promotion", "gateway", "journal/journal.go", "if !s.Starting || s.Started || s.Ended || s.Destroyed {", "if !s.Starting || s.Started || s.Destroyed {", "./journal", "TestStartupJournalTransitions", "ended slot promoted"},
	{"starting_credential", "gateway", "journal/journal.go", " || s.ChannelSecretHex == \"\" {", " {", "./journal", "TestStartupJournalTransitions", "intent without credential accepted"},
	{"durable_intent", "gateway", "journal/journal.go", "s.Starting = true", "s.Starting = false", "./journal", "TestStartupJournalTransitions", "durable starting lost"},
	{"destroy_clears_intent", "gateway", "journal/journal.go", "s.Starting = false\n", "// omitted intent removal\n", "./journal", "TestStartupJournalTransitions", "destroyed intent retained"},
	{"serve_recovery", "gateway", "cmd/gateway/serve.go", "e = gw.RecoverStarting(recoveryCtx)", "_ = recoveryCtx; e = nil", "./cmd/gateway", "TestServeStartupRecovery/destroy", "serve skipped interrupted launch recovery"},
	{"serve_recovery_failure", "gateway", "cmd/gateway/serve.go", "if e != nil {\n\t\treturn errors.New(\"GATEWAY_START_RECOVERY\")", "if e != nil && false {\n\t\treturn errors.New(\"GATEWAY_START_RECOVERY\")", "./cmd/gateway", "TestServeStartupRecovery/cleanup_failure", "serve ignored failed start recovery"},
	{"station_name", "gateway", "gateway/inbound.go", "if frame.StationName != slot.StationName {", "if frame.StationName != slot.StationName && false {", "./gateway", "TestStartupAdmissionGuards/wrong_name", "startup admission guard"},
	{"channel_credential", "gateway", "gateway/inbound.go", "if slot.ChannelSecretHex == \"\" {", "if slot.ChannelSecretHex == \"\" && false {", "./gateway", "TestStartupAdmissionGuards/no_credential", "startup admission guard"},
	{"file_fsync", "gateway", "journal/journal.go", "sr1FileSync(tmp)", "error(nil)", "./journal", "TestStartupSyncProbe", "startup sync sequence"},
	{"directory_fsync", "gateway", "journal/journal.go", "return sr1DirectorySync(d)", "return nil", "./journal", "TestStartupSyncProbe", "startup sync sequence"},
	{"single_binding", "gateway", "gateway/inbound.go", "if _, taken := g.bound[slot.ID]; taken {", "if _, taken := g.bound[slot.ID]; taken && false {", "./gateway", "TestStartupPendingBindings", "second pending binding admitted"},
	{"hmac", "gateway", "gateway/inbound.go", "!stationlink.VerifyResponse(secret, nonceHex, pendingSlot, pendingStation, frame.Response)", "false && !stationlink.VerifyResponse(secret, nonceHex, pendingSlot, pendingStation, frame.Response)", "./gateway", "TestStartupAdmissionGuards/wrong_secret", "startup admission guard"},
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
	out := flag.String("out", ".temp/sr1-guards", "evidence directory")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "sr1-guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"rental", "single-use", "sealwatch", "payment-chain", "station-lifecycle", "model-proxy", "signer-service", "grant-store"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	// deploy's local replacements retain their repository-relative experiments layout.
	if e = os.MkdirAll(filepath.Join(work, "experiments"), 0700); e != nil {
		return e
	}
	for _, dep := range []string{"single-use", "sealwatch"} {
		if e = os.Symlink(filepath.Join(work, dep), filepath.Join(work, "experiments", dep)); e != nil {
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
	// Observe actual Sync invocations in the copied fixture, without adding
	// hooks or test switches to the product. Both wrappers call the real Sync.
	jf := filepath.Join(modules["gateway"], "journal", "journal.go")
	originalJournal, e := os.ReadFile(jf)
	if e != nil {
		return e
	}
	if strings.Count(string(originalJournal), "tmp.Sync()") != 1 || strings.Count(string(originalJournal), "d.Sync()") != 1 {
		return errors.New("sync instrumentation drift")
	}
	instrumented := strings.Replace(string(originalJournal), "tmp.Sync()", "sr1FileSync(tmp)", 1)
	instrumented = strings.Replace(instrumented, "d.Sync()", "sr1DirectorySync(d)", 1)
	if e = os.WriteFile(jf, []byte(instrumented), 0600); e != nil {
		return e
	}
	provenance, _ := json.Marshal(map[string]string{"source_sha256": hash(originalJournal), "instrumented_sha256": hash([]byte(instrumented))})
	if e = os.WriteFile(filepath.Join(runDir, "sync-instrumentation.json"), provenance, 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(modules["gateway"], "journal", "sr1_sync_probe.go"), []byte(syncProbe), 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(modules["gateway"], "journal", "sr1_sync_probe_test.go"), []byte(syncProbeTest), 0600); e != nil {
		return e
	}

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
	for _, b := range []struct{ module, pkg, test string }{{"gateway", "./gateway", "TestStartup.*"}, {"gateway", "./journal", "TestStartup.*"}, {"gateway", "./cmd/gateway", "TestServeStartupRecovery"}} {
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
const syncProbe = `package journal
import "os"
var sr1Observe func(string)
func sr1FileSync(f *os.File) error { if sr1Observe != nil { sr1Observe("file") }; return f.Sync() }
func sr1DirectorySync(f *os.File) error { if sr1Observe != nil { sr1Observe("directory") }; return f.Sync() }
`
const syncProbeTest = `package journal
import ("testing";"strings")
// Each start mark returns only after the real file and directory Sync calls.
// This observes call ordering; it is not a power-loss or storage-hardware test.
func TestStartupSyncProbe(t *testing.T) {
    s,err:=Open(t.TempDir());if err!=nil{t.Fatal(err)}
    if err=s.Put(&Slot{ID:"probe",RenterPubKey:"fixture",ChannelSecretHex:"credential"});err!=nil{t.Fatal(err)}
    for _, mark:=range []func(string)error{s.MarkStarting,s.MarkStarted} {
        var trace []string
        sr1Observe=func(kind string){trace=append(trace,kind)}
        err=mark("probe")
        sr1Observe=nil
        if err!=nil{t.Fatal(err)}
        if strings.Join(trace,",")!="file,directory" {t.Fatalf("startup sync sequence: %v",trace)}
    }
}
`
