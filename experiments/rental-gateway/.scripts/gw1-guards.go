// Run from rental-gateway: go run .scripts/gw1-guards.go -out .temp/gw1-guards [-core]
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
	{"placeholder_pin", "gateway", "cmd/gateway/config.go", "return false // repeated-byte pin", "return true // repeated-byte pin", "./cmd/gateway", "TestConfigPlaceholderPins", "placeholder pin accepted", false},
	{"inbound_drop_counter", "gateway", "cmd/gateway/inbound.go", "q.droppedFull.Add(1)", "q.droppedFull.Add(0)", "./cmd/gateway", "TestInboundStatusBounds", "saturation accounting", false},
	{"remote_local_root", "gateway", "cmd/gateway/config.go", " || c.Station.Root != \"\"", "", "./cmd/gateway", "TestConfigRemote/local-root", "remote config guard missing", false},
	{"remote_connection_bound", "gateway", "cmd/gateway/serve.go", "if l.limit > 0 && len(l.conns) >= l.limit {", "if l.limit > 0 && len(l.conns) >= l.limit && false {", "./cmd/gateway", "TestRemoteConnectionBounds", "excess connection not refused", false},
	{"remote_idle_deadline", "gateway", "cmd/gateway/serve.go", "if c.owner.timeout > 0 {\n\t\t_ = c.Conn.SetReadDeadline", "if c.owner.timeout > 0 && false {\n\t\t_ = c.Conn.SetReadDeadline", "./cmd/gateway", "TestRemoteConnectionBounds", "idle deadline not enforced", false},
	{"remote_startup_cleanup", "gateway", "cmd/gateway/station_runtime.go", "if err != nil {\n\t\t\tr.close()", "if err != nil && false {\n\t\t\tr.close()", "./cmd/gateway", "TestRemoteStartupRollback", "partial payload listener leaked", false},
	{"booking_deadline", "gateway", "cmd/gateway/booking.go", "Timeout:       timeout,", "Timeout:       max(timeout, time.Second),", "./cmd/gateway", "TestBookingClientDeadline", "booking call budget ignored", false},
	{"mainnet", "gateway", "cmd/gateway/config.go", " || c.Kernel.Network != \"regtest\"", "", "./cmd/gateway", "TestConfigBoundary/mainnet", "config guard missing", false},
	{"genesis", "gateway", "cmd/gateway/config.go", " || c.Kernel.Genesis != su.RegtestGenesis", " || (c.Kernel.Genesis != su.RegtestGenesis && false)", "./cmd/gateway", "TestConfigBoundary/genesis", "config guard missing", false},
	{"privacy_pin", "gateway", "cmd/gateway/config.go", "c.Exchange.PrivacySHA256 != booking.Hash([]byte(booking.PrivacyNotice)) || ", "(c.Exchange.PrivacySHA256 != booking.Hash([]byte(booking.PrivacyNotice)) && false) || ", "./cmd/gateway", "TestConfigBoundary/privacy", "config guard missing", false},
	{"test_mode_validator", "gateway", "cmd/gateway/config.go", "if c.Mode == \"test\" && !allowTest {", "if c.Mode == \"test\" && !allowTest && false {", "./cmd/gateway", "TestConfigBoundary", "deployment validator accepted test mode", false},
	{"production_stubs", "gateway", "cmd/gateway/config.go", "if c.Mode != \"test\" && (", "if false && (", "./cmd/gateway", "TestConfigRemote/stub-screen", "remote config guard missing", false},
	{"implicit_stub", "gateway", "cmd/gateway/config.go", "(c.Kernel.Kind == \"real\" && c.Kernel.StubVerdict != \"\")", "(c.Kernel.Kind == \"real\" && c.Kernel.StubVerdict != \"\" && false)", "./cmd/gateway", "TestConfigBoundary/implicit-stub", "config guard missing", false},
	{"secret_permissions", "gateway", "cmd/gateway/config.go", "(perm != 0 && st.Mode().Perm() != perm)", "(perm != 0 && st.Mode().Perm() != perm && false)", "./cmd/gateway", "TestConfigFiles", "wrong secret mode accepted", false},
	{"config_symlink", "gateway", "cmd/gateway/config.go", "os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK", "os.O_RDONLY|syscall.O_NONBLOCK", "./cmd/gateway", "TestConfigFiles", "symlink config accepted", false},
	{"directory_ancestry", "gateway", "cmd/gateway/serve.go", "e != nil || resolved != ancestor", "e != nil || (resolved != ancestor && false)", "./cmd/gateway", "TestPrivateDirNoRedirectedEffects", "symlink accepted", false},
	{"booking_privacy", "gateway", "cmd/gateway/booking.go", "out.PrivacyNotice != booking.PrivacyNotice || ", "", "./cmd/gateway", "TestBookingClientRefusals/privacy", "bad catalogue accepted", false},
	{"booking_strict", "gateway", "cmd/gateway/booking.go", "if booking.Strict(b, out) != nil {", "if json.Unmarshal(b, out) != nil {", "./cmd/gateway", "TestBookingClientRefusals/unknown", "bad catalogue accepted", false},
	{"booking_redirect", "gateway", "cmd/gateway/booking.go", "CheckRedirect: func(*http.Request, []*http.Request) error { return errBooking }", "CheckRedirect: func(*http.Request, []*http.Request) error { return nil }", "./cmd/gateway", "TestBookingClientRefusals", "redirect followed", false},
	{"presentation_symlink", "gateway", "presentationdir/directory.go", "unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK", "unix.O_RDONLY|unix.O_NONBLOCK", "./cmd/gateway", "TestPresentationDirectory", "symlink accepted", false},
	{"presentation_writable", "gateway", "presentationdir/directory.go", " || st.Mode().Perm()&0022 != 0 || st.Size()", " || st.Size()", "./cmd/gateway", "TestPresentationDirectory", "writable proof accepted", false},
	{"manager_pin", "gateway", "cmd/gateway/tls.go", "if hex.EncodeToString(pin[:]) != c.ManagerCertSHA256 {", "if hex.EncodeToString(pin[:]) != c.ManagerCertSHA256 && false {", "./cmd/gateway", "TestGatewayTLSAuthority", "manager authority bypass", false},
	{"server_pin", "gateway", "cmd/gateway/tls.go", "hex.EncodeToString(hash[:]) != c.CertSHA256 || ", "(hex.EncodeToString(hash[:]) != c.CertSHA256 && false) || ", "./cmd/gateway", "TestGatewayTLSAuthority", "server pin accepted", false},
	{"off_cancel", "gateway", "screen/off.go", "if e := ctx.Err(); e != nil {", "if e := ctx.Err(); e != nil && false {", "./screen", "TestOff", "cancel allowed", false},
	{"queue_bound", "gateway", "cmd/gateway/inbound.go", "make(chan *nostr.Event, capacity)", "make(chan *nostr.Event, capacity+1)", "./cmd/gateway", "TestInboundDoesNotBlockRelayACK", "queue bound", false},
	{"catalogue_duplicate", "booking", "http.go", "len(q[\"limit\"]) != 1", "len(q[\"limit\"]) < 1", ".", "TestHTTPCatalogue", "catalogue invalid query admitted or mutated", false},
	{"core_real_checker", "gateway", "cmd/gateway/serve.go", "var checker kernel.Checker = adapter", "var checker kernel.Checker = &kernel.Stub{Verdict: \"live\"}", "./cmd/gateway", "TestCoreServe", "spent seal did not close slot", true},
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
	out := flag.String("out", ".temp/gw1-guards", "evidence directory")
	core := flag.Bool("core", false, "include pinned genuine Core controls; GW1_CORE_* required")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "gw1-guard-work-")
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
	modules := map[string]string{"gateway": filepath.Join(work, "rental-gateway"), "binding": filepath.Join(work, "rental-gateway", "kernelbind"), "booking": filepath.Join(work, "rental-booking")}
	runTest := func(name, module, pkg, test string, useCore bool) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = modules[module]
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GW1_REGTEST=0")
		if useCore {
			cmd.Dir = modules["gateway"]
			cmd.Env = append(cmd.Env, "GW1_REGTEST=1", "GW1_RUN_ROOT="+filepath.Join(runDir, name+"-core"))
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
	for _, b := range []struct{ module, pkg, test string }{{"gateway", "./cmd/gateway", "Test(Config.*|Remote.*|BookingClient.*|PresentationDirectory|Inbound.*|PrivateDirNoRedirectedEffects|GatewayTLSAuthority)"}, {"gateway", "./screen", "TestOff"}, {"booking", ".", "TestHTTPCatalogue"}} {
		code, _, e := runTest("baseline-"+b.module+strings.ReplaceAll(b.pkg, "/", "-"), b.module, b.pkg, b.test, false)
		if e != nil || code != 0 {
			return fmt.Errorf("baseline %s/%s exit %d: %v", b.module, b.pkg, code, e)
		}
	}
	if *core {
		for _, test := range []string{"TestCoreServe"} {
			code, b, e := runTest("baseline-"+test, "gateway", "./cmd/gateway", test, true)
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
