// Run from station-lifecycle: go run .scripts/guards.go -out .temp/guards.
// Mutations touch only copied modules; each must reach its named assertion.
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

type plant struct{ Name, Module, File, Old, New, Package, Test, Witness string }

var plants = []plant{
	{"r4_six_seconds", "core", "fence.go", "current-issued >= 6_000_000_000", "current-issued >= 5_000_000_000", ".", "TestCreateFence", "early or regressed clock proved absence"},
	{"r4_persist_before_send", "core", "manager.go", "r.CreateFence = &f\n\t\tm.state.Records[s.ID] = r\n\t\treturn m.save()", "r.CreateFence = &f\n\t\tm.state.Records[s.ID] = r\n\t\treturn nil", "./slotd", "TestR4UncertainRecovery/absent", "create sent before durable fence"},
	{"r4_clock_proof", "core", "slotd/host.go", "if e == nil && fence.Elapsed(now) {", "if e == nil && (fence.Elapsed(now) || true) {", "./slotd", "TestR4StatusProbeOrdering", "pre-fence absence retroactively accepted"},
	{"r4_boot_identity", "core", "fence.go", "if f.BootID != now.BootID {", "if f.BootID != now.BootID && false {", ".", "TestCreateFence", "reboot did not invalidate old request"},

	{"uncertain_absence", "core", "slotd/host.go", "if !allowAbsent {", "if !allowAbsent && false {", "./slotd", "TestUncertainCreateAbsence", "uncertain absence claimed clean"},

	{"durable_intent", "core", "manager.go", "if e := m.save(); e != nil {\n\t\treturn recordStatus(r), e\n\t}\n\tbudget :=", "budget :=", ".", "TestManagerLifecycle", "host effect before durable intent"},
	{"stop_dominates", "core", "broker.go", "b.fresh[key] = s.Phase == \"running\"", "b.fresh[key] = s.Phase == \"running\"; if s.Phase == \"running\" { r.Desired = \"start\" }", ".", "TestBrokerLifecycle", "late running ACK erased stop"},
	{"bootstrap_version", "binding", "bootstrap.go", "(b.V != 1 && b.V != 2) || ", "", ".", "TestBootstrapV2Schema", "invalid bootstrap accepted"},

	{"slot_policy", "core", "manager.go", "if e := m.cfg.Range.validateSlot(s); e != nil {", "if e := m.cfg.Range.validateSlot(s); e != nil && false {", ".", "TestManagerRefusals/grant", "invalid slot allocated authority"},
	{"payload_pin", "core", "manager.go", "if s.PayloadID != m.cfg.Payload.ID || s.PayloadSHA256 != m.cfg.Payload.SHA256 {", "if (s.PayloadID != m.cfg.Payload.ID || s.PayloadSHA256 != m.cfg.Payload.SHA256) && false {", ".", "TestManagerRefusals/payload", "invalid slot allocated authority"},
	{"own_clock_expiry", "core", "manager.go", "} else if now >= r.Slot.NotAfter {", "} else if now >= r.Slot.NotAfter && false {", ".", "TestManagerExpiryRecovery/expiry", "expiry/recovery did not clean without restart"},
	{"fresh_readiness", "core", "broker.go", "fresh := b.fresh[key]", "fresh := true", ".", "TestBrokerFreshReadiness", "restart reused old running ACK"},
	{"manager_leaf_pin", "core", "transport.go", " || hash(r.TLS.PeerCertificates[0].Raw) != peerSHA256", "", ".", "TestPollAuthentication/wrong-client", "unauthenticated poll accepted"},
	{"gateway_leaf_pin", "core", "transport.go", " || hash(s.PeerCertificates[0].Raw) != pin", "", ".", "TestPollAuthentication/wrong-server", "unauthenticated poll accepted"},
	{"helper_payload", "core", "slotd/host.go", "(!checkPayload || r.PayloadSHA256 == s.PayloadSHA256)", "(!checkPayload || r.PayloadSHA256 == s.PayloadSHA256 || true)", "./slotd", "TestHostBindings/payload", "wrong payload started"},
	{"helper_bootstrap", "core", "slotd/host.go", " && r.BootstrapSHA256 == sum(s.Bootstrap)", "", "./slotd", "TestHostBindings/bootstrap", "foreign/failed slot automatically destroyed"},
	{"helper_deadline", "core", "slotd/host.go", " && r.NotAfter == time.Unix(s.NotAfter, 0).UTC().Format(time.RFC3339)", "", "./slotd", "TestHostBindings/deadline", "foreign/failed slot automatically destroyed"},
	{"helper_allowlist", "core", "slotd/wire.go", "if !ValidRequest(r) {", "if !ValidRequest(r) && false {", "./slotd", "TestRequestRefusals", "unknown helper authority sent"},
	{"helper_canonical", "core", "slotd/wire.go", " || !bytes.Equal(raw, canonical(r))", " || (!bytes.Equal(raw, canonical(r)) && false)", "./slotd", "TestResponseRefusals", "unverifiable response accepted"},
	{"remote_recovery", "gateway", "gateway/ops.go", "if remote, ok := g.cfg.Driver.(station.Recoverer); ok {", "if remote, ok := g.cfg.Driver.(station.Recoverer); ok && false {", "./gateway", "TestRemoteRecoveryEndDestroy/destroy/none", "remote recovery not completed"},
	{"pending_cleanup", "gateway", "gateway/ops.go", "if errors.Is(effErr, station.ErrCleanupPending) {", "if errors.Is(effErr, station.ErrCleanupPending) && false {", "./gateway", "TestRemoteRecoveryEndDestroy/destroy/pending", "uncertain cleanup must remain started"},
	{"booking_binding", "binding", "driver.go", " || s.ID != spec.BookingID || s.BookingID != spec.BookingID", "", ".", "TestGatewayBindingRefusals", "foreign booking accepted"},
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
	out := flag.String("out", ".temp/guards", "evidence directory")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile("go.mod"); e != nil || !bytes.HasPrefix(b, []byte("module github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle\n")) {
		return errors.New("run from station-lifecycle")
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
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"single-use", "sealwatch", "rental", "rental-booking", "payment-chain", "model-proxy"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"station-lifecycle", "rental-gateway"} {
		if e = copyModule(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	modules := map[string]string{"core": filepath.Join(work, "station-lifecycle"), "binding": filepath.Join(work, "station-lifecycle", "gatewaybind"), "gateway": filepath.Join(work, "rental-gateway")}
	runTest := func(name, module, pkg, test string) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", pkg)
		cmd.Dir = modules[module]
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
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
	// Every named negative control must first pass unmodified, not merely compile.
	for _, p := range plants {
		code, b, e := runTest("baseline-"+p.Name, p.Module, p.Package, p.Test)
		if e != nil || code != 0 || !bytes.Contains(b, []byte("--- PASS: "+p.Test)) {
			return fmt.Errorf("baseline %s missing/pass failure: exit=%d error=%v", p.Name, code, e)
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
	fmt.Printf("%d/%d intended guard failures\n", len(results), len(plants))
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
