// Run from relay. Each bounded plant edits copied source only and must fail its
// exact product assertion; compilation failures, timeouts and crashes refuse.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/deploy/workspace"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct{ Name, Module, File, Old, New, Test, Witness string }

var plants = []plant{
	{"req_read_config", "relay", "config.go", "if c.websocketReadLimit() < maxRequestBytes {", "if false && c.websocketReadLimit() < maxRequestBytes {", "TestRequestReadLimit", "short REQ read limit accepted"},
	{"req_read_wire", "relay", "relay.go", "ws.SetReadLimit(r.cfg.websocketReadLimit())", "ws.SetReadLimit(r.cfg.websocketReadLimit()-1)", "TestRequestReadLimit", "maximal REQ not served"},
	{"event_bytes", "relay", "store.go", "len(raw) > c.MaxEventBytes", "false && len(raw) > c.MaxEventBytes", "TestWireRefusals", "invalid ACK"},
	{"optional_auth_order", "relay", "relay.go", "challenged := r.cfg.RequireWriteAuth || r.cfg.RequireReadAuth || r.cfg.RestrictGiftWrapReads || r.cfg.UnknownPowBits > 0", "challenged := true", "TestBookingPublisher", "booking first ACK"},
	{"signature", "relay", "store.go", "nostr.VerifySignature(e) != nil", "(false && nostr.VerifySignature(e) != nil)", "TestStoreRefusals", "bad signature"},
	{"kinds", "relay", "store.go", "e.Kind != 1059 && e.Kind != 8181 && e.Kind != 8182", "false && e.Kind != 1059 && e.Kind != 8181 && e.Kind != 8182", "TestStoreRefusals", "forbidden event"},
	{"time", "relay", "store.go", "return e.CreatedAt >= now-c.RetentionSeconds && e.CreatedAt <= now+c.FutureSeconds", "return true", "TestStoreRefusals", "time boundary"},
	{"capacity", "relay", "store.go", "len(next) >= s.cfg.MaxEvents", "false && len(next) >= s.cfg.MaxEvents", "TestStoreDurability", "capacity evicted live event"},
	{"bytes", "relay", "store.go", "len(raw) > s.cfg.MaxStoreBytes", "false && len(raw) > s.cfg.MaxStoreBytes", "TestRetentionAndBytes", "store byte cap"},
	{"poison", "relay", "store.go", "if s.poisoned {\n\t\treturn false, fail(\"STORE_UNAVAILABLE\")", "if false && s.poisoned {\n\t\treturn false, fail(\"STORE_UNAVAILABLE\")", "TestStoreFailure", "uncertain store resumed"},
	{"persistence", "relay", "store.go", "if s.save(raw) != nil {\n\t\ts.poisoned = true\n\t\treturn false, fail(\"STORE_WRITE\")\n\t}", "_ = raw // planted: skip persistence", "TestStoreDurability", "restart lost event"},
	{"empty_filter", "relay", "filter.go", "f.IDs != nil && !contains(f.IDs, e.ID)", "len(f.IDs) > 0 && !contains(f.IDs, e.ID)", "TestFilters", "match=false"},
	{"duplicate_keys", "relay", "config.go", "e != nil || !ok || seen[s]", "e != nil || !ok", "TestFilterRefusals", "invalid filter accepted"},
	{"auth_signature", "relay", "relay.go", "nostr.VerifySignature(e) != nil", "(false && nostr.VerifySignature(e) != nil)", "TestAuthentication", "ACK want false/restricted:"},
	{"auth_challenge", "relay", "relay.go", "tags[\"challenge\"] != p.challenge", "(false && tags[\"challenge\"] != p.challenge)", "TestAuthentication", "ACK want false/restricted:"},
	{"auth_url", "relay", "relay.go", "tags[\"relay\"] != r.cfg.PublicURL", "(false && tags[\"relay\"] != r.cfg.PublicURL)", "TestAuthentication", "ACK want false/restricted:"},
	{"auth_time", "relay", "relay.go", "e.CreatedAt < r.now().Unix()-600", "(false && e.CreatedAt < r.now().Unix()-600)", "TestAuthentication", "ACK want false/restricted:"},
	{"write_auth", "relay", "relay.go", "r.cfg.RequireWriteAuth && len(p.auth) == 0", "false && r.cfg.RequireWriteAuth && len(p.auth) == 0", "TestAuthentication", "ACK want false/auth-required:"},
	{"read_auth", "relay", "relay.go", "r.cfg.RequireReadAuth || r.cfg.RestrictGiftWrapReads && gift", "false && (r.cfg.RequireReadAuth || r.cfg.RestrictGiftWrapReads && gift)", "TestReadAuthAndSubscriptionCap", "read auth bypass"},
	{"recipient", "relay", "relay.go", "return p.auth[recipient]", "return p.auth[recipient] || true", "TestAuthentication", "foreign recipient leaked"},
	{"work", "relay", "relay.go", "r.cfg.UnknownPowBits > 0 && !known", "false && r.cfg.UnknownPowBits > 0 && !known", "TestOuterWork", "ACK want false/pow:"},
	{"ip_connection", "relay", "relay.go", "b.connections >= r.cfg.MaxConnectionsPerIP", "false && b.connections >= r.cfg.MaxConnectionsPerIP", "TestPeerLimits", "connection IP bypass"},
	{"frame_quota", "relay", "relay.go", "p.quota.used >= r.cfg.FramesPerMinute || b.used >= r.cfg.FramesPerIPMinute", "false && (p.quota.used >= r.cfg.FramesPerMinute || b.used >= r.cfg.FramesPerIPMinute)", "TestQuotaBoundaries", "frame quota isolation"},
	{"proxy", "relay", "relay.go", "r.cfg.TrustedProxyIP != \"\" && ip.String() == r.cfg.TrustedProxyIP", "true", "TestPeerLimits", "connection IP bypass"},
	{"subscription_cap", "relay", "relay.go", "len(p.subs) >= r.cfg.Subscriptions", "false && len(p.subs) >= r.cfg.Subscriptions", "TestReadAuthAndSubscriptionCap", "subscription cap"},
	{"fake_build", "station-lifecycle", "slotd/fake_darwin.go", "//go:build darwin && slotdfake", "//go:build darwin", "TestFakeBuildBoundary", "fake build boundary"},
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/guards", "public evidence")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	mod, e := os.ReadFile("go.mod")
	if e != nil || !bytes.HasPrefix(mod, []byte("module github.com/relux-works/swarma-chain-lab/experiments/relay\n")) {
		return errors.New("run from relay")
	}
	evidence, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(evidence, 0700); e != nil {
		return e
	}
	logs, e := os.MkdirTemp(evidence, "run-")
	if e != nil {
		return e
	}
	fmt.Println("evidence:", logs)
	if e = os.MkdirAll(filepath.Join(root, ".temp"), 0700); e != nil {
		return e
	}
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "guards-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"relay", "station-lifecycle"} {
		if e = copyTree(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"rental-gateway", "rental", "rental-booking", "single-use", "sealwatch", "payment-chain", "model-proxy"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	fixtureWork, e := workspace.Isolate(root, work)
	if e != nil {
		return e
	}
	runTest := func(p plant, label string) ([]byte, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		pkg := "."
		if p.Module == "station-lifecycle" {
			pkg = "./slotd"
		}
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+p.Test+"$", pkg)
		cmd.Dir = filepath.Join(work, p.Module)
		cmd.Env = append(os.Environ(), "GOWORK="+fixtureWork, "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
		var b bytes.Buffer
		cmd.Stdout = &b
		cmd.Stderr = &b
		if e := cmd.Start(); e != nil {
			return nil, -1, e
		}
		pid := cmd.Process.Pid
		err := cmd.Wait()
		code := 0
		if err != nil {
			var x *exec.ExitError
			if !errors.As(err, &x) {
				return nil, -1, err
			}
			code = x.ExitCode()
		}
		raw := append([]byte(fmt.Sprintf("owned test-command PID %d\n", pid)), b.Bytes()...)
		if e := os.WriteFile(filepath.Join(logs, label+".log"), raw, 0600); e != nil {
			return nil, code, e
		}
		return raw, code, ctx.Err()
	}
	type result struct {
		Name          string
		Exit          int
		Detected      bool
		Before, After string
	}
	results := []result{}
	for _, p := range plants {
		raw, code, e := runTest(p, "baseline-"+p.Name)
		if e != nil || code != 0 || !bytes.Contains(raw, []byte("--- PASS: "+p.Test)) {
			return fmt.Errorf("baseline %s failed exit=%d", p.Name, code)
		}
		path := filepath.Join(work, p.Module, p.File)
		before, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if n := strings.Count(string(before), p.Old); n != 1 {
			return fmt.Errorf("plant %s matched %d", p.Name, n)
		}
		after := []byte(strings.Replace(string(before), p.Old, p.New, 1))
		if e = os.WriteFile(path, after, 0600); e != nil {
			return e
		}
		raw, code, e = runTest(p, p.Name)
		restore := os.WriteFile(path, before, 0600)
		if e != nil {
			return e
		}
		if restore != nil {
			return restore
		}
		detected := code == 1 && bytes.Contains(raw, []byte("--- FAIL: "+p.Test)) && bytes.Contains(raw, []byte(p.Witness)) && !bytes.Contains(raw, []byte("[build failed]")) && !bytes.Contains(raw, []byte("panic:"))
		results = append(results, result{p.Name, code, detected, fmt.Sprintf("%x", sha256.Sum256(before)), fmt.Sprintf("%x", sha256.Sum256(after))})
		data, _ := json.MarshalIndent(results, "", "  ")
		if e = os.WriteFile(filepath.Join(logs, "results.json"), data, 0600); e != nil {
			return e
		}
		fmt.Printf("%s detected=%v\n", p.Name, detected)
		if !detected {
			return fmt.Errorf("plant %s missed intended assertion", p.Name)
		}
	}
	fmt.Printf("%d intended failures\n", len(results))
	return nil
}
func copyTree(src, dst string) error {
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
		if !d.Type().IsRegular() {
			return errors.New("unexpected source type")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0600)
	})
}
