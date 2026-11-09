package rehearsal

import (
	"encoding/json"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The release manifest must describe the same product source and normal Linux
// build. A Linux overlay build under identical flags must have a different hash;
// comparing a Darwin overlay against a Linux release would prove nothing.
func (l *lab) releaseIsolation(overlay string) {
	t := l.t
	t.Helper()
	dir := os.Getenv("IT2_RELEASE_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("IT2_RELEASE_DIR must name the exact product release")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	checked(t, e, "release manifest")
	var m struct {
		Commit    string `json:"commit"`
		GoVersion string `json:"go_version"`
		GOOS      string `json:"goos"`
		GOARCH    string `json:"goarch"`
		CGO       string `json:"cgo_enabled"`
		Artifacts []struct {
			Service string `json:"service"`
			Binary  string `json:"binary"`
			Hash    string `json:"sha256"`
		} `json:"artifacts"`
	}
	checked(t, json.Unmarshal(raw, &m), "release manifest shape")
	if m.GOOS != "linux" || m.GOARCH != "amd64" || m.CGO != "0" || m.GoVersion != "go1.26.8" || len(m.Commit) != 40 {
		t.Fatal("release target mismatch")
	}
	_, code := l.command("release product source equality", "git", "-C", l.repo, "diff", "--exit-code", m.Commit, "HEAD", "--", "go.work", "go.work.sum", "deploy", "experiments/rental-gateway", "experiments/rental", "experiments/rental-booking", "experiments/station-lifecycle", "experiments/model-proxy", "experiments/single-use", "experiments/sealwatch", "experiments/payment-chain")
	if code != 0 {
		t.Fatal("release and rehearsal product source differ")
	}
	releaseHash := ""
	for _, a := range m.Artifacts {
		if a.Service == "gateway" {
			if a.Binary != "bin/gateway" {
				t.Fatal("release gateway path")
			}
			releaseHash = a.Hash
		}
	}
	bin, e := os.ReadFile(filepath.Join(dir, "bin/gateway"))
	checked(t, e, "release gateway binary")
	if releaseHash == "" || rental.Hash(bin) != releaseHash {
		t.Fatal("release gateway hash mismatch")
	}
	build := func(name string, useOverlay bool) string {
		target := filepath.Join(l.private, name)
		args := []string{"GOENV=off", "GOTOOLCHAIN=local", "GOWORK=" + filepath.Join(l.repo, "go.work"), "GOFLAGS=", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOEXPERIMENT=", "GOAMD64=v1", "GOPROXY=off", "GOSUMDB=off", "go", "-C", filepath.Join(l.repo, "experiments/rental-gateway"), "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-o", target}
		if useOverlay {
			args = append(args, "-overlay", overlay)
		}
		args = append(args, "./cmd/gateway")
		_, code := l.command(name, "env", args...)
		if code != 0 {
			t.Fatal("release comparison build failed: " + name)
		}
		b, e := os.ReadFile(target)
		checked(t, e, "release comparison artifact")
		return rental.Hash(b)
	}
	normal, changed := build("normal-linux-gateway", false), build("overlay-linux-gateway", true)
	if normal != releaseHash || normal == changed {
		t.Fatal("release builder overlay isolation failed")
	}
	l.evidence["release_overlay_isolation"] = map[string]string{"release_commit": m.Commit, "release_manifest_sha256": rental.Hash(raw), "release_gateway_sha256": releaseHash, "normal_linux_gateway_sha256": normal, "overlay_linux_gateway_sha256": changed}
}

// Preparation-only build proof: no Core, wallet, service or signing key is used.
// It establishes build isolation, not a working rental or model request.
func TestOverlayReleaseIsolation(t *testing.T) {
	root := os.Getenv("IT2_BUILD_ONLY_ROOT")
	if root == "" {
		t.Skip("requires fresh IT2_BUILD_ONLY_ROOT and IT2_RELEASE_DIR")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute build root")
	}
	checked(t, os.Mkdir(root, 0700), "fresh build root")
	repo, e := filepath.Abs("../..")
	checked(t, e, "build repo")
	l := &lab{t: t, root: root, private: filepath.Join(root, "private"), public: filepath.Join(root, "public"), repo: repo, evidence: map[string]any{}}
	checked(t, os.Mkdir(l.private, 0700), "build private root")
	checked(t, os.Mkdir(l.public, 0700), "build public root")
	defer func() {
		var pids []map[string]any
		for _, pid := range l.pids {
			absent := syscall.Kill(pid, 0) == syscall.ESRCH
			pids = append(pids, map[string]any{"pid": pid, "absent": absent})
			if !absent {
				t.Error("build process still present")
			}
		}
		l.evidence["core_run"] = false
		l.evidence["direct_processes"] = pids
		l.evidence["passed"] = !t.Failed()
		l.write(filepath.Join(l.public, "result.json"), encoded(l.evidence), 0600)
	}()
	overlay := l.registrarOverlay()
	l.releaseIsolation(overlay)
	_, code := l.command("Darwin overlay build", "go", "-C", filepath.Join(repo, "experiments/rental-gateway"), "build", "-overlay", overlay, "-race", "-trimpath", "-buildvcs=false", "-o", filepath.Join(l.private, "gateway-overlay"), "./cmd/gateway")
	if code != 0 {
		t.Fatal("Darwin overlay build failed")
	}
}
