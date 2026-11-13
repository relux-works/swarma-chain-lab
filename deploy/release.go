// Package deploy prepares local, unsigned release artifacts. It never
// installs a service, signs a release, reads custody files or deploys to a host.
package deploy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
)

const GoVersion = "go1.26.8"

var (
	ErrInput     = errors.New("deploy: invalid input")
	ErrDirty     = errors.New("deploy: checkout must be clean")
	ErrSource    = errors.New("deploy: source unavailable")
	ErrToolchain = errors.New("deploy: toolchain mismatch")
	ErrBuild     = errors.New("deploy: build failed")
	ErrDifferent = errors.New("deploy: builds differ")
	ErrOutput    = errors.New("deploy: output unavailable")
	ErrManifest  = errors.New("deploy: invalid release manifest")
)

type Artifact struct {
	Service   string `json:"service"`
	Module    string `json:"module,omitempty"`
	Package   string `json:"package,omitempty"`
	Binary    string `json:"binary,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	Screening string `json:"screening,omitempty"`
}

// Tool is an operator command shipped in the release. It is not a service: it
// has no unit, no service policy and no readiness status, and nothing in the
// release activates it. Its binary is built twice and compared like a service.
type Tool struct {
	Tool    string `json:"tool"`
	Module  string `json:"module"`
	Package string `json:"package"`
	Binary  string `json:"binary"`
	SHA256  string `json:"sha256"`
}
type Manifest struct {
	Version    int        `json:"version"`
	Commit     string     `json:"commit"`
	GoVersion  string     `json:"go_version"`
	GOOS       string     `json:"goos"`
	GOARCH     string     `json:"goarch"`
	CGOEnabled string     `json:"cgo_enabled"`
	BuildFlags []string   `json:"build_flags"`
	Artifacts  []Artifact `json:"artifacts"`
	Tools      []Tool     `json:"tools"`
	Pending    []Artifact `json:"pending"`
}

// ReleaseInput accepts an exact full commit SHA, not a mutable branch/ref. Out
// must not exist and must have an existing canonical parent outside Repo.
type ReleaseInput struct{ Repo, Commit, Out string }

var releaseArtifacts = []Artifact{
	{Service: "gateway", Module: "experiments/rental-gateway", Package: "./cmd/gateway", Binary: "bin/gateway", Status: "configuration-preparation", Screening: "off", Reason: "operator-pinned payload and remote manager required; host execution is a separate gate"},
	{Service: "booking", Module: "experiments/rental-booking", Package: "./cmd/rental-booking", Binary: "bin/rental-booking", Status: "configuration-preparation"},
	{Service: "store", Module: "experiments/grant-store", Package: "./cmd/grant-store", Binary: "bin/grant-store", Status: "configuration-preparation"},
	{Service: "relay", Module: "experiments/relay", Package: "./cmd/swarma-relay", Binary: "bin/swarma-relay", Status: "configuration-preparation", Reason: "loopback behind explicit trusted reverse proxy; gift-wrap read AUTH awaits gateway client integration"},
	{Service: "issuer", Module: "experiments/signer-service", Package: "./cmd/swarma-signer", Binary: "bin/swarma-signer", Status: "configuration-preparation", Reason: "owner-provisioned custody and private intake required; no signer activation implied"},
	{Service: "model", Module: "experiments/model-proxy", Package: "./cmd/model-proxy", Binary: "bin/model-proxy", Status: "configuration-preparation", Reason: "owner-approved model prices, caps and API credential required; Linux peer-credential administration"},
	{Service: "stations", Module: "experiments/station-lifecycle", Package: "./cmd/station-manager", Binary: "bin/station-manager", Status: "configuration-preparation", Reason: "ordinary Linux transport; independently installed root helper and policy required"},
	{Service: "payload", Module: "experiments/station-payload", Package: "./cmd/station-payload", Binary: "bin/station-payload", Status: "configuration-preparation", Reason: "scripted consumer only; per-slot launch belongs to the root helper policy, no standalone unit"},
	{Service: "wallet", Module: "experiments/agent-wallet", Package: "./cmd/agent-walletd", Binary: "bin/agent-walletd", Status: "configuration-preparation", Reason: "separate service UID, per-agent socket group, receipt key and private wallet RPC configuration required; host custody smoke remains separate"},
}

// releaseTools are operator commands a host runs from the signed release
// rather than from a source checkout.
var releaseTools = []Tool{
	{Tool: "deploy-kit", Module: "deploy", Package: "./cmd/deploy-kit", Binary: "bin/deploy-kit"},
}

var (
	releasePending    = []Artifact{{Service: "a2ad", Status: "pending", Reason: "a2a daemon deployment integration not included in this kit"}}
	releaseBuildFlags = []string{"-trimpath", "-buildvcs=false", "-mod=readonly"}
)

type buildFunc func(context.Context, string, string, string, Artifact) ([]byte, error)

func exactHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonicalDir(path string) bool {
	p, e := filepath.EvalSymlinks(path)
	st, se := os.Stat(path)
	return e == nil && se == nil && st.IsDir() && filepath.IsAbs(path) && filepath.Clean(path) == path && p == path
}

// BuildRelease builds both independent source trees with separate build caches.
// Nothing is published unless every binary matches and the source is still clean.
func BuildRelease(ctx context.Context, in ReleaseInput) (Manifest, error) {
	return buildRelease(ctx, in, buildGo)
}

func command(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Env = env
	// Error strings/diagnostics may contain operator paths or environment data;
	// callers return a fixed error class instead of propagating subprocess text.
	return c.Output()
}
func git(ctx context.Context, repo string, args ...string) ([]byte, error) {
	return command(ctx, repo, os.Environ(), "git", args...)
}
func clean(ctx context.Context, repo string) error {
	b, e := git(ctx, repo, "status", "--porcelain=v1", "--untracked-files=all")
	if e != nil {
		return ErrSource
	}
	if len(b) != 0 {
		return ErrDirty
	}
	return nil
}
func goEnv(cache string) []string {
	e := append(os.Environ(), "GOENV=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOEXPERIMENT=", "GOAMD64=v1", "GOPROXY=off", "GOSUMDB=off")
	if cache != "" {
		e = append(e, "GOCACHE="+cache)
	}
	return e
}

func buildRelease(ctx context.Context, in ReleaseInput, build buildFunc) (Manifest, error) {
	var empty Manifest
	if ctx == nil || !exactHex(in.Commit, 20) || !canonicalDir(in.Repo) || !filepath.IsAbs(in.Out) || filepath.Clean(in.Out) != in.Out || !canonicalDir(filepath.Dir(in.Out)) {
		return empty, ErrInput
	}
	rel, e := filepath.Rel(in.Repo, in.Out)
	if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return empty, ErrInput
	}
	if _, e = os.Lstat(in.Out); !os.IsNotExist(e) {
		return empty, ErrOutput
	}
	top, e := git(ctx, in.Repo, "rev-parse", "--show-toplevel")
	if e != nil || strings.TrimSpace(string(top)) != in.Repo {
		return empty, ErrInput
	}
	if e = clean(ctx, in.Repo); e != nil {
		return empty, e
	}
	head, e := git(ctx, in.Repo, "rev-parse", "HEAD")
	if e != nil || strings.TrimSpace(string(head)) != in.Commit {
		return empty, ErrSource
	}
	version, e := command(ctx, in.Repo, goEnv(""), "go", "env", "GOVERSION")
	if e != nil || strings.TrimSpace(string(version)) != GoVersion {
		return empty, ErrToolchain
	}
	work, e := os.MkdirTemp(filepath.Dir(in.Out), ".swarma-release-")
	if e != nil {
		return empty, ErrOutput
	}
	defer os.RemoveAll(work)
	archive := filepath.Join(work, "source.tar")
	if _, e = git(ctx, in.Repo, "archive", "--format=tar", "--output="+archive, in.Commit); e != nil {
		return empty, ErrSource
	}
	first, second := filepath.Join(work, "first"), filepath.Join(work, "second")
	for _, root := range []string{first, second} {
		if e = extract(archive, root); e != nil {
			return empty, ErrSource
		}
	}
	m, stage, e := assemble(ctx, work, first, second, in.Commit, build)
	if e != nil {
		return empty, e
	}
	if e = clean(ctx, in.Repo); e != nil {
		return empty, e
	}
	head, e = git(ctx, in.Repo, "rev-parse", "HEAD")
	if e != nil || strings.TrimSpace(string(head)) != in.Commit {
		return empty, ErrSource
	}
	// The directory contains a complete unsigned bundle before its name appears.
	if _, e = os.Lstat(in.Out); !os.IsNotExist(e) {
		return empty, ErrOutput
	}
	if e = os.Rename(stage, in.Out); e != nil {
		return empty, ErrOutput
	}
	return m, nil
}

// assemble builds every service and tool binary as a compared pair, then writes
// the bundle, its manifest and SHA256SUMS under work. It publishes nothing.
func assemble(ctx context.Context, work, first, second, commit string, build buildFunc) (Manifest, string, error) {
	m := Manifest{Version: 1, Commit: commit, GoVersion: GoVersion, GOOS: "linux", GOARCH: "amd64", CGOEnabled: "0", BuildFlags: append([]string(nil), releaseBuildFlags...), Artifacts: append([]Artifact(nil), releaseArtifacts...), Tools: append([]Tool(nil), releaseTools...), Pending: append([]Artifact(nil), releasePending...)}
	stage := filepath.Join(work, "bundle")
	if e := os.MkdirAll(filepath.Join(stage, "bin"), 0700); e != nil {
		return Manifest{}, "", ErrOutput
	}
	stageBinary := func(a Artifact) (string, error) {
		one, e := buildPair(ctx, work, first, second, a, build)
		if e != nil {
			return "", e
		}
		if e = os.WriteFile(filepath.Join(stage, a.Binary), one, 0755); e != nil {
			return "", ErrOutput
		}
		return digest(one), nil
	}
	for i, a := range m.Artifacts {
		h, e := stageBinary(a)
		if e != nil {
			return Manifest{}, "", e
		}
		m.Artifacts[i].SHA256 = h
	}
	// A tool takes the same twice-built comparison; only its module, package
	// and binary path reach the builder.
	for i, t := range m.Tools {
		h, e := stageBinary(Artifact{Module: t.Module, Package: t.Package, Binary: t.Binary})
		if e != nil {
			return Manifest{}, "", e
		}
		m.Tools[i].SHA256 = h
	}
	// Deploy templates are exact committed public source, never an operator's
	// substituted configuration or credential files from the working checkout.
	if e := copyTemplates(filepath.Join(first, "deploy", "templates"), filepath.Join(stage, "templates")); e != nil {
		return Manifest{}, "", ErrSource
	}
	for _, name := range []string{"SMOKE.md", "SMOKE-DK2.md", "README.md", "INSTALL-CONFIG.md"} {
		b, e := os.ReadFile(filepath.Join(first, "deploy", name))
		if e != nil {
			return Manifest{}, "", ErrSource
		}
		if e = os.WriteFile(filepath.Join(stage, name), b, 0644); e != nil {
			return Manifest{}, "", ErrOutput
		}
	}
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return Manifest{}, "", ErrOutput
	}
	b = append(b, '\n')
	// The builder publishes only a manifest its own validator accepts.
	if _, e = ValidateManifest(b); e != nil {
		return Manifest{}, "", ErrManifest
	}
	if e = os.WriteFile(filepath.Join(stage, "manifest.json"), b, 0644); e != nil {
		return Manifest{}, "", ErrOutput
	}
	if e = writeSums(stage); e != nil {
		return Manifest{}, "", ErrOutput
	}
	return m, stage, nil
}

// ValidateManifest strictly decodes a public release manifest and accepts it
// only with this kit's target, flags and exact inventory: every service row,
// every tool row and the pending row, each built hash as lowercase SHA-256.
// Unknown, duplicate or missing members refuse, so a tool row cannot carry a
// service, status or unit member and cannot move into the service rows.
func ValidateManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > 1<<20 || uniqueJSON(raw) != nil || !manifestMemberNames(raw) {
		return Manifest{}, ErrManifest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return Manifest{}, ErrManifest
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Manifest{}, ErrManifest
	}
	if m.Version != 1 || !exactHex(m.Commit, 20) || m.GoVersion != GoVersion || m.GOOS != "linux" || m.GOARCH != "amd64" || m.CGOEnabled != "0" || !reflect.DeepEqual(m.BuildFlags, releaseBuildFlags) || !reflect.DeepEqual(m.Pending, releasePending) || len(m.Artifacts) != len(releaseArtifacts) || len(m.Tools) != len(releaseTools) {
		return Manifest{}, ErrManifest
	}
	for i, a := range m.Artifacts {
		want := releaseArtifacts[i]
		want.SHA256 = a.SHA256
		if a != want || !exactHex(a.SHA256, 32) {
			return Manifest{}, ErrManifest
		}
	}
	for i, t := range m.Tools {
		want := releaseTools[i]
		want.SHA256 = t.SHA256
		if t != want || !exactHex(t.SHA256, 32) {
			return Manifest{}, ErrManifest
		}
	}
	return m, nil
}

// encoding/json matches struct fields case-insensitively, even with
// DisallowUnknownFields. Check exact member names at every manifest object
// boundary first, so aliases cannot supply or overwrite canonical values.
func manifestMemberNames(raw []byte) bool {
	only := func(object map[string]json.RawMessage, names []string) bool {
		if object == nil {
			return false
		}
		for name := range object {
			if !slices.Contains(names, name) {
				return false
			}
		}
		return true
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || !only(root, []string{"version", "commit", "go_version", "goos", "goarch", "cgo_enabled", "build_flags", "artifacts", "tools", "pending"}) {
		return false
	}
	artifactNames := []string{"service", "module", "package", "binary", "sha256", "status", "reason", "screening"}
	for _, inventory := range []struct {
		name  string
		names []string
	}{
		{"artifacts", artifactNames},
		{"tools", []string{"tool", "module", "package", "binary", "sha256"}},
		{"pending", artifactNames},
	} {
		var rows []map[string]json.RawMessage
		if json.Unmarshal(root[inventory.name], &rows) != nil {
			return false
		}
		for _, row := range rows {
			if !only(row, inventory.names) {
				return false
			}
		}
	}
	return true
}

func buildPair(ctx context.Context, work, first, second string, a Artifact, build buildFunc) ([]byte, error) {
	one, e := build(ctx, first, filepath.Join(work, "cache-first"), filepath.Join(work, "binary-first"), a)
	if e != nil {
		return nil, ErrBuild
	}
	two, e := build(ctx, second, filepath.Join(work, "cache-second"), filepath.Join(work, "binary-second"), a)
	if e != nil {
		return nil, ErrBuild
	}
	if len(one) == 0 || !bytes.Equal(one, two) {
		return nil, ErrDifferent
	}
	return one, nil
}

func buildGo(ctx context.Context, root, cache, out string, a Artifact) ([]byte, error) {
	dir := filepath.Join(root, filepath.FromSlash(a.Module))
	if _, e := command(ctx, dir, goEnv(cache), "go", "mod", "verify"); e != nil {
		return nil, ErrBuild
	}
	if _, e := command(ctx, dir, goEnv(cache), "go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-o", out, a.Package); e != nil {
		return nil, ErrBuild
	}
	b, e := os.ReadFile(out)
	if e != nil {
		return nil, ErrBuild
	}
	return b, nil
}

func extract(archive, root string) error {
	if e := os.Mkdir(root, 0700); e != nil {
		return e
	}
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	r := tar.NewReader(f)
	var total int64
	for {
		h, e := r.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || !filepath.IsLocal(name) || filepath.ToSlash(filepath.Clean(name)) != name || h.Size < 0 || h.Size > 128<<20 {
			return ErrSource
		}
		total += h.Size
		if total > 1<<30 {
			return ErrSource
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeXGlobalHeader:
			continue
		case tar.TypeDir:
			if e = os.MkdirAll(path, 0700); e != nil {
				return e
			}
		case tar.TypeReg:
			if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
				return e
			}
			out, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(h.Mode)&0777)
			if e != nil {
				return e
			}
			_, e = io.CopyN(out, r, h.Size)
			ce := out.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		default:
			return ErrSource
		}
	}
}
func copyTemplates(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0755)
		}
		if !d.Type().IsRegular() {
			return ErrSource
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0644)
	})
}
func writeSums(root string) error {
	var names []string
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	if e != nil {
		return e
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		raw, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			return e
		}
		b.WriteString(digest(raw) + "  " + name + "\n")
	}
	return os.WriteFile(filepath.Join(root, "SHA256SUMS"), []byte(b.String()), 0644)
}
