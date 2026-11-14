package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// walletToolNames is an independent acceptance inventory, not derived from releaseTools.
var walletToolNames = []string{"agent-wallet-reconcile", "agent-wallet", "agent-wallet-alert-forwarder"}

func assertReleasedWalletTool(t *testing.T, m Manifest, stage, name string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var published Manifest
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateManifest(raw); err != nil {
		t.Fatal("published manifest rejected", err)
	}
	binary, err := os.ReadFile(filepath.Join(stage, "bin", name))
	if err != nil {
		t.Fatal("wallet tool missing", err)
	}
	want := Tool{Tool: name, Module: "experiments/agent-wallet", Package: "./cmd/" + name, Binary: "bin/" + name, SHA256: digest(binary)}
	for _, inventory := range [][]Tool{m.Tools, published.Tools} {
		count := 0
		for _, row := range inventory {
			if row.Tool == name {
				count++
				if row != want {
					t.Fatalf("wrong %s row: %+v", name, row)
				}
			}
		}
		if count != 1 {
			t.Fatalf("manifest must list %s exactly once, got %d", name, count)
		}
	}
	sums, err := os.ReadFile(filepath.Join(stage, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Split(string(sums), "\n") {
		if line == want.SHA256+"  "+want.Binary {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("SHA256SUMS must list %s exactly once, got %d", name, count)
	}
}

func assertReleasedWalletTools(t *testing.T, m Manifest, stage string) {
	t.Helper()
	for _, name := range walletToolNames {
		t.Run(name+"-inventory", func(t *testing.T) { assertReleasedWalletTool(t, m, stage, name) })
	}
}

// Claim: each wallet tool is built once per source tree and appears with its actual hash in both manifests and SHA256SUMS; fixture bytes stand in for compilation.
func TestReleaseWalletToolsInventory(t *testing.T) {
	for _, name := range walletToolNames {
		t.Run(name, func(t *testing.T) {
			work, first, second := assembleFixture(t)
			var roots []string
			build := func(_ context.Context, root, _, _ string, a Artifact) ([]byte, error) {
				if a.Package == "./cmd/"+name {
					roots = append(roots, root)
				}
				return fixtureBinary(a.Package), nil
			}
			m, stage, err := assemble(context.Background(), work, first, second, fixtureCommit, build)
			if err != nil {
				t.Fatal(err)
			}
			assertReleasedWalletTool(t, m, stage, name)
			if !reflect.DeepEqual(roots, []string{first, second}) {
				t.Fatalf("%s lacks independent build pair: %v", name, roots)
			}
		})
	}
}

// Claim: a differing second build of each wallet tool refuses manifest/checksum staging; the identical pair is accepted.
func TestReleaseWalletToolsMismatch(t *testing.T) {
	for _, name := range walletToolNames {
		t.Run(name, func(t *testing.T) {
			for _, mismatch := range []bool{false, true} {
				t.Run(map[bool]string{false: "equal", true: "different"}[mismatch], func(t *testing.T) {
					work, first, second := assembleFixture(t)
					build := func(_ context.Context, root, _, _ string, a Artifact) ([]byte, error) {
						if mismatch && root == second && a.Package == "./cmd/"+name {
							return []byte("wallet tool mismatch"), nil
						}
						return fixtureBinary(a.Package), nil
					}
					_, stage, err := assemble(context.Background(), work, first, second, fixtureCommit, build)
					if mismatch {
						if err != ErrDifferent || stage != "" {
							t.Fatalf("mismatch not refused: stage=%q error=%v", stage, err)
						}
					} else if err != nil {
						t.Fatal("matching neighbour refused", err)
					}
					for _, file := range []string{"manifest.json", "SHA256SUMS"} {
						_, err := os.Stat(filepath.Join(work, "bundle", file))
						if mismatch && !os.IsNotExist(err) || !mismatch && err != nil {
							t.Fatalf("wrong staged state for %s: %v", file, err)
						}
					}
				})
			}
		})
	}
}

// Claim: version-1 manifests accept all three new tool rows and refuse each dropped, repointed, malformed or case-aliased row with ErrManifest.
func TestValidateManifestWalletTools(t *testing.T) {
	work, first, second := assembleFixture(t)
	m, _, err := assemble(context.Background(), work, first, second, fixtureCommit, func(_ context.Context, _, _, _ string, a Artifact) ([]byte, error) {
		return fixtureBinary(a.Package), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range walletToolNames {
		t.Run(name, func(t *testing.T) {
			index := -1
			for i, row := range m.Tools {
				if row.Tool == name {
					index = i
				}
			}
			if index < 0 {
				t.Fatal("wallet tool inventory missing")
			}
			for _, mode := range []string{"valid", "dropped", "name", "module", "package", "binary", "hash", "case-alias"} {
				t.Run(mode, func(t *testing.T) {
					candidate := m
					candidate.Tools = append([]Tool(nil), m.Tools...)
					row := &candidate.Tools[index]
					switch mode {
					case "dropped":
						candidate.Tools = append(candidate.Tools[:index], candidate.Tools[index+1:]...)
					case "name":
						row.Tool = "other"
					case "module":
						row.Module = "deploy"
					case "package":
						row.Package = "./cmd/agent-walletd"
					case "binary":
						row.Binary = "bin/agent-walletd"
					case "hash":
						row.SHA256 = "bad"
					}
					raw, err := json.Marshal(candidate)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "case-alias" {
						raw = bytes.Replace(raw, []byte(`"tool":"`+name+`"`), []byte(`"tool":"`+name+`","TOOL":"`+name+`"`), 1)
					}
					got, err := ValidateManifest(raw)
					if mode == "valid" {
						if err != nil || got.Version != 1 || !reflect.DeepEqual(got.Tools, m.Tools) {
							t.Fatal("new inventory refused", err)
						}
					} else if err != ErrManifest || got.Tools != nil {
						t.Fatal("tampered wallet tool accepted", err)
					}
				})
			}
		})
	}
}

const forwarderTemplate = "templates/systemd/swarma-wallet-alert-forwarder.service.in"

func assertReleasedForwarderTemplate(t *testing.T, repo, release string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join(repo, "deploy", forwarderTemplate))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(release, forwarderTemplate))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("release lacks exact forwarder template", err)
	}
	sums, err := os.ReadFile(filepath.Join(release, "SHA256SUMS"))
	if err != nil || strings.Count(string(sums), digest(want)+"  "+forwarderTemplate+"\n") != 1 {
		t.Fatal("forwarder template checksum missing", err)
	}
}

// Claim: fixture assembly preserves the committed forwarder unit and its checksum; real release coverage is checked by TestReleaseIntegration.
func TestAssembleShipsWalletAlertForwarderUnit(t *testing.T) {
	work, first, second := assembleFixture(t)
	_, stage, err := assemble(context.Background(), work, first, second, fixtureCommit, func(_ context.Context, _, _, _ string, a Artifact) ([]byte, error) {
		return fixtureBinary(a.Package), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertReleasedForwarderTemplate(t, first, stage)
}
