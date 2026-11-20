//go:build linux && gateway_lab

package main

import (
	"os"
	"path/filepath"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

// TestLabSocketPath proves the existing protected generation directory works while other generations, reused names and symlink ancestors refuse.
func TestLabSocketPath(test *testing.T) {
	root := test.TempDir()
	directory := filepath.Join(root, "credential-gateway", "generation")
	if os.MkdirAll(directory, 0750) != nil {
		test.Fatal("fixture")
	}
	socket := filepath.Join(directory, "gateway.sock")
	if !socketPath(socket, "generation") {
		test.Fatal("valid generation")
	}
	if socketPath(socket, "other") || socketPath(filepath.Join(directory, "other.sock"), "generation") {
		test.Fatal("path alias")
	}
	alternate := filepath.Join(root, "alternate")
	if os.Mkdir(alternate, 0750) != nil {
		test.Fatal("fixture")
	}
	alias := filepath.Join(alternate, "credential-gateway")
	if os.Symlink(filepath.Join(root, "credential-gateway"), alias) != nil {
		test.Fatal("fixture")
	}
	if socketPath(filepath.Join(alias, "generation", "gateway.sock"), "generation") {
		test.Fatal("symlink accepted")
	}
}

// TestLabRecordFiles proves a private nonsecret snapshot works while wrong modes and symlinks refuse.
func TestLabRecordFiles(test *testing.T) {
	directory := test.TempDir()
	path := filepath.Join(directory, "record")
	if os.WriteFile(path, []byte(`{}`), 0400) != nil {
		test.Fatal("fixture")
	}
	if _, err := proxy.ReadPrivateFile(path, 0400, 262144); err != nil {
		test.Fatal("valid snapshot", err)
	}
	if os.Chmod(path, 0600) != nil {
		test.Fatal("fixture")
	}
	if _, err := proxy.ReadPrivateFile(path, 0400, 262144); err == nil {
		test.Fatal("wrong file mode")
	}
	if os.Chmod(path, 0400) != nil {
		test.Fatal("fixture")
	}
	alias := filepath.Join(directory, "alias")
	if os.Symlink(path, alias) != nil {
		test.Fatal("fixture")
	}
	if _, err := proxy.ReadPrivateFile(alias, 0400, 262144); err == nil {
		test.Fatal("symlink")
	}
	if _, err := proxy.ReadPrivateFile(path, 0400, 262144); err != nil {
		test.Fatal("restored control", err)
	}
}
