package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: each real CLI rolls back a closed stdout pipe without partial files, then permits same-path retry with exact public output matching the stored secret.
func TestG2CLIClosedStdoutPipeRollback(t *testing.T) {
	directory, params, public := g2OutputInputs(t)
	binary := filepath.Join(directory, "deploy-kit")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("setup build: %v %s", err, output)
	}
	for _, command := range []string{"g2-keygen", "g2-rpcauth"} {
		t.Run(command, func(t *testing.T) {
			outputDir := t.TempDir()
			destination := filepath.Join(outputDir, "secret")
			args := []string{command, "-out", destination}
			if command == "g2-rpcauth" {
				args = []string{command, "-params", params, "-wallet-public", public, "-wallet-config-out", destination}
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			// Close the only read end before starting the child: its real fd 1
			// write must encounter EPIPE, without timing or an injected signal.
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			process := exec.CommandContext(ctx, binary, args...)
			process.Stdout = writer
			var stderr bytes.Buffer
			process.Stderr = &stderr
			runErr := process.Run()
			t.Logf("closed stdout: status=%v error=%v", process.ProcessState, runErr)
			if _, statErr := os.Lstat(destination); !os.IsNotExist(statErr) {
				t.Fatalf("G2_CLOSED_PIPE_RETAINED_SECRET: stat_error=%v", statErr)
			}
			entries, err := os.ReadDir(outputDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("G2_CLOSED_PIPE_PARTIAL_FILE: entries=%d error=%v", len(entries), err)
			}
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), "broken pipe") {
				t.Fatalf("expected handled EPIPE and exit 1: error=%v stderr_bytes=%d", runErr, stderr.Len())
			}

			// A fresh process with writable stdout must succeed at the same path.
			var stdout bytes.Buffer
			stderr.Reset()
			retry := exec.CommandContext(ctx, binary, args...)
			retry.Stdout, retry.Stderr = &stdout, &stderr
			if err := retry.Run(); err != nil || stderr.Len() != 0 {
				t.Fatalf("same-path retry: error=%v stderr_bytes=%d", err, stderr.Len())
			}
			raw, err := os.ReadFile(destination)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(destination)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("retry did not create a regular file")
			}
			if command == "g2-keygen" {
				scalar, err := hex.DecodeString(string(raw))
				if err != nil || len(raw) != 64 || len(scalar) != 32 || info.Mode().Perm() != 0600 {
					t.Fatal("retry key format or mode")
				}
				if stdout.String() != "G2_KEY_XONLY "+g2TestXOnly(t, scalar)+"\n" || bytes.Contains(stdout.Bytes(), raw) {
					t.Fatal("retry output is not exactly the stored key's public line")
				}
			} else {
				var wallet g2WalletConfig
				if json.Unmarshal(raw, &wallet) != nil || info.Mode().Perm() != 0640 {
					t.Fatal("retry wallet format or mode")
				}
				matches := g2RPCAuthLines.FindStringSubmatch(stdout.String())
				if matches == nil {
					t.Fatal("retry output is not exactly the three public rpcauth lines")
				}
				for i, route := range []g2WalletRoute{wallet.Observer, wallet.Wallet.Route, wallet.Broadcast} {
					if route.Username != g2RPCRoutes[i] || len(route.Password) != 64 || !g2TestCoreVerify(matches[1+2*i], matches[2+2*i], route.Password) || strings.Contains(stdout.String(), route.Password) {
						t.Fatalf("retry public line %d does not verify the stored route password or leaks it", i)
					}
				}
			}
		})
	}
}
