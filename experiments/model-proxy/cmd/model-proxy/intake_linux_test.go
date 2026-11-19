//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

func gatewayDirectory(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp(os.TempDir(), "gc-")
	if err != nil {
		t.Fatal("gateway scratch unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "credential-gateway", "service-current")
	if os.MkdirAll(directory, 0750) != nil {
		t.Fatal("generation directory unavailable")
	}
	return filepath.Join(directory, "gateway.sock")
}

// Claim: explicit socket mode still requires managed mode, the protected broker
// mapping and the fixed recipient; none is inferred from ambient configuration.
func TestGatewayStartupGuards(t *testing.T) {
	for _, mode := range []string{"development", "recipient", "missing-mapping", "mapping-read", "broker-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			config := proxy.GatewayFileConfig{Mode: proxy.ModeManaged}
			config.Upstream = proxy.ManagedUpstream
			brokerPath := "protected-mapping"
			var reads atomic.Int32
			read := func(path string, _ int64) ([]byte, error) {
				reads.Add(1)
				if path != brokerPath {
					t.Error("another source location was read")
				}
				if mode == "mapping-read" {
					return nil, errors.New(brokerCanary)
				}
				mapping := brokerFile{Socket: filepath.Join(t.TempDir(), "absent"), BrokerUID: uint32(os.Geteuid()), ServiceGeneration: "service-current", Account: "account-current", AgentUID: uint32(os.Geteuid()), AgentGeneration: "worker-current", LaunchID: "launch-current", MaxLifetimeSeconds: 60}
				return json.Marshal(mapping)
			}
			switch mode {
			case "development":
				config.Mode = ""
			case "recipient":
				config.Upstream = "https://untrusted.invalid/v1/messages"
			case "missing-mapping":
				brokerPath = ""
			}
			socket := gatewayDirectory(t)
			err := serveGateway(context.Background(), config, brokerPath, socket, read)
			if err == nil || err.Error() != "CREDENTIAL_SOURCE" {
				t.Fatal("unqualified socket startup was not refused with a closed diagnostic")
			}
			if _, statErr := os.Lstat(socket); !os.IsNotExist(statErr) {
				t.Fatal("failed startup left a listener")
			}
			if mode != "mapping-read" && mode != "broker-unavailable" && reads.Load() != 0 {
				t.Fatal("inactive or invalid configuration touched a credential source")
			}
		})
	}
}

// Claim: the explicit command path serves plaintext HTTP on the generation
// socket, checks its real kernel peer before leasing, and closes only its socket.
func TestGatewayCommandUnixPeer(t *testing.T) {
	for _, authorized := range []bool{false, true} {
		name := "unauthorized"
		if authorized {
			name = "authorized"
		}
		t.Run(name, func(t *testing.T) {
			fixture := startBroker(t)
			fixture.config.AgentUID = uint32(os.Geteuid())
			if !authorized {
				fixture.config.AgentUID++
			}
			raw, _ := json.Marshal(fixture.config)
			config := proxy.GatewayFileConfig{Mode: proxy.ModeManaged}
			config.Upstream = proxy.ManagedUpstream
			socket := gatewayDirectory(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- serveGateway(ctx, config, "protected-mapping", socket, func(string, int64) ([]byte, error) { return raw, nil })
			}()
			deadline := time.Now().Add(3 * time.Second)
			for {
				if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0660 {
					break
				}
				select {
				case <-done:
					t.Fatal("gateway startup failed")
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("gateway socket did not appear")
				}
				time.Sleep(time.Millisecond)
			}
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			target, expected := "http://api.anthropic.com/api/claude_code/policy_limits", 403
			if authorized {
				target, expected = "http://api.anthropic.com/not-admitted", 400
			}
			response, err := client.Get(target)
			if err != nil {
				t.Fatal("plaintext intake unavailable")
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != expected {
				t.Fatal("command listener peer gate changed")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal("gateway did not stop cleanly")
			}
			fixture.mu.Lock()
			requests := fixture.requests
			fixture.mu.Unlock()
			if requests != 0 {
				t.Fatal("unauthorized peer requested a broker lease")
			}
			if _, err := os.Lstat(socket); !os.IsNotExist(err) {
				t.Fatal("closed generation retained its listener")
			}
		})
	}
}

// Claim: the selected socket belongs to the exact protected generation; stale,
// writable, symlinked and non-socket-name locations remain unavailable.
func TestGatewaySocketQualification(t *testing.T) {
	for _, mode := range []string{"valid", "relative", "stale", "name", "writable", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			socket := gatewayDirectory(t)
			switch mode {
			case "relative":
				socket = "credential-gateway/service-current/gateway.sock"
			case "stale":
				socket = filepath.Join(filepath.Dir(filepath.Dir(socket)), "service-stale", "gateway.sock")
				if os.Mkdir(filepath.Dir(socket), 0750) != nil {
					t.Fatal("stale generation control unavailable")
				}
			case "name":
				socket = filepath.Join(filepath.Dir(socket), "other.sock")
			case "writable":
				if os.Chmod(filepath.Dir(socket), 0777) != nil {
					t.Fatal("writable control unavailable")
				}
			case "symlink":
				parent := filepath.Dir(filepath.Dir(socket))
				if os.Rename(parent, parent+"-real") != nil || os.Symlink(parent+"-real", parent) != nil {
					t.Fatal("symlink control unavailable")
				}
			}
			if gatewaySocketPath(socket, "service-current") != (mode == "valid") {
				t.Fatal("unqualified generation listener path admitted")
			}
		})
	}
}
