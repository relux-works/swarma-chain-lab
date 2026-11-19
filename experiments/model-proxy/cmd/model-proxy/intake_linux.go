//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
)

func serveGateway(ctx context.Context, config proxy.GatewayFileConfig, brokerPath, socket string, read func(string, int64) ([]byte, error)) error {
	if config.Mode != proxy.ModeManaged || config.Upstream != proxy.ManagedUpstream || len(config.ModelProfiles) != 0 || brokerPath == "" {
		return errors.New("CREDENTIAL_SOURCE")
	}
	raw, err := read(brokerPath, proxy.MaxBody)
	if err != nil {
		return errors.New("CREDENTIAL_SOURCE")
	}
	startup, cancelStartup := context.WithTimeout(ctx, 5*time.Second)
	holder, err := openManagedHolder(startup, raw)
	cancelStartup()
	if err != nil {
		return err
	}
	defer holder.close()
	caller, generation := holder.GatewayBinding()
	if !gatewaySocketPath(socket, generation) {
		return errors.New("LISTEN")
	}
	gateway, err := service.NewGateway(holder, service.Mapping{Caller: caller, ServiceGeneration: generation, Listener: generation, Policy: "claude-launch-v1", Placeholder: service.Placeholder})
	if err != nil {
		return errors.New("CREDENTIAL_SOURCE")
	}
	defer gateway.Close()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return errors.New("LISTEN")
	}
	defer listener.Close()
	if os.Chmod(socket, 0660) != nil {
		return errors.New("LISTEN")
	}
	server := &http.Server{Handler: gateway, ConnContext: gateway.ConnContext, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	defer server.Close()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return errors.New("LISTEN")
}

func gatewaySocketPath(socket, generation string) bool {
	directory := filepath.Dir(socket)
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || filepath.Base(socket) != "gateway.sock" || filepath.Base(directory) != generation || filepath.Base(filepath.Dir(directory)) != "credential-gateway" {
		return false
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	for parent := directory; ; parent = filepath.Dir(parent) {
		entry, err := os.Lstat(parent)
		if err != nil || !entry.IsDir() {
			return false
		}
		if parent == filepath.Dir(parent) {
			return true
		}
	}
}
