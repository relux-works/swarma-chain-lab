//go:build linux && gateway_lab

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
)

type brokerMapping struct {
	Socket           string `json:"socket"`
	BrokerUID        uint32 `json:"broker_uid"`
	Generation       string `json:"service_generation"`
	Account          string `json:"account"`
	WorkerUID        uint32 `json:"agent_uid"`
	WorkerGeneration string `json:"agent_generation"`
	LaunchID         string `json:"launch_id"`
	Lifetime         uint64 `json:"max_lifetime_seconds"`
}

func main() {
	flag.CommandLine.SetOutput(io.Discard)
	configPath := flag.String("config", "", "")
	brokerPath := flag.String("broker-config", "", "")
	socket := flag.String("gateway-socket", "", "")
	paths := make([]*string, 5)
	for index, name := range []string{"activation", "authority", "fence", "manager-floor", "release-set"} {
		paths[index] = flag.String(name, "", "")
	}
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if flag.NArg() != 0 || run(ctx, *configPath, *brokerPath, *socket, paths) != nil {
		_, _ = io.WriteString(os.Stderr, "LAB_GATEWAY_REFUSED\n")
		os.Exit(1)
	}
}

type runInputs struct {
	loadConfig    func(string) (proxy.GatewayFileConfig, error)
	readInstalled func(string, int64) ([]byte, error)
	readPrivate   func(string, os.FileMode, int64) ([]byte, error)
	gatewayIO     service.LabGatewayIO
}

func run(ctx context.Context, configPath, brokerPath, socket string, paths []*string, supplied ...runInputs) error {
	inputs := runInputs{loadConfig: proxy.LoadGatewayConfig, readInstalled: proxy.ReadInstalledFile, readPrivate: proxy.ReadPrivateFile}
	if len(supplied) > 1 {
		return errors.New("closed")
	}
	if len(supplied) == 1 {
		inputs = supplied[0]
	}

	if len(paths) != 5 || inputs.loadConfig == nil || inputs.readInstalled == nil || inputs.readPrivate == nil {
		return errors.New("closed")
	}
	config, err := inputs.loadConfig(configPath)
	if err != nil || config.Mode != proxy.ModeManaged || config.Upstream != proxy.ManagedUpstream || len(config.ModelProfiles) != 0 || config.DailyCostCeilingNanoUSD == 0 {
		return errors.New("closed")
	}
	records := make([][]byte, 5)
	for index, path := range paths {
		records[index], err = inputs.readPrivate(*path, 0400, 262144)
		if err != nil {
			return errors.New("closed")
		}
	}
	pins, err := service.NewLabPins(records[0], records[1], records[2], records[3], records[4])
	if err != nil {
		return errors.New("closed")
	}
	raw, err := inputs.readInstalled(brokerPath, 65536)
	if err != nil {
		return errors.New("closed")
	}
	var mapping brokerMapping
	if json.Unmarshal(raw, &mapping) != nil {
		return errors.New("closed")
	}
	canonical, _ := json.Marshal(mapping)
	if !bytes.Equal(raw, canonical) || mapping.Lifetime < 1 || mapping.Lifetime > 900 || !socketPath(socket, mapping.Generation) {
		return errors.New("closed")
	}
	ended := make(chan struct{})
	source, err := service.OpenLabSource(ctx, service.Config{Socket: mapping.Socket, BrokerUID: mapping.BrokerUID, ServiceUID: uint32(os.Geteuid()), Generation: mapping.Generation, MaxLifetime: time.Duration(mapping.Lifetime) * time.Second}, pins, func() { close(ended) })
	if err != nil {
		return errors.New("closed")
	}
	defer source.Close()
	caller, _ := source.GatewayBinding()
	if caller.Account != mapping.Account || caller.UID != mapping.WorkerUID || caller.Generation != mapping.WorkerGeneration || caller.LaunchID != mapping.LaunchID {
		return errors.New("closed")
	}
	adapted, err := proxy.AdaptManagedSource(source)
	if err != nil {
		return errors.New("closed")
	}
	meter, err := proxy.New(proxy.Config{DailyCostCeilingNanoUSD: config.DailyCostCeilingNanoUSD, StateDir: config.StateDir, Endpoint: config.Endpoint, Upstream: config.Upstream, Source: adapted, Mode: config.Mode, Models: config.Models, Now: time.Now})
	if err != nil {
		return errors.New("closed")
	}
	defer meter.Close()
	gateway, err := service.NewLabGateway(source, meter.ReserveGeneration, inputs.gatewayIO)
	if err != nil {
		return errors.New("closed")
	}
	defer gateway.Close()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return errors.New("closed")
	}
	defer listener.Close()
	if os.Chmod(socket, 0660) != nil {
		return errors.New("closed")
	}
	requests := &labRequests{next: gateway}
	server := &http.Server{Handler: requests, ConnContext: gateway.ConnContext, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Minute, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
		case <-ended:
		case <-closed:
			return
		}
		_ = server.Close()
		_ = listener.Close()
	}()
	err = server.Serve(listener)
	_ = server.Close()
	requests.drain()
	if source.AwaitHold(ctx) != nil {
		return errors.New("closed")
	}
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return errors.New("closed")
}

type labRequests struct {
	next    http.Handler
	mu      sync.Mutex
	retired bool
	pending sync.WaitGroup
}

func (requests *labRequests) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requests.mu.Lock()
	if requests.retired {
		requests.mu.Unlock()
		http.Error(writer, "GATEWAY_REFUSED", http.StatusServiceUnavailable)
		return
	}
	requests.pending.Add(1)
	requests.mu.Unlock()
	defer requests.pending.Done()
	requests.next.ServeHTTP(writer, request)
}
func (requests *labRequests) drain() {
	requests.mu.Lock()
	requests.retired = true
	requests.mu.Unlock()
	requests.pending.Wait()
}

func socketPath(socket, generation string) bool {
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
