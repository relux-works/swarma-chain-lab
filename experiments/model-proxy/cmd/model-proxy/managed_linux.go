//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
)

// This nonsecret mapping is admitted by the same installed-file manifest and
// ownership boundary as the gateway configuration. It is never worker input.
type brokerFile struct {
	Socket             string `json:"socket"`
	BrokerUID          uint32 `json:"broker_uid"`
	ServiceGeneration  string `json:"service_generation"`
	Account            string `json:"account"`
	AgentUID           uint32 `json:"agent_uid"`
	AgentGeneration    string `json:"agent_generation"`
	LaunchID           string `json:"launch_id"`
	MaxLifetimeSeconds uint64 `json:"max_lifetime_seconds"`
}

var _ proxy.ManagedSource = (*service.Source)(nil)

func managedSource(ctx context.Context, raw []byte) (proxy.CredentialSource, func(), error) {
	var c brokerFile
	if len(raw) == 0 || len(raw) > proxy.MaxBody || json.Unmarshal(raw, &c) != nil {
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	canonical, e := json.Marshal(c)
	if e != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) || c.MaxLifetimeSeconds == 0 || c.MaxLifetimeSeconds > 900 {
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	client, e := service.Dial(ctx, service.Config{Socket: c.Socket, BrokerUID: c.BrokerUID, ServiceUID: uint32(os.Geteuid()), Generation: c.ServiceGeneration, MaxLifetime: time.Duration(c.MaxLifetimeSeconds) * time.Second})
	if e != nil {
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	source, e := service.NewSource(client, service.Caller{Account: c.Account, UID: c.AgentUID, Generation: c.AgentGeneration, LaunchID: c.LaunchID})
	if e != nil {
		client.Close()
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	adapted, e := proxy.AdaptManagedSource(source)
	if e != nil {
		client.Close()
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	closeSource := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = source.Close(ctx)
		_ = client.Close()
	}
	return adapted, closeSource, nil
}
