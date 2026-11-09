package main

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

// No UID or spending defaults: presence selects the v2 bootstrap profile.
type modelProxyConfig struct {
	AdminSocket string     `json:"admin_socket"`
	ServerUID   *uint32    `json:"server_uid"`
	Origin      string     `json:"origin"`
	CertSHA256  string     `json:"cert_sha256"`
	Caps        proxy.Caps `json:"caps"`
}

func (m *modelProxyConfig) valid() bool {
	if m == nil {
		return true
	}
	if !bookingModelCaps(m).Valid() {
		return false
	}
	u, e := url.Parse(m.Origin)
	return absPath(m.AdminSocket) && len(m.AdminSocket) <= 100 && m.ServerUID != nil && pinDigest(m.CertSHA256) && m.Caps.Valid() && e == nil && u.Scheme == "https" && u.Hostname() != "" && u.Path == "" && u.RawPath == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.String() == m.Origin && u.Host == strings.ToLower(u.Host) && !strings.Contains(m.Origin, "#")
}

func bookingModelCaps(m *modelProxyConfig) *booking.ModelCaps {
	if m == nil {
		return nil
	}
	c := m.Caps
	return &booking.ModelCaps{InputTokens: c.InputTokens, OutputTokens: c.OutputTokens, Requests: c.Requests, MaxTokens: c.MaxTokens, CostNanoUSD: c.CostNanoUSD, DefaultMaxOutputTokens: c.DefaultMaxOutputTokens}
}

type pinnedRegistrar struct {
	client   gatewaybind.ModelRegistrar
	endpoint proxy.Endpoint
}

func (r *pinnedRegistrar) Prepare(ctx context.Context, b proxy.Binding) (proxy.Credential, error) {
	credential, e := r.client.Prepare(ctx, b)
	if e != nil {
		return proxy.Credential{}, errors.New("MODEL_PREPARE")
	}
	if !credential.Valid() || credential.Endpoint != r.endpoint {
		return proxy.Credential{}, errors.New("MODEL_ENDPOINT_PIN")
	}
	return credential, nil
}
func (r *pinnedRegistrar) Activate(ctx context.Context, b proxy.Binding) error {
	if r.client.Activate(ctx, b) != nil {
		return errors.New("MODEL_ACTIVATE")
	}
	return nil
}
func (r *pinnedRegistrar) Revoke(ctx context.Context, b proxy.Binding) error {
	if r.client.Revoke(ctx, b) != nil {
		return errors.New("MODEL_REVOKE")
	}
	return nil
}
func stationDriverConfig(c serveConfig, store *journal.Store) gatewaybind.Config {
	m := c.Station.Manager
	cfg := gatewaybind.Config{StateDir: m.StateDir, Journal: store, PayloadID: m.PayloadID, PayloadSHA256: m.PayloadSHA256, SlotMin: uint16(m.SlotMin), SlotMax: uint16(m.SlotMax), ManagerCertSHA256: m.TLS.ManagerCertSHA256, Now: time.Now, StartTimeout: time.Duration(m.StartMilliseconds) * time.Millisecond}
	if p := c.ModelProxy; p != nil {
		cfg.ModelRegistrar = &pinnedRegistrar{client: proxy.Client{SocketPath: p.AdminSocket, ServerUID: *p.ServerUID}, endpoint: proxy.Endpoint{URL: p.Origin, CertSHA256: p.CertSHA256}}
		cfg.ModelCaps = p.Caps
	}
	return cfg
}
