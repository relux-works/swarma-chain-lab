// Package kernelbind binds the landed detached-grant kernel
// (relux.works/swarma-chain-lab/experiments/rental, LIP-0003) to
// the gateway's kernel boundary:
//
//	rental.Check(ctx, node, policy, envelopeBytes, agentName,
//	  senderPubkey, nowUnix) rental.Receipt
//	rental.Present(ctx, node, policy, envelopeBytes, id, agentName,
//	  senderPubkey, nowUnix) rental.Receipt
//	rental.CachedCertificate(policy, senderPubkey) ([]byte, string, error)
//
// The mapping is a field copy: the kernel owns every chain
// decision. This stays a separate nested module so the gateway
// module keeps building without the chain stack; its replaces now
// resolve in-tree (../../rental and siblings).
package kernelbind

import (
	"context"
	"fmt"

	"relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	singleuse "relux.works/swarma-chain-lab/experiments/single-use"
)

// Adapter binds the real detached kernel. It implements both
// kernel.Checker and kernel.Presenter.
type Adapter struct {
	Node   singleuse.Node
	Policy rental.Policy
}

var (
	_ kernel.Checker   = (*Adapter)(nil)
	_ kernel.Presenter = (*Adapter)(nil)
)

// New builds an Adapter with the detached policy pins: regtest
// network + genesis are fixed by the kernel profile, the seal
// script is derived from the pinned issuer (grant) key, and
// stateDir is the kernel's own durable store (presentation cache,
// seal index, per-certificate state). It must be an absolute,
// cleaned path (the kernel enforces this again).
func New(node singleuse.Node, stateDir, agentName, issuerPubkey string) (*Adapter, error) {
	script, err := rental.GrantSealScript(issuerPubkey)
	if err != nil {
		return nil, fmt.Errorf("kernelbind: issuer key: %w", err)
	}
	return &Adapter{
		Node: node,
		Policy: rental.Policy{
			Network:    "regtest",
			Genesis:    singleuse.RegtestGenesis,
			AgentName:  agentName,
			SealScript: script,
			StateDir:   stateDir,
		},
	}, nil
}

func mapReceipt(r rental.Receipt) kernel.Receipt {
	return kernel.Receipt{
		Verdict:           r.Verdict,
		Reason:            r.Reason,
		CertificateSHA256: r.CertificateSHA256,
		StationName:       r.StationName, // v2 carries the agent name here
		CheckedAt:         r.CheckedAt,
		Closed:            r.Closed,
		Scope:             r.Scope,
		BudgetSat:         r.BudgetSat,
	}
}

// Check implements kernel.Checker against the detached kernel. The
// kernel never errors; every failure arrives as a pending/refused
// receipt, and only live admits.
func (a *Adapter) Check(ctx context.Context, envelopeBytes []byte, agentName, senderPubkey string, nowUnix int64) (kernel.Receipt, error) {
	return mapReceipt(rental.Check(ctx, a.Node, a.Policy, envelopeBytes, agentName, senderPubkey, nowUnix)), nil
}

// Present implements kernel.Presenter: a fresh Check, and only a
// live verdict admits the bytes into the kernel's bounded
// per-sender presentation cache (replacement only via a new live
// presentation; cache-full refuses a new sender).
func (a *Adapter) Present(ctx context.Context, envelopeBytes []byte, id, agentName, senderPubkey string, nowUnix int64) (kernel.Receipt, error) {
	return mapReceipt(rental.Present(ctx, a.Node, a.Policy, envelopeBytes, id, agentName, senderPubkey, nowUnix)), nil
}

// CachedCertificate implements kernel.Presenter: it returns the
// cached public envelope bytes for a sender (never a verdict —
// every message is still Checked fresh), or
// kernel.ErrNoPresentation when the sender has presented nothing.
func (a *Adapter) CachedCertificate(senderPubkey string) ([]byte, error) {
	raw, _, err := rental.CachedCertificate(a.Policy, senderPubkey)
	if err != nil {
		if err.Error() == "PRESENTATION_ABSENT" {
			return nil, kernel.ErrNoPresentation
		}
		return nil, err
	}
	return raw, nil
}
