// Package kernelbind binds the landed M1 kernel
// (relux.works/swarma-chain-lab/experiments/rental) to the gateway's
// kernel.Checker interface, per the frozen interface in
// grants-dev/m1/INTERFACE.md (sha256 49f7942d…):
//
//	rental.Check(ctx, node singleuse.Node, policy rental.Policy,
//	  envelopeBytes []byte, stationName, senderPubkey string,
//	  nowUnix int64) rental.Receipt
//
// This is a separate nested module so the gateway module builds and
// tests on the pre-M1 base; it compiles once M1 lands at
// ../../rental (see go.mod replaces). The mapping is a field copy:
// the kernel owns every chain decision.
package kernelbind

import (
	"context"

	"relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	singleuse "relux.works/swarma-chain-lab/experiments/single-use"
)

// Adapter binds the real M1 kernel.
type Adapter struct {
	Node   singleuse.Node
	Policy rental.Policy
}

// Check implements kernel.Checker. The kernel never errors; every
// failure arrives as a pending/refused receipt, and only live admits.
func (a *Adapter) Check(ctx context.Context, envelopeBytes []byte, stationName, senderPubkey string, nowUnix int64) (kernel.Receipt, error) {
	r := rental.Check(ctx, a.Node, a.Policy, envelopeBytes, stationName, senderPubkey, nowUnix)
	return kernel.Receipt{
		Verdict:           r.Verdict,
		Reason:            r.Reason,
		CertificateSHA256: r.CertificateSHA256,
		StationName:       r.StationName,
		CheckedAt:         r.CheckedAt,
		Closed:            r.Closed,
		Scope:             r.Scope,
		BudgetSat:         r.BudgetSat,
	}, nil
}
