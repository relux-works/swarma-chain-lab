package singleuse

import (
	"context"
	"time"
)

// ReadObservation exposes the existing own-node binding primitives to adjacent
// protocols. It neither authorizes effects nor applies W3 request policy.
// One instance is sequential, bounded to 30 seconds, and must be closed.
type ReadObservation struct {
	o      observation
	cancel context.CancelFunc
}
type ChainInfo = chainInfo
type Header = header
type TransactionView = rpcTx
type NameView = nameShow

// ParseCoins exposes the exact decimal-to-atoms parser used for node outputs.
func ParseCoins(s string) (int64, error) { return coins(s) }

func NewReadObservation(ctx context.Context, node Node) *ReadObservation {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	return &ReadObservation{o: observation{ctx: ctx, node: node}, cancel: cancel}
}
func (r *ReadObservation) Close()                              { r.cancel() }
func (r *ReadObservation) Start(network, genesis string) error { return r.o.start(network, genesis) }
func (r *ReadObservation) Call(method string, out any, args ...any) error {
	return r.o.call(method, out, args...)
}
func (r *ReadObservation) Transaction(id string) (TransactionView, *Transaction, error) {
	return r.o.transaction(id)
}

// PaymentTransaction binds legacy or witness payment serialization to stripped
// txid and exact RPC projections. Anchor/seal/spend paths keep Transaction().
func (r *ReadObservation) PaymentTransaction(id string) (TransactionView, *Transaction, error) {
	var view rpcTx
	if !digestHex(id) {
		return view, nil, fail("TXID")
	}
	if e := r.o.call("getrawtransaction", &view, id, true); e != nil {
		return view, nil, e
	}
	return bindPaymentTransaction(id, view)
}
func (r *ReadObservation) Confirmed(v TransactionView) (Header, error) { return r.o.confirmed(v) }
func (r *ReadObservation) Active(block string) (Header, error)         { return r.o.active(block) }
func (r *ReadObservation) Stable() error                               { return r.o.stable() }
func (r *ReadObservation) Tip() ChainInfo                              { return r.o.tip }
func (r *ReadObservation) Calls() int                                  { return r.o.calls }
