package notarycheck

import (
	"context"
	"net/http"
)

// NameObservation is the current value and registration at one explicit chain
// view. A source must fail rather than substitute its latest or cached view.
type NameObservation struct {
	Registration Point  `json:"registration"`
	Value        []byte `json:"-"`
	Height       int64  `json:"height"`
	BlockHash    string `json:"blockhash"`
}

// NameSource supplies chain reads without coupling the checker to node I/O.
// Offline callers must explicitly label their supplied observations as fixtures.
type NameSource interface {
	Lookup(name string, height int64, blockhash string) (NameObservation, error)
}

// NodeNameReader is the running RPC adapter. Its zero value fails closed.
type NodeNameReader struct {
	endpoint, user string
	password       rpcPassword
	client         *http.Client
	ctx            context.Context
}

// CheckRunning never accepts an injected fixture or operator-supplied source.
// The strict default needs no name source. This unconfigured MVP path refuses;
// the service uses CheckRunningWithNode with the concrete RPC adapter.
func CheckRunning(in Input) (Result, error) {
	if in.Names != nil {
		return Result{}, refuse("MVP_CHAIN_READ_REQUIRED")
	}
	in.Names = &NodeNameReader{}
	return Check(in)
}
