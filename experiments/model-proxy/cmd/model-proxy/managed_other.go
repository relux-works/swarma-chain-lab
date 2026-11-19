//go:build !linux

package main

import (
	"context"
	"errors"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

func managedSource(context.Context, []byte) (proxy.CredentialSource, func(), error) {
	return nil, nil, errors.New("CREDENTIAL_SOURCE")
}
