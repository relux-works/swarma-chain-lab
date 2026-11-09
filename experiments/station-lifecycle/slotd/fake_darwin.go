//go:build darwin && slotdfake

package slotd

import (
	"context"
	"net"
	"time"
)

// NewFakeClient exposes only the transport seam for explicit Darwin rehearsal
// builds. Requests and responses still traverse the production r4 stream codec.
// It grants no Linux peer authority and is absent in every Linux build.
func NewFakeClient(dial func(context.Context) (net.Conn, error)) (*Client, error) {
	if dial == nil {
		return nil, failure("SLOTD_FAKE_DIAL")
	}
	return &Client{dial: dial, timeout: 2 * time.Second}, nil
}
