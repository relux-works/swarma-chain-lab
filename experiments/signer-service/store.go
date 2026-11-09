package signerservice

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	gs "relux.works/swarma-chain-lab/experiments/grant-store"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// S1Store fixes its URL and readers at construction. This regtest unit accepts
// only literal loopback HTTP; deployment TLS/mTLS is intentionally separate.
type S1Store struct {
	client               *gs.Client
	url, landlord, agent string
}

func NewS1Store(server string, key *nostr.PrivKey, landlord, agent string) (*S1Store, error) {
	u, e := url.Parse(server)
	if e != nil {
		return nil, fail("STORE_ROUTE")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || key == nil || !digest(landlord) || !digest(agent) {
		return nil, fail("STORE_ROUTE")
	}
	c := &gs.Client{Signer: key, MaxBytes: 16384, HTTP: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}}
	return &S1Store{c, server, landlord, agent}, nil
}
func (s *S1Store) Put(ctx context.Context, raw []byte) (string, error) {
	d, e := s.client.PutGrant(ctx, s.url, raw, s.landlord, s.agent)
	if e != nil {
		return "", fail("STORE_PENDING")
	}
	return d.SHA256, nil
}
