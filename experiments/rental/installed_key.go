package rental

import (
	"context"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
)

const installedService = "issuer"

var installedRead = func(path string, limit int64) ([]byte, error) {
	return configguard.ReadService(installedService, path, limit)
}

func readInstalledGrantKey(path, expected string) (*secp.PrivateKey, error) {
	raw, e := installedRead(path, 32)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	return parseGrantKey(raw, expected)
}

// IssueInstalledGrant is the daemon custody boundary; it never falls back to
// the standalone tool's owner-private key-file contract.
func IssueInstalledGrant(ctx context.Context, node su.Node, p IssuerPolicy, request, publication []byte, pool Point, spec PlanSpec, keyPath string, now int64) GrantIssueResult {
	return issueGrantRouted(ctx, node, p, request, publication, pool, spec, keyPath, now, nil, nil, readInstalledGrantKey)
}
func IssueInstalledGrantWithNodes(ctx context.Context, identity su.Node, payments map[string]su.Node, p IssuerPolicyV2, request, publication []byte, pool Point, spec PlanSpec, keyPath string, now int64) GrantIssueResult {
	route := grantPaymentRoute{policies: map[string]PaymentAdmissionPolicy{}, nodes: map[string]su.Node{}}
	for coin, policy := range p.PaymentPolicies {
		route.policies[coin] = policy
	}
	for coin, node := range payments {
		route.nodes[coin] = node
	}
	return issueGrantRouted(ctx, identity, p.IssuerPolicy, request, publication, pool, spec, keyPath, now, nil, &route, readInstalledGrantKey)
}
