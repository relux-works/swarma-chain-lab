# CG1 dependencies and deployment boundary

CG1 reuses the landed rental v3 kernel and rental-gateway/kernelbind. It neither
forks chain validation nor depends on the unlanded exchange. The packaging and
Go version decision is tracked in UNRESOLVED_QUESTIONS.md: CG1 and a2a-link use
Go 1.26, while upstream a2a remains on 1.25 and never imports this module.

Infra must provision the verifier's own Namecoin Core regtest observer with
read-only rpcauth/rpcwhitelist. The reused single-use.NewRPC constructor requires
the exact username `w3-observer`, a literal loopback host and a bounded port and
password. There is no alternate username, route or credential fallback. Credentials
stay in the authenticated Courier engine's private deployment configuration.

The observer permits only getblockchaininfo, getblockhash, getblockheader,
getrawtransaction, gettxout, name_show, getrawmempool and getblock. No wallet or
transaction broadcast method is part of the checker. A custom operator-owned
Node implementation must preserve that read-only boundary and honor context
cancellation; untrusted received data must never select a Node implementation.

Courier supplies a transport-verified NIP-17 inner seal key and the complete
bounded grant-cert. It does not resolve S1 in v1. Upstream a2a owns a generic
admission seam; the a2a-link fork registers CG1 at build time. Matrix identities
cannot carry a grant policy. Held/retry and exchange spools are bounded and
owned by Courier, and never confer inbox or signing authority themselves.
