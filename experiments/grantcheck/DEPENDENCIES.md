# CG1 dependencies and deployment boundary

CG1 reuses the landed rental v3 kernel and rental-gateway/kernelbind. It neither
forks chain validation nor depends on the unlanded exchange. The packaging and
Go version decision is tracked in UNRESOLVED_QUESTIONS.md: CG1 and a downstream transport adapter use
Go 1.26, while upstream a2a remains on 1.25 and never imports this module.

Infra must provision the verifier's own Namecoin Core regtest observer with
read-only rpcauth/rpcwhitelist. The reused single-use.NewRPC constructor requires
the exact username `w3-observer`, a literal loopback host and a bounded port and
password. There is no alternate username, route or credential fallback. Credentials
stay in the authenticated a2a daemon (a2ad) engine's private deployment configuration.

The observer permits only getblockchaininfo, getblockhash, getblockheader,
getrawtransaction, gettxout, name_show, getrawmempool and getblock. No wallet or
transaction broadcast method is part of the checker. Under an explicit `main`
configuration (README, "Contract profiles and configured network") the observer
is the verifier's own Namecoin Core mainnet node with the same read-only method
list; the checker then requires the chain name `main` and the mainnet genesis. A custom operator-owned
Node implementation must preserve that read-only boundary and honor context
cancellation; untrusted received data must never select a Node implementation.

a2a daemon supplies a transport-verified NIP-17 inner seal key and the complete
bounded grant-cert. It does not resolve S1 in v1. Upstream a2a owns a generic
admission seam; a downstream transport adapter registers CG1 at build time. A downstream transport adapter may use the test-bench grant policy only with
the verified per-message BIP-340 sender contract documented in POLICY.md. Held/retry and exchange spools are bounded and
owned by a2a daemon, and never confer inbox or signing authority themselves.

## Combined-budget published selections

The durable writer snapshot is `v0.3.1-0.20261114224110-dc6be5c16d88` and the
grantcheck snapshot containing its requirement is `v0.1.2-0.20261114224915-633a050cea27`.
Both descend from the strict-parser snapshot
`e70a35a41dec5948d5452f1f898f4d26977372d7`; the writer selection also contains
`dc6be5c16d8875de430e5c84943aecbc98efa23f`, which adds `Store.WriteBounded`.
Grantcheck consumers must select the corrected grantcheck manifest, not merely
a commit with a newer timestamp or the new API source. These pseudo-versions
name earlier signed commits; delivery must preserve those exact objects.
The graph snapshot remains a semantic floor and is regenerated independently
from the published strict-parser snapshot.
