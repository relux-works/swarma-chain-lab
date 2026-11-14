# Native envelope integration decision

The native message profile permits Ed25519 authors and P-256 approvers, with
verified attestations. This BIP-340-only laboratory cannot establish native
`swarm-envelope/2` conformance. Before a real carrier consumes these grants,
a separately reviewed change must define either an admitted BIP-340 profile or
an authenticated binding from the native envelope author to the v3 grant key.
The benchmark deliberately chooses neither production architecture.

The checker compatibility adapter still targets main's `Inbound(ctx, key,
presentation)` API. Switching to a transport-neutral API belongs to the separate
checker change after its interface is accepted. No checker or K1 source is
changed by this benchmark.
