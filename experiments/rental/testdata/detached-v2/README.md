# Detached v2 public wire fixture

Deterministic laboratory keys 1 (grant), 2 (grantee), 3 (nostr); no production
custody material. `unsigned.json`, `envelope.json` and `agent-value.json` are
exact canonical bytes without a newline. `metadata.json` pins both digests and
the even-y P2PKH seal script. This is an offline interoperability fixture, not
a live certificate: the repeated-b transaction id is intentionally synthetic.
`TestDetachedFixture` verifies these bytes and bindings without re-signing.
