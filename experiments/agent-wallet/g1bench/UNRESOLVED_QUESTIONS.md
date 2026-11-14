# Remaining native trust integration

Track A now preserves native-shaped Ed25519 swarm-envelope/2 messages and adds
the accepted BIP-340 co-signature over exact bytes. It uses the transport-neutral
checker API and protected per-identity recipient bindings. Those follow-ups are
resolved in the bench.

Fixture keys and the synthetic zero attestation reference do not implement
root-signed attestation, generation/revocation evidence, production binding
storage, or installed-consumer qualification. Those remain deployment work.
The closed bench handler is not a general message payload grammar.

A BIP-340 envelope author profile (Track B) remains a separately reviewed future
change. Track A does not relabel the Ed25519 author as the grant key. Its local
strict BIP-340 parser should switch to the shared helper once that helper lands
on main; the current base has no such helper.
