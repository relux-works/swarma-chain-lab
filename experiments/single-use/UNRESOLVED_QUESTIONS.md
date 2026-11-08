# Remaining research boundaries

- Independent review is required before publication or runtime admission.
- Mainnet support requires separate delta review and admission of the exact
  mainnet runtime, own-node route, pins and transactions; every transaction needs
  owner GO for its exact signed hex. Offline templates do not supply that GO.
- The grantee chain key is an operator pin in v0. A future attestation/registry
  protocol must bind it to the P-256 grant identity before removing that pin.
- A bounded legacy scan may refuse busy or witness-containing chains. A future
  spend-index/proof adapter needs its own contract and independent evidence.
- One confirmation permits reorg risk. No effect rollback, global deduplication
  or automatic retry of an uncertain durable reservation is defined.
- Process-crash controls do not establish power-loss guarantees across filesystems.
