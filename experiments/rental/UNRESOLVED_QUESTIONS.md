# Remaining integration decisions

- This is regtest-only. Production keys, deployment, signing caps, payment
  sweeping, revocation broadcast and availability remain separate work.
- Gateway adoption must use the detached policy, authenticated inner sender,
  inline exact-id presentation and a fresh Check for every message. Retaining
  the Go call shape does not migrate an old policy or signed wire automatically.
- M4 owns scope/target/budget, anti-replay, prize exclusion and effects. Kernel
  output alone does not authorize them. Time/chain observations are not atomic
  with an external effect.
- Persistent state belongs outside hostile station UIDs. Disaster recovery must
  preserve closure, seen-seal indices and issuer booking/pool burns. Automatic
  recovery of uncertain signatures is intentionally absent.
- First observers cannot infer unseen key rotations. Same-seal equivocation
  across independent verifiers remains possible without shared history.
- Grant-key rotation needs new seal ownership/policy pins for new grants and
  continued old policy/state observation for old certificates.
- Batch commitments bind cardinality and the internal root. A caller must
  still authenticate the chosen on-chain commitment; the kernel does not
  require an anchor or provide a production batch-discovery service.
- Bounded legacy/witness read decoding does not validate transaction input
  signatures locally; the own Core active-chain view supplies that validation.
  Legacy W3 signer profile is unchanged. Detached start_now has no anchor block;
  payment and pool must already be confirmed, signed hold bounds still apply.
- Public LIP/CIP specification publication and production custody review belong
  to their owners; this producer supplies source/evidence for independent review.
