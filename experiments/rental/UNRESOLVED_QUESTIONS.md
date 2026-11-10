# Remaining integration decisions

- V3 grant verification and the V2 payment issuer admit explicitly pinned NMC
  main and regtest. The legacy payment API `IssueGrant` stays regtest-only;
  main uses `IssueGrantWithNodes`. The MA1-03 main issuance witness uses explicit
  public reply projections over disposable regtest nodes, not mainnet consensus
  or real custody. Production deployment and spending authorization remain
  separate from this library; an unsigned plan is not spending approval. See
  [the main route audit](MAIN-ISSUANCE-AUDIT.md) for admitted and refused paths.
- Gateway/wallet adoption must migrate to the v3 policy and presentation wire,
  stable signed-grant ID, new receipt fields, authenticated inner sender and
  fresh Check for every action. Keeping the Go call shape does not migrate data.
- M3 must separately adopt names.register before real bookings can request it.
  Existing five-action contracts are preserved and do not grant that action.
- Scope/target/budget, anti-replay, prize exclusion and external effects belong
  to the enforcement point. Time/chain observations are not atomic with effects.
- Persistent state belongs outside hostile agent UIDs. Recovery must preserve
  closure, seen-seal indices and issuer booking/pool burns. Uncertain signature
  recovery intentionally stops; funding-input reservation is a signer concern.
- Funding and change must use a separately pinned key/script. Issuer/refill
  integrations must supply funding_script; old seal-funded plans cannot migrate
  through replay. The separate signer must enforce this on actual prevouts too.
- V3 grant signatures require the fixed `swarma-grant-v3` prefix. Earlier
  untagged development objects must be regenerated, never silently accepted.
- First observers cannot infer unseen rotations. Same-seal equivocation across
  independent verifiers remains possible without shared history. Per-grant
  issuance commits authority bytes but does not establish globally unique seals.
- Key rotation needs new seal ownership/policy pins for new grants and retained
  old policy/state observation for old grants. Cold name ownership is separate.
- The renter can see commitment inputs/formula before consenting, but final
  grant ID/landlord countersignature/commitment only after issuance. The UI and
  delivery/recovery flow for this verification need separate integration.
- Optional batch discovery remains outside the kernel. V3 always requires its
  own confirmed issuance commitment; a batch root cannot replace it.
- Bounded legacy/witness decoding does not locally validate input signatures;
  the own Core active-chain view provides that validation. Legacy W3 is unchanged.
- Public LIP/CIP publication and production security review belong to their
  owners. This producer supplies local signed source/evidence for independent review.

## SW1 follow-up boundary

The authenticated chain-pin wire encoding for construction profile W remains
open; current code requires the explicit local `construction_profile` pin.
SW1 is linkage-only. SW1b must first specify authenticated payment-role/terms
proofs and their GV4 binding before Q:0 can be an unconfirmed A input. Until then
`W_UNCONFIRMED_NON_LINKAGE_PARENT` rejects Q and every other ordinary unconfirmed
parent. See [the boundary inventory](../WITNESS-PROFILE.md); this is an explicit
deferred extension, not a fallback to L or a claim that full W is delivered.

## SW1-consumer-fixtures follow-up

`agent-wallet` and `rental-executor` consume grant-v3 `rental.Check`. Their trusted
policies must pin W and their historical opt-in Core fixtures need native/ALL
T/A construction migration. Those fixtures/configs are explicitly outside SW1
qualification and knowingly incompatible where they omit W or use legacy T/A.
Migrate and qualify both consumers before using them as W deployment examples;
no fallback or journal reset is authorized.
