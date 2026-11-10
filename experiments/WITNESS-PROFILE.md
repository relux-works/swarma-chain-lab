# SW1: linkage-only witness construction

The authenticated chain configuration must explicitly select `construction_profile:
"W"`. This implements the first, linkage-only delivery of LIP-0008 §1.1 and §9
(spec pin `e1533ce4`). The exact future chain-pin wire encoding remains open;
this field is a local authenticated configuration pin, not an unsigned assertion
in a presentation. Missing, unknown and `L` values refuse. Profile L is not
implemented. Existing v3 grant bytes, signing domain and issuance commitments do
not change; profile W constrains their transaction construction and observation.

SW1b is deferred: there is **no unconfirmed payment exception** in this delivery.
A signed grant/presentation does not yet authenticate the payment role and terms
needed to distinguish payment output Q from arbitrary wallet funding. Therefore
T:L + Q:0 refuses when Q is unconfirmed, even if Q is itself native P2WPKH/ALL.
Do not add an unsigned role flag, infer payment from a script/address, or present
this subset as the complete future two-parent W contract.

## Transaction contract

Every input of seal creation T and issuance anchor A spends an exact native v0
20-byte keyhash program (`0014` followed by 20 bytes), has an empty scriptSig,
and has exactly a strict DER low-S signature ending in byte `01` plus a valid
compressed public key matching that program. The verifier recomputes BIP143
using the actual spent output amount/script and checks every signature. A witness
marker or consensus-valid transaction is insufficient. Wrapped witness, legacy,
P2WSH, taproot, NONE, SINGLE and ANYONECANPAY all refuse.

Ordinary T/A funding must be confirmed. A may spend at most one non-seal output
L of T; L must itself be native P2WPKH. If T is unconfirmed, or T and A appear in
the same block, A must spend this L. A may instead use independently confirmed
funding when T is already in an earlier block. Confirmed ordinary parents must
precede their spender's block; same-block T must precede A in that exact block.
No other mempool or same-block parent is allowed. Coinbase may terminate
confirmed funding ancestry. No recursive unconfirmed ancestry is admitted.

W does not constrain the seal output script. The current issuer still pins its
existing grant-key P2PKH seal, and revocation spends that seal through its existing
legacy path. Historical explicit v0/v2/name transaction APIs remain historical;
they do not provide an alternate v3 W admission path.

The producer authenticates T's complete signed raw transaction before signing
the grant that contains its stripped txid/outpoint. It never rebuilds T after
that signature. A is planned after grant signing, frozen durably, signed, then
referenced by its stripped txid. Recovery rechecks exact plan, inputs, outputs,
prevouts and all witness signatures. Witness bytes are preserved for rebroadcast
and observation; txids exclude witness. Historical signing-time confirmation
cannot be reconstructed from final bytes alone: the producer enforces it live,
and the receiver checks active-chain parent/block precedence.

## Boundary inventory

| Boundary | Checks / consequence |
| --- | --- |
| `single-use.DecodeWitnessTransaction`, `VerifyWitnessInputs` | Bounded witness codec, every actual prevout, empty scriptSig, exact stack, native program, ALL byte, keyhash, DER/low-S and cryptographic signature. Legacy decoder stays strict. |
| `ReadObservation.WitnessCreation` | Own-node raw T bound to signed seal txid, RPC projection, output index, active parent membership and confirmed ordinary funding. |
| `ReadObservation.WitnessIssuance` | Repeats T checks; binds raw A; forbids seal spend, multiple links, non-native L, other unconfirmed parents and invalid dependency/block order; returns no partial construction on refusal. |
| `rental.IssueGrant` / `IssueGrantWithNodes` | Trusted W/funding pins, live T check before reservation/signature, exact L exception, actual unspent amount/script, repeated funding and node stability checks. Payment admission remains confirmed. |
| `rental.MakeGrantIssuancePlan`, pool refill | Explicit W in plan; native funding/change, at most one T-derived funding input. Offline plans do not assert confirmation. Revoke remains a distinct seal-spend plan. |
| `rental.Check` / `Present` | W graph check after issuance commitment confirmation and before new live state/cache admission. Existing durable closures/name-rotation semantics remain conservative. |
| `signer-service` config, `observe`, signing/recovery | Explicit W; native funding key preserves compressed-key parity. Observe validates T for enrolled/used seals; only exact L paired with that seal can be unconfirmed. Issuance prefers enrolled L. Actual signatures are ALL only; missing W on T/A plans never selects legacy signing. |
| `signer-service` broadcast/publication | Decode witness while deriving stripped txid; recover exact original raw bytes after lost ACK. Reobserve full W graph and stable confirmed A before publishing presentation. |
| `kernelbind.New` / `NewForNetwork` | Required explicit construction-profile parameter; passes authenticated pin into rental policy. |
| `grantcheck.New` | Required `Config.ConstructionProfile`, checked before state opens and included in durable binding. Real kernelbind admission remains mandatory. |
| gateway config / booking admission | Required `kernel.construction_profile`; real adapter invokes rental checks before grant admission. Booking payment logic has no unconfirmed-payment exception. |
| deploy issuer/gateway templates and validators | Carry explicit W; native funding script in issuer template. This is configuration validation, not chain authority or deployment authorization. |
| `agent-wallet`, `rental-executor` | Both call `rental.Check` for grant-v3 admission and now require `policy.construction_profile: "W"` in their trusted policy. Missing/other values refuse before RPC or cache access. Wallet payment/name planners remain separate. |
| `sealwatch` | Historical v0 seal/certificate path; no T/A grant-v3 construction admission entry point. |

Profile pins are included in kernel, issuer and grantcheck state bindings; signer
already binds the full configuration. An old journal is not silently adopted
under the new construction policy. Preserve it and provision a separately owned
state root after review. Do not erase issuance reservations or closures.

## Stable W reasons

| Reason | Refusal |
| --- | --- |
| `W_PROFILE_REQUIRED` | Missing, mismatched or unsupported authenticated profile. |
| `W_WITNESS_REQUIRED`, `W_WITNESS_SHAPE` | Missing witness or wrong per-input stack/signature/key shape. |
| `W_NATIVE_P2WPKH_REQUIRED` | Spent program is not native P2WPKH, or scriptSig is nonempty. |
| `W_SIGHASH_ALL_REQUIRED` | Any input uses a signature mode other than exact ALL. |
| `W_PUBLIC_KEY`, `W_SIGNATURE_INVALID` | Program/key mismatch or invalid/noncanonical signature, amount or body commitment. |
| `W_DUPLICATE_INPUT`, `W_PREVOUT` | Duplicate input or invalid/missing prevout/index/amount. |
| `W_TXID`, `W_BODY_BINDING`, `W_COINBASE_INPUT` | Wrong raw transaction identity/projection or coinbase used as T/A. |
| `W_PARENT_STATE`, `W_SEAL_OUTPUT` | Inconsistent confirmation metadata or absent seal output. |
| `W_UNCONFIRMED_NON_LINKAGE_PARENT` | Any ordinary parent is unconfirmed or not earlier than its confirmed spender. Includes deferred payment Q. |
| `W_LINKAGE_SCRIPT`, `W_LINKAGE_REQUIRED` | Invalid L program, multiple T-derived A inputs, or absent necessary dependency. |
| `W_ISSUANCE_SPENDS_SEAL`, `W_DEPENDENCY_ORDER` | A consumes the grant seal, or T/A block dependency is inconsistent/reversed. |

Existing bounded codec, own-node RPC, active-chain membership, stale observation,
funding-policy, reservation, fee and output-binding reasons also remain in force.
A construction refusal grants no authority and creates no new reservation,
signature or admitted proof. Existing clock high-water, lock files, rejection
telemetry and already justified monotonic closure handling are not authority.

## Tools and evidence

Run Go commands only in an owned physical scratch checkout with absolute HOME,
config, temp, toolchain and cache paths under that same root (Go 1.26.8).

- Module checks: `go test -race ./...`, `go vet ./...`, `go build ./...` from
  each affected module. Core tests are opt-in, not implied by default passes.
- From repository root: `go run .scripts/sw1-guards.go -out /absolute/new-dir`.
  Go overlays calibrate each plant with a passing baseline and the intended
  assertion failure; logs, source/mutant hashes, PIDs and exits go to that dir.
- From `experiments/signer-service`, provide `SG1_REGTEST=1`, a **new** absolute
  `SG1_RUN_ROOT`, and pinned `SG1_CORE_DAEMON` / `SG1_CORE_CLI`; run separately:
  `go test -race -count=1 -run '^TestCoreWitnessSameBlock$' .` and
  `go test -race -count=1 -run '^TestCoreWitnessRefusals$' .`, plus
  `go test -race -count=1 -run '^TestCoreWitnessFundingConfirmation$' .` for
  Enroll/Refill refusal, ledger preservation and the confirmed neighbor.
- From `experiments/rental`, the analogous `M1_*` variables and
  `go test -race -count=1 -run '^TestCoreWitnessIssuerParentRefusal$' .` exercise
  a real unconfirmed ordinary funding refusal and its confirmed neighbor.

These fixtures start only isolated regtest nodes, record and stop their PIDs,
and preserve sanitized public evidence separately from private fixture state.
Independent btcd digest/script-engine controls supplement genuine Core tests.
Graph fixtures cover extra/third parent, legacy ancestry, L script, changed T
body and block ordering with exact reasons and no partial result. They do not
claim a simulated graph is a separately consensus-validated chain.

### Consumer qualification limit

`agent-wallet` and `rental-executor` grant-v3 configs and historical opt-in Core
fixtures are outside SW1 qualification and knowingly incompatible where they
omit W or construct legacy T/A. The required follow-up is
`SW1-consumer-fixtures`: migrate both consumers' fixture funding/graphs and
policies, then qualify their Core suites. This does not weaken `rental.Check`.

### Control interpretation

The SW1 overlay suite includes signer ordinary-funding, graph linkage cardinality,
seal-spend and offline planner cardinality controls. The native-input control
uses nonempty scriptSig with otherwise valid signatures; the body-binding control
uses the funding reader; signer profile controls use valid dependencies. These
mutations turn refusal into admission, not merely a later error.

Two intentionally redundant checks retain reason-only controls: removing the
linkage-script check still encounters native-input verification, and removing
the grantcheck startup pin still encounters kernelbind's pin check. Their logs
prove the intended early reason/order, not an admission bypass. The signer
second-link bound is likewise backed by the final exact-one-link check; its
negative case is tested, but a single-bound mutation is not claimed detected.
