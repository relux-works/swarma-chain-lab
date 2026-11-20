# G1b construction coverage

Scope: broker `9f1f90faadb6f51b3c4767c8276a4c3b5e0d1066`,
`docs/lab-profile-v0.md` §5.1 G1b and its assigned acceptance rows;
`contracts/lab-v0/attempt-accounting.md` (C0e) and `bounded-invocation.md`
(C0b). This is local tagged construction evidence, not native Q acceptance.
Exact candidate, commands, exits, mutation results and limits are in the delivery
handoff. Test comments state their individual claims; parser catalogue tests
supplement the composed tests and are never counted as a forwarding proof.

## Acceptance allocation

| Row | Composed controls and forbidden outcomes | Narrowing mutants / catalogue |
| --- | --- | --- |
| A01 | `TestLabBuildTagIsolation`, default/tagged module builds, `TestLabAttemptRunAdmission`, `TestLabAttemptRunReplay` | retained `untag-source`, `untag-contract`, `open-object`; new `closed-field-set`, `ccj-canonical`, `ccj-duplicate` |
| A02 | `TestLabAttemptWireThroughHTTP` exercises every frozen wire case through the bounded public gateway; retained `TestLabServeHTTPWireCatalogue`, `TestLabAPIKeyForwarding`, `TestLabSSEThroughHTTP`, `TestLabLeakSurfacesThroughHTTP` retain admission/response behavior | `forward-unwired`; retained wire, body, canonical-beta, scan, response and error/SSE plants |
| A03 | `TestLabAttemptSourceBindingThroughHTTP`, `TestLabAttemptRunAdmission`, retained `TestLabRunAdmission` and `TestLabLeaseBindingsThroughHTTP` | `source-join`, `native-*`, retained UID-truncation/caller/peer/lease binding plants |
| A05 | `TestLabAttemptReservationThroughHTTP`, `TestLabAttemptPersistenceErrorsThroughHTTP`, `TestLabAttemptCASThroughHTTP`, `TestLabAttemptRunCrash`, `TestLabAttemptRunDurability`, `TestLabAttemptRunReplay`, `TestLabAttemptRunStatus`, `TestLabAttemptRunStatusBoot`, `TestLabAttemptRunStatusStore` | reservation/charge, history/prefix, missing-head/CAS, fsync/close, crash/UNKNOWN-replay and exact status plants |
| A06 | `TestLabAttemptRunAdmission` independently reseals approval/release/access/launch negatives; `TestLabAttemptRunCurrent` changes protected proof inputs idle and in flight | `approved-*`, `plan-*`, `approval-*`, `release-*`, `access-*`, `current-proof-scan` |
| A07 | `TestLabAttemptRunDeadlines`, `TestLabAttemptRunStalledFsync`, `TestLabAttemptRunIdleBound`, retained `TestLabRenewalThroughHTTP` and lease deadline tests | `per-deadline`, `per-deadline-stalled-sync`, `group-deadline-startup-sync`, `group-preauth-clock`, retained renewal/watchdog plants |
| A09 | Real `run()` listener plus live/idle/partial downstream sockets and upstream cancellation in deadline, current-proof, unknown and crash tests; retained `TestLabRunAuthorityTeardown` and `TestLabRunHoldBinding` | new deadline/current/UNKNOWN plants plus retained listener/broker/hold/watchdog plants |
| A10 | `TestLabAttemptBoundsThroughHTTP`, `TestLabAttemptNoQueueThroughHTTP`, `TestLabAttemptRunBounds`, `TestLabAttemptUnknownThroughHTTP`, `TestLabAttemptRunUnknown`, `TestLabAttemptNonReplayableThroughHTTP`, `TestLabAttemptTransportThroughHTTP`, crash/replay tests | `forward-unwired`, `count-bound`, `cost-bound`, `no-queue`, `sticky-charge`, `unknown-replay`, transport/no-replay plants |
| A11 | `TestLabAttemptRunAdmission` joins exact client/wire/index/price/executor/release and second-build assertions, alongside unchanged default binary/module graph checks | `profile-pin`, `wire-pin`, `price-pin`, `release-index`, `price-*`, `executor-member`, `second-*` |
| A12 | `TestLabAttemptRunAdmission` requires protected human-only endpoint/guest/vendor access and cap assertions; retained whole-marker request/response/hold tests remain green | `approved-access`, `access-*`, `cap-*`, retained whole-marker/header/hold plants |

## Mutation semantics

`service/scripts/check-lab-attempt-plants.py` applies each exact source overlay to
an unchanged candidate and runs the named composed test. Only exit 1 with the
named test's failure (not a compilation failure, panic, skipped plant or setup
error) counts as a kill. `results.json` preserves the exact command, process,
exit and log. Every listed plant must be killed for delivery; earlier diagnostic
survivors/build failures are not silently converted into kills.

A class plant disables all known redundant guards where a single-line removal
would not express the forbidden behavior: missing-head removes reload plus
pre/post-write CAS, count removes allocation/settlement/replay checks, no-queue
removes the atomic admission token and active/prior-reservation guards, per-deadline removes context and kernel
wall selections, preauthorization time removes both startup checks and redundant
immediate retirement, directory-alias plants remove both no-link and same-inode checks,
canonical duplicates remove the duplicate and byte-canonical
checks, terminal usage removes EOF and settlement guards, and transport reuse
removes both connection-close settings. These are explicit bounded class claims,
not a claim that every equivalent line removal must fail. Mutation testing is
not exhaustive fault-model or platform qualification.

The tables below name every delivery plant and its composed failing test. The
rightmost column states precisely what the planted implementation narrows or
removes. A survivor is uncovered and blocks the local review handoff.

## G1b gates

| Gate / mutant | Composed failing test | Narrowing claim |
| --- | --- | --- |
| `forward-unwired` | `TestLabAttemptReservationThroughHTTP` | a real Messages forward must create a durable reservation |
| `source-join` | `TestLabAttemptSourceBindingThroughHTTP` | another live source cannot borrow this gate |
| `closed-field-set` | `TestLabAttemptRunAdmission/plan-extra` | closed plan fields remain closed in run |
| `count-range` | `TestLabAttemptRunAdmission/plan-count-over` | C0b invocation count is at most 256 |
| `usd-scale` | `TestLabAttemptRunAdmission/plan-usd-fraction` | USD is exactly six fractional digits |
| `usage-partition` | `TestLabAttemptUnknownThroughHTTP/cache-sum` | cache partitions must equal the authoritative creation total |
| `price-round-up` | `TestLabAttemptUnknownThroughHTTP/round-up` | disjoint exact products round upward once |
| `rate-input_usd_per_million` | `TestLabAttemptReservationThroughHTTP` | each disjoint pinned rate contributes to settlement |
| `rate-output_usd_per_million` | `TestLabAttemptReservationThroughHTTP` | each disjoint pinned rate contributes to settlement |
| `rate-cache_write_5m_usd_per_million` | `TestLabAttemptReservationThroughHTTP` | each disjoint pinned rate contributes to settlement |
| `rate-cache_write_1h_usd_per_million` | `TestLabAttemptReservationThroughHTTP` | each disjoint pinned rate contributes to settlement |
| `rate-cache_read_usd_per_million` | `TestLabAttemptReservationThroughHTTP` | each disjoint pinned rate contributes to settlement |
| `worst-context` | `TestLabAttemptReservationThroughHTTP` | reservation covers the full published million-token context |
| `worst-category` | `TestLabAttemptReservationThroughHTTP` | the largest input/cache rate governs worst-case reservation |
| `approved-plan` | `TestLabAttemptRunAdmission/unapproved-plan` | expected approval pins are protected external authority inputs |
| `approved-release` | `TestLabAttemptRunAdmission/unapproved-release` | expected approval pins are protected external authority inputs |
| `approved-access` | `TestLabAttemptRunAdmission/unapproved-access` | expected approval pins are protected external authority inputs |
| `profile-pin` | `TestLabAttemptRunAdmission/client-profile` | the approved client profile is the frozen one |
| `wire-pin` | `TestLabAttemptRunAdmission/wire-profile` | the approved wire profile is the frozen one |
| `price-pin` | `TestLabAttemptRunAdmission/pinned-price` | a release cannot substitute cheaper unapproved price bytes |
| `release-index` | `TestLabAttemptRunAdmission/release-index` | C0e contract revision is pinned |
| `plan-live_budget_approved` | `TestLabAttemptRunAdmission/unapproved-budget` | approved bounded model/output/live-budget profile is mandatory |
| `plan-model` | `TestLabAttemptRunAdmission/model-profile` | approved bounded model/output/live-budget profile is mandatory |
| `plan-max_output_tokens_per_invocation` | `TestLabAttemptRunAdmission/output-profile` | approved bounded model/output/live-budget profile is mandatory |
| `wall-order` | `TestLabAttemptRunAdmission/wall-order` | per-attempt wall allocation cannot exceed the group allocation |
| `plan-approval` | `TestLabAttemptRunAdmission/plan-approval-chain` | C0b digest chain is joined after resealing the mutated subject |
| `approval-release` | `TestLabAttemptRunAdmission/approval-release-chain` | C0b digest chain is joined after resealing the mutated subject |
| `approval-target` | `TestLabAttemptRunAdmission/approval-invocation-chain` | C0b digest chain is joined after resealing the mutated subject |
| `release-target` | `TestLabAttemptRunAdmission/release-invocation-chain` | C0b digest chain is joined after resealing the mutated subject |
| `launch-operation` | `TestLabAttemptRunAdmission/launch-operation` | launch operation, generation, heads and complete input digests join exactly |
| `launch-generation` | `TestLabAttemptRunAdmission/launch-generation` | launch operation, generation, heads and complete input digests join exactly |
| `launch-heads` | `TestLabAttemptRunAdmission/launch-heads` | launch operation, generation, heads and complete input digests join exactly |
| `launch-target` | `TestLabAttemptRunAdmission/launch-target-pin` | launch operation, generation, heads and complete input digests join exactly |
| `launch-approval` | `TestLabAttemptRunAdmission/launch-approval-pin` | launch operation, generation, heads and complete input digests join exactly |
| `launch-release` | `TestLabAttemptRunAdmission/launch-release-pin` | launch operation, generation, heads and complete input digests join exactly |
| `launch-access` | `TestLabAttemptRunAdmission/launch-access-pin` | launch operation, generation, heads and complete input digests join exactly |
| `input-unique` | `TestLabAttemptRunAdmission/launch-input-duplicate` | duplicate input-pin names refuse |
| `input-digest` | `TestLabAttemptRunAdmission/launch-input-digest` | all four bounded launch inputs are pinned |
| `second-build` | `TestLabAttemptRunAdmission/second-build` | every included asset has a reproducible second build |
| `second-digest` | `TestLabAttemptRunAdmission/second-build-digest` | second-build hashes agree |
| `executor-member` | `TestLabAttemptRunAdmission/executor-release` | the bounded executor digest identifies exactly one approved manager asset |
| `price-member-count` | `TestLabAttemptRunAdmission/price-member-missing` | exactly one approved price archive member is required |
| `price-product` | `TestLabAttemptRunAdmission/price-member-product` | the gateway price member has the exact path, mode and digest |
| `price-mode` | `TestLabAttemptRunAdmission/price-member-mode` | the gateway price member has the exact path, mode and digest |
| `price-digest` | `TestLabAttemptRunAdmission/price-member-digest` | the gateway price member has the exact path, mode and digest |
| `approval-seal` | `TestLabAttemptRunAdmission/(approval-seal|release-seal)$` | embedded approvals bind their exact canonical targets |
| `approval-expiry` | `TestLabAttemptRunAdmission/(release-expired|approval-expired)$` | both approvals must be currently unexpired |
| `approval-order` | `TestLabAttemptRunAdmission/(approval-after-off|release-after-off)$` | off-VM receipt cannot precede approval |
| `off-vm-future` | `TestLabAttemptRunAdmission/off-vm-future` | future off-VM authority refuses |
| `access-seal` | `TestLabAttemptRunAdmission/access-seal` | access attestation is separately owner sealed |
| `access-endpoint` | `TestLabAttemptRunAdmission/access-endpoint` | every endpoint exclusion must be true |
| `access-human` | `TestLabAttemptRunAdmission/(access-principal|access-vendor-principal)$` | every privileged controller is human |
| `access-roster` | `TestLabAttemptRunAdmission/access-vendor` | changed vendor roster closes admission |
| `access-audit` | `TestLabAttemptRunAdmission/access-vendor-audit` | partial vendor audit closes admission |
| `cap-remaining` | `TestLabAttemptRunAdmission/available-cap` | the available vendor cap covers the owner-approved group |
| `cap-hard` | `TestLabAttemptRunAdmission/cap-over-hard` | available-cap readback cannot exceed the attested hard cap |
| `manager-commit` | `TestLabAttemptRunAdmission/manager-uncommitted` | the manager join is committed, never UNKNOWN |
| `native-accepted` | `TestLabAttemptRunAdmission/missing-native-acceptance` | B1 accepted-pair digest, not an arbitrary response, enables the listener |
| `native-admitted` | `TestLabAttemptRunAdmission/native-phase` | only admitted native starts enable forwarding |
| `native-complete` | `TestLabAttemptRunAdmission/native-incomplete` | partial native evidence is closed |
| `native-current` | `TestLabAttemptRunAdmission/native-generation-current` | native store generation remains current |
| `native-generation` | `TestLabAttemptRunAdmission/native-generation` | native start targets the approved generation |
| `native-boot` | `TestLabAttemptRunAdmission/native-boot` | native evidence and group share the current boot |
| `native-execution` | `TestLabAttemptRunAdmission/native-debit-execution` | both native debit and receipt name the accepted execution |
| `native-epoch` | `TestLabAttemptRunAdmission/(native-receipt-epoch|native-debit-epoch)$` | both native accounting artifacts share the start epoch |
| `native-process` | `TestLabAttemptRunAdmission/(native-pid|native-start-time)$` | receipt and debit identify the same native process instance |
| `native-store` | `TestLabAttemptRunAdmission/native-debit` | native debit belongs to the installed store generation |
| `native-time` | `TestLabAttemptRunAdmission/native-debit-time-future` | debit commit cannot be observed in the future |
| `head-missing` | `TestLabAttemptBoundsThroughHTTP/missing-head` | the missing-head class disables reload and both redundant CAS comparisons; cached state cannot recreate lost authoritative history |
| `no-queue` | `TestLabAttemptBoundsThroughHTTP/concurrent` | one group has one active billable attempt, no queue |
| `count-bound` | `TestLabAttemptBoundsThroughHTTP/count` | no new ordinal past count bound |
| `cost-bound` | `TestLabAttemptBoundsThroughHTTP/cost` | worst-case reservation must fit remaining approved USD |
| `clock-regression` | `TestLabAttemptBoundsThroughHTTP/clock-regression` | backward monotonic observation closes UNKNOWN |
| `sticky-charge` | `TestLabAttemptRunUnknown` | uncertain outcomes retain the full allocation |
| `crash-reservation` | `TestLabAttemptRunCrash` | a crash consumes the reserved ordinal and full allocation |
| `history-chain` | `TestLabAttemptRunReplay/previous` | snapshot predecessors form the exact append-only digest chain |
| `history-sequence` | `TestLabAttemptRunReplay/sequence` | snapshot sequence increments exactly once |
| `history-immutable` | `TestLabAttemptRunReplay/release-join` | all C0b/native/B4 admission joins stay immutable |
| `history-ordinal` | `TestLabAttemptRunReplay/ordinal` | attempt ordinals are contiguous and never reused |
| `history-reservation` | `TestLabAttemptRunReplay/reservation-cost` | recovered reservations retain the full pinned worst case |
| `history-charge` | `TestLabAttemptRunReplay/settled-cost` | recovered settlement equals authoritative exact price |
| `history-usage-digest` | `TestLabAttemptRunReplay/usage-digest` | recovered usage is fully digest bound |
| `history-reserve-prefix` | `TestLabAttemptRunReplay/prefix` | settlement cannot retarget its reserved ordinal/start/allocation |
| `fsync-file` | `TestLabAttemptRunDurability` | pre-forward immutable snapshot and head bytes are fsynced |
| `fsync-directory` | `TestLabAttemptRunDurability` | directory barriers bracket head publication before forward |
| `fsync-error` | `TestLabAttemptPersistenceErrorsThroughHTTP/file-sync` | uncertain file persistence prevents a forward |
| `close-error` | `TestLabAttemptPersistenceErrorsThroughHTTP/file-close` | uncertain close prevents a forward |
| `usage-stop` | `TestLabAttemptUnknownThroughHTTP/partial` | settlement requires terminal message_stop |
| `usage-cumulative` | `TestLabAttemptReservationThroughHTTP` | message_delta output is cumulative, not additive |
| `usage-regression` | `TestLabAttemptUnknownThroughHTTP/regression` | cumulative counters cannot regress |
| `usage-model` | `TestLabAttemptUnknownThroughHTTP/model` | the billed model is the approved one |
| `usage-tier` | `TestLabAttemptUnknownThroughHTTP/tier` | the billed tier is the pinned standard tier |
| `transport-http1` | `TestLabAttemptTransportThroughHTTP` | below-gate HTTP2 retry mechanisms remain disabled |
| `nonreplayable-body` | `TestLabAttemptNonReplayableThroughHTTP` | net/http cannot silently replay a reserved request body |
| `transport-close` | `TestLabAttemptTransportThroughHTTP` | each attempt uses a nonreused HTTP1 connection |
| `post-write-cas` | `TestLabAttemptCASThroughHTTP/changed-head` | head is compared again after pre-forward durable writes and before publication |
| `current-proof-scan` | `TestLabAttemptRunCurrent` | access/approval inputs remain byte-current while idle and in flight |
| `per-deadline` | `TestLabAttemptRunDeadlines/per-attempt` | the per-attempt deadline independently cancels upstream |
| `group-preauth-clock` | `TestLabAttemptRunPreauthorization/stale-group` | the preauthorization clock class disables both admission checks and redundant immediate retirement; a stale G must never open a listener |
| `accounting-link` | `TestLabAttemptRunPreauthorization/accounting-link` | a symlink cannot replace the protected accounting directory |
| `root-mode` | `TestLabAttemptRunPreauthorization/root-mode` | accounting inputs reside in the private service-owned root |
| `input-mode` | `TestLabAttemptRunPreauthorization/record-mode` | protected inputs have the exact immutable file mode |
| `input-link` | `TestLabAttemptRunPreauthorization/record-link` | a protected input cannot have a hardlink alias |
| `native-pid-ceiling` | `TestLabAttemptRunAdmission/native-pid-overflow` | native PID representation is bounded independently of matching receipt/debit fields |
| `unknown-replay` | `TestLabAttemptRunCrash` | an unknown group cannot be downgraded or transitioned on a repeated start |
| `status-unknown-exit` | `TestLabAttemptRunStatus/unknown/control` | read-only reconciliation retains the UNKNOWN exit rather than claiming clean exhaustion |
| `directory-sync-error` | `TestLabAttemptPersistenceErrorsThroughHTTP/directory-sync` | directory fsync errors propagate before any forward |
| `ccj-canonical` | `TestLabAttemptRunReplay/noncanonical` | the composed reload rejects noncanonical snapshot bytes before joins |
| `ccj-duplicate` | `TestLabAttemptRunReplay/duplicate` | duplicate member plus redundant canonicality bypass cannot silently overwrite ledger members |
| `status-actual-boot` | `TestLabAttemptRunStatusBoot` | read-only status binds the actual kernel boot even when all stored joins have been re-sealed |
| `per-deadline-stalled-sync` | `TestLabAttemptRunStalledFsync/per-attempt` | per-attempt teardown cannot wait for ledger fsync or the gate mutex |
| `group-deadline-startup-sync` | `TestLabAttemptRunStalledFsync/startup` | the preauthorization group deadline retires broker authority even while startup fsync is blocked |

| `native-caller-execution` | `TestLabAttemptRunAdmission/native-caller-execution` | the managed caller execution is the exact native start, not merely the same UID and generation |

| `status-accounting-link` | `TestLabAttemptRunStatusStore/link` | read-only status rejects a linked store even when every stored digest is unchanged |
| `status-accounting-mode` | `TestLabAttemptRunStatusStore/mode` | read-only status requires the protected directory mode, not only protected file bytes |

| `allocation-no-queue` | `TestLabAttemptNoQueueThroughHTTP` | a request cannot wait behind an in-progress reservation and later enter the group |

## Retained G1 gates

All previously committed test function names remain present. The bounded public
constructor is used by the shipped command; the private intake fixture retains
the pre-accounting G1 test scope without providing a command/runtime bypass.

| Row / mutant | Composed failing test | Narrowing claim |
| --- | --- | --- |
| A02 / `duplicate-json-member` | `TestLabBodyOperatorsThroughHTTP` | duplicate body fields cannot overwrite earlier values |
| A02 / `cache-placement-pinned` | `TestLabBodyOperatorsThroughHTTP` | the cache profile is a multiset, not a placement claim |
| A02 / `header-case-control` | `TestLabServeHTTPWireCatalogue` | ASCII header case controls must remain admitted |
| A02 / `body-number-rounding` | `TestLabBodyOperatorsThroughHTTP` | fixed output bounds cannot use lossy rounding |
| A08 / `no-cross-read-retention` | `TestLabLeakSurfacesThroughHTTP` | a split whole needle must not escape |
| A02 / `sse-buffer-until-eof` | `TestLabSSEThroughHTTP` | safe complete SSE events flush before EOF |
| A09 / `no-body-idle-timeout` | `TestLabReadStall` | stalled bodies retain the independent idle budget |
| A01 / `untag-source` | `TestLabBuildTagIsolation` | lab source must be excluded from default builds |
| A01 / `open-object` | `TestLabLeaseBindingsThroughHTTP` | extra nested fields must refuse |
| A01 / `noncanonical-record` | `TestLabLeaseBindingsThroughHTTP` | CCJ framing is byte exact |
| A02 / `payload-overflow` | `TestLabPayloadThroughHTTP` | the real handler refuses the next byte at its intake ceiling |
| A02 / `missing-beta` | `TestLabServeHTTPWireCatalogue` | all eleven flags are required |
| A02 / `duplicate-beta-field` | `TestLabServeHTTPWireCatalogue` | two beta header fields refuse |
| A02 / `oauth-scheme` | `TestLabAPIKeyForwarding` | OAuth is not an API-key source |
| A02 / `extra-body-field` | `TestLabServeHTTPWireCatalogue` | unobserved body aliases cannot be admitted |
| A02 / `policy-key-injection` | `TestLabAPIKeyForwarding` | policy GET must stay credential free |
| A03 / `uid-truncation` | `TestLabRunAdmission` | the UID-truncation class disables both source range and native caller binding, not only one redundant rejection |
| A09 / `null-current-sequence` | `TestLabSequenceThroughHTTP` | a nullable decoded sequence cannot refresh authority |
| A03 / `caller-retarget` | `TestLabLeaseBindingsThroughHTTP` | a lease cannot retarget the protected caller |
| A03 / `wrong-peer` | `TestLabKernelCallerRefusal` | a kernel UID mismatch cannot lease |
| A07 / `selector-mismatch` | `TestLabRunAdmission` | a lower independent ceiling is still a mismatch |
| A07 / `ignore-caller-deadline` | `TestLabLeaseBindingsThroughHTTP` | earliest caller bound remains exclusive |
| A07 / `renew-ended` | `TestLabRenewalThroughHTTP` | ended handles cannot be renewed back into life |
| A07 / `half-second-renewal` | `TestLabRenewalThroughHTTP` | long leases must not churn every half-second |
| A08 / `new-hold-operation` | `TestLabRunHoldBinding` | lost acknowledgments reconcile the same ID |
| A08 / `unknown-hold-success` | `TestLabRunHoldBinding` | UNKNOWN is never a committed hold |
| A08 / `local-only-response` | `TestLabLeakSurfacesThroughHTTP` | response matches must enter the hold bridge |
| A09 / `one-second-watchdog` | `TestLabAuthorityCancellationThroughHTTP` | the watchdog cannot share a one-second budget |
| A09 / `no-listener-teardown` | `TestLabRunAuthorityTeardown` | authority loss retires the listener and streams |
| A09 / `broker-left-open` | `TestLabRunAuthorityTeardown` | the stale broker connection closes too |
| A01 / `untag-contract` | `TestLabBuildTagIsolation` | untagged GoFiles and embeds exclude every lab implementation |
| A02 / `shape-unwired` | `TestLabServeHTTPWireCatalogue` | the composed handler applies closed wire shape |
| A02 / `post-body-unwired` | `TestLabServeHTTPWireCatalogue` | the composed handler applies the frozen coupled body |
| A02 / `get-body-unwired` | `TestLabServeHTTPResponseGates` | policy GET has no worker body |
| A02 / `canonical-beta-unwired` | `TestLabBetaCanonicalThroughHTTP` | the admitted profile emits the exact eleven-flag header |
| A02 / `encoded-response-unwired` | `TestLabServeHTTPResponseGates` | encoded upstream bodies are not passed through |
| A08 / `post-load-scan-unwired` | `TestLabPostLoadHoldThroughHTTP` | first-use inventory is rescanned before injection |
| A08 / `inbound-scan-unwired` | `TestLabLeakSurfacesThroughHTTP` | known material in every inbound surface enters the hold |
| A08 / `response-header-scan-unwired` | `TestLabLeakSurfacesThroughHTTP` | response headers are scanned before copying |
| A07 / `lease-ignore-activation` | `TestLabLeaseBindingsThroughHTTP` | lease binds the exact activation record |
| A07 / `lease-ignore-authority` | `TestLabLeaseBindingsThroughHTTP` | lease binds the exact authority record |
| A07 / `lease-ignore-fence` | `TestLabLeaseBindingsThroughHTTP` | lease binds the exact fence record |
| A07 / `lease-ignore-context` | `TestLabLeaseBindingsThroughHTTP` | issued material cannot retarget context |
| A07 / `lease-ignore-gateway` | `TestLabLeaseBindingsThroughHTTP` | issued material cannot retarget gateway |
| A07 / `lease-ignore-caller` | `TestLabLeaseBindingsThroughHTTP` | issued material cannot retarget caller |
| A07 / `lease-ignore-manager_floor` | `TestLabLeaseBindingsThroughHTTP` | issued material cannot retarget manager_floor |
| A07 / `lease-ignore-request-id` | `TestLabLeaseBindingsThroughHTTP` | lease belongs to this request operation |
| A07 / `lease-ignore-renewed-id` | `TestLabSequenceThroughHTTP` | renewal belongs to the same lease |
| A07 / `lease-future-issue` | `TestLabLeaseBindingsThroughHTTP` | future-issued material cannot install |
| A07 / `lease-ignore-pinned-deadline` | `TestLabLeaseBindingsThroughHTTP` | lease cannot exceed pinned per-use expiry |
| A07 / `lease-ignore-lifetime` | `TestLabLeaseBindingsThroughHTTP` | selected lifetime must equal activation ceiling |
| A07 / `lease-ignore-expired` | `TestLabLeaseBindingsThroughHTTP` | expired material cannot install |
| A07 / `lease-ignore-interval` | `TestLabLeaseBindingsThroughHTTP` | authorized interval stays within selected lifetime |
| A07 / `lease-ignore-authority_until` | `TestLabLeaseBindingsThroughHTTP` | lease respects earliest authority_until |
| A07 / `lease-ignore-qualification_until` | `TestLabLeaseBindingsThroughHTTP` | lease respects earliest qualification_until |
| A07 / `lease-ignore-time_until` | `TestLabLeaseBindingsThroughHTTP` | lease respects earliest time_until |
| A07 / `revocation-regress` | `TestLabSequenceThroughHTTP` | renewed lease cannot regress observed revocation sequence |
| A09 / `check-sequence-regress` | `TestLabSequenceThroughHTTP` | current check cannot regress observed sequence |
| A07 / `call-version-unbound` | `TestLabVersionRaceThroughHTTP` | in-flight use never acquires a newer deadline |
| A09 / `call-source-unbound` | `TestLabAuthorityCancellationThroughHTTP` | source retirement cancels actual upstream call context |
| A08 / `startup-floor-hold-ignored` | `TestLabRunStartupFloor` | active floor hold prevents command startup |
| A08 / `hold-any-operation` | `TestLabRunHoldBinding` | committed hold must bind operation |
| A08 / `hold-any-digest` | `TestLabRunHoldBinding` | committed hold must bind digest |
| A08 / `hold-any-context` | `TestLabRunHoldBinding` | committed hold must bind context |
| A08 / `hold-any-caller` | `TestLabRunHoldBinding` | committed hold must bind caller |
| A09 / `main-ignore-ended` | `TestLabRunAuthorityTeardown` | the shipped command closes listener and all downstream connections |
| A08 / `main-skip-hold-wait` | `TestLabRunHoldBinding` | UNKNOWN hold keeps the closed command alive |
| A08 / `main-skip-handler-drain` | `TestLabRunLateLeak` | an active read cannot report a hold after command exit |
| A03 / `main-caller-account` | `TestLabRunAdmission` | command mapping must join protected caller account |
| A03 / `main-caller-uid` | `TestLabRunAdmission` | command mapping must join protected caller uid |
| A03 / `main-caller-generation` | `TestLabRunAdmission` | command mapping must join protected caller generation |
| A03 / `main-caller-launch` | `TestLabRunAdmission` | command mapping must join protected caller launch |
| A01 / `untag-intake` | `TestLabBuildTagIsolation` | untagged graph excludes lab intake |
| A01 / `untag-command` | `TestLabBuildTagIsolation` | untagged graph excludes lab command |
| A01 / `untag-testkit` | `TestLabBuildTagIsolation` | untagged graph excludes lab testkit |
| A02 / `canonical-beta-deleted` | `TestLabBetaCanonicalThroughHTTP` | canonical beta must exist exactly once |
| A08 / `inbound-header-first-value` | `TestLabMultiValueHeadersThroughHTTP` | every inbound value is scanned before shape rejection |
| A08 / `response-header-first-value` | `TestLabMultiValueHeadersThroughHTTP` | every value of a forwarded response header is scanned |
| A08 / `inbound-header-delimited-values` | `TestLabMultiValueHeadersThroughHTTP` | split inbound material matches across value boundaries without a separator |
| A08 / `response-header-delimited-values` | `TestLabMultiValueHeadersThroughHTTP` | split response material cannot escape through separate values |
| A08 / `early-body-scan-unwired` | `TestLabEarlyBodyScanThroughHTTP` | known material is held before reservation rather than only at the post-load scan |
| A09 / `intake-authority-unbound` | `TestLabAuthorityCancellationThroughHTTP` | gateway closure independently cancels an in-flight request while source authority is live |
| A09 / `cold-check-rpc-timeout-off` | `TestLabColdCheckTimeoutThroughHTTP` | the initial check is bounded before watchdog initialization |
| A09 / `main-retired-dispatch-reopened` | `TestLabRunRetiredDispatch` | drained dispatch cannot forward to a still-live gateway |
| A09 / `main-second-close-unwired` | `TestLabRunAuthorityTeardown` | listener failure must close active connections before waiting for handlers |
| A07 / `pinned-deadline-class-unwired` | `TestLabLeaseBindingsThroughHTTP` | the composed pinned-deadline class cannot rely on redundant neighbouring checks |
| A07 / `value-pinned-deadline-unwired` | `TestLabPinnedDeadlineThroughHTTP` | cold expired authority cannot even request a lease |
| A07 / `check-pinned-deadline-unwired` | `TestLabPinnedDeadlineThroughHTTP` | pinned expiry retires authority without acquiring the lease mutex |
| A01 / `production-idle-absolute-count` | `TestManagedSourceRecovery` | startup reconnects must not be misclassified as idle polling failures |
| A01 / `production-idle-poll-disabled` | `TestManagedSourceRecovery` | broker events must detect absent autonomous idle polling |

## External native gates and out-of-contract portions

No allocated G1b construction row is silently waived. A04 and A08 are not in the
G1b unit's allocation (§5.1); their prior G1 tests/hold behavior are retained, not
new platform claims. The following parts of allocated acceptance rows remain
external, as the §5.1 B1/B2/B3/M1/B5/B4/RG/Q ownership rows and C0e's authority,
accepted-start and B4 sections require:

- A03/A06/A09: real kernel caller/class/placement qualification, accepted C
  opening, native NTS/fence/prefix/currentness and C0d publication-pair evidence
  are B1/B2/B3/M1/B4/Q inputs, not authority minted by this gateway fixture.
- A06/A10/A11: authenticated owner approvals and fresh root cap/access placement
  are B5 responsibilities. Actual executor/client/archive measurement, approved
  second builds, installer/NSS/seccomp/network-FD closure are M1/RG/RM gates.
- A05/A09/A12: B4 must hash the exact protected ledger into accounting
  `QRow.effect_sha256` and join the current native baseline. The local read-only
  status command does not write or repair B4 evidence or a broker store.
- A12: owner-run complete lifecycle/surface scan, real credential needle/version,
  vendor/endpoint visibility and protected live Q evidence are Q/B4 gates. Local
  synthetic controls establish neither live authority nor real vendor access.

These are declared native integration/release limits, not permission to default
missing inputs, claim native acceptance, reopen UNKNOWN or ship to production.
