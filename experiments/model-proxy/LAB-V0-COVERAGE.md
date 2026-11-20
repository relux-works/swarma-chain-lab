# G1 fix-round-2 gate coverage

This map is a test-to-overlay index, not native qualification or a substitute
for the exact-head exit codes in the producer handoff. All overlays are applied
to isolated source copies with `go test -overlay`; originals are never edited.
Compile errors, panics, missing overlays and setup failures do not count as kills.
The runner requires a nonzero exit and the named `--- FAIL: Test...` record.

The HTTP tables exercise `LabGateway.ServeHTTP`, not just its classifiers.
Command tests execute shipped `run()` with the real LabSource, LabGateway,
accounting and Unix HTTP server; only static-file admission collaborators,
the real Unix listener factory for a listener-failure injection,
synthetic worker peer identity and non-network upstream transport are injected.
The broker peer check remains real. Kernel-identity qualification is separate.
Build-tag gates use tagged/untagged GoFiles/EmbedFiles and command selection.

All original C0 operator, parser, native caller and production tests are retained.
C0 parser-size-counter controls are supplemental, not fabricated accepted
at-limit records; the payload overlay here uses the actual HTTP intake ceiling.

| Row | Gate / invariant | Named composed test | Source-overlay mutant |
| --- | --- | --- | --- |
| A02 | duplicate body fields cannot overwrite earlier values | `TestLabBodyOperatorsThroughHTTP` | `duplicate-json-member` |
| A02 | the cache profile is a multiset, not a placement claim | `TestLabBodyOperatorsThroughHTTP` | `cache-placement-pinned` |
| A02 | ASCII header case controls must remain admitted | `TestLabServeHTTPWireCatalogue` | `header-case-control` |
| A02 | fixed output bounds cannot use lossy rounding | `TestLabBodyOperatorsThroughHTTP` | `body-number-rounding` |
| A08 | a split whole needle must not escape | `TestLabLeakSurfacesThroughHTTP` | `no-cross-read-retention` |
| A02 | safe complete SSE events flush before EOF | `TestLabSSEThroughHTTP` | `sse-buffer-until-eof` |
| A09 | stalled bodies retain the independent idle budget | `TestLabReadStall` | `no-body-idle-timeout` |
| A01 | lab source must be excluded from default builds | `TestLabBuildTagIsolation` | `untag-source` |
| A01 | extra nested fields must refuse | `TestLabLeaseBindingsThroughHTTP` | `open-object` |
| A01 | CCJ framing is byte exact | `TestLabLeaseBindingsThroughHTTP` | `noncanonical-record` |
| A02 | the real handler refuses the next byte at its intake ceiling | `TestLabPayloadThroughHTTP` | `payload-overflow` |
| A02 | all eleven flags are required | `TestLabServeHTTPWireCatalogue` | `missing-beta` |
| A02 | two beta header fields refuse | `TestLabServeHTTPWireCatalogue` | `duplicate-beta-field` |
| A02 | OAuth is not an API-key source | `TestLabAPIKeyForwarding` | `oauth-scheme` |
| A02 | unobserved body aliases cannot be admitted | `TestLabServeHTTPWireCatalogue` | `extra-body-field` |
| A02 | policy GET must stay credential free | `TestLabAPIKeyForwarding` | `policy-key-injection` |
| A03 | C0 UIDs cannot truncate into kernel UIDs | `TestLabRunAdmission` | `uid-truncation` |
| A09 | a nullable decoded sequence cannot refresh authority | `TestLabSequenceThroughHTTP` | `null-current-sequence` |
| A03 | a lease cannot retarget the protected caller | `TestLabLeaseBindingsThroughHTTP` | `caller-retarget` |
| A03 | a kernel UID mismatch cannot lease | `TestLabKernelCallerRefusal` | `wrong-peer` |
| A07 | a lower independent ceiling is still a mismatch | `TestLabRunAdmission` | `selector-mismatch` |
| A07 | earliest caller bound remains exclusive | `TestLabLeaseBindingsThroughHTTP` | `ignore-caller-deadline` |
| A07 | ended handles cannot be renewed back into life | `TestLabRenewalThroughHTTP` | `renew-ended` |
| A07 | long leases must not churn every half-second | `TestLabRenewalThroughHTTP` | `half-second-renewal` |
| A08 | lost acknowledgments reconcile the same ID | `TestLabRunHoldBinding` | `new-hold-operation` |
| A08 | UNKNOWN is never a committed hold | `TestLabRunHoldBinding` | `unknown-hold-success` |
| A08 | response matches must enter the hold bridge | `TestLabLeakSurfacesThroughHTTP` | `local-only-response` |
| A09 | the watchdog cannot share a one-second budget | `TestLabAuthorityCancellationThroughHTTP` | `one-second-watchdog` |
| A09 | authority loss retires the listener and streams | `TestLabRunAuthorityTeardown` | `no-listener-teardown` |
| A09 | the stale broker connection closes too | `TestLabRunAuthorityTeardown` | `broker-left-open` |
| A01 | untagged GoFiles and embeds exclude every lab implementation | `TestLabBuildTagIsolation` | `untag-contract` |
| A02 | the composed handler applies closed wire shape | `TestLabServeHTTPWireCatalogue` | `shape-unwired` |
| A02 | the composed handler applies the frozen coupled body | `TestLabServeHTTPWireCatalogue` | `post-body-unwired` |
| A02 | policy GET has no worker body | `TestLabServeHTTPResponseGates` | `get-body-unwired` |
| A02 | the admitted profile emits the exact eleven-flag header | `TestLabBetaCanonicalThroughHTTP` | `canonical-beta-unwired` |
| A02 | encoded upstream bodies are not passed through | `TestLabServeHTTPResponseGates` | `encoded-response-unwired` |
| A08 | first-use inventory is rescanned before injection | `TestLabPostLoadHoldThroughHTTP` | `post-load-scan-unwired` |
| A08 | known material in every inbound surface enters the hold | `TestLabLeakSurfacesThroughHTTP` | `inbound-scan-unwired` |
| A08 | response headers are scanned before copying | `TestLabLeakSurfacesThroughHTTP` | `response-header-scan-unwired` |
| A07 | lease binds the exact activation record | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-activation` |
| A07 | lease binds the exact authority record | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-authority` |
| A07 | lease binds the exact fence record | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-fence` |
| A07 | issued material cannot retarget context | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-context` |
| A07 | issued material cannot retarget gateway | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-gateway` |
| A07 | issued material cannot retarget caller | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-caller` |
| A07 | issued material cannot retarget manager_floor | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-manager_floor` |
| A07 | lease belongs to this request operation | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-request-id` |
| A07 | renewal belongs to the same lease | `TestLabSequenceThroughHTTP` | `lease-ignore-renewed-id` |
| A07 | future-issued material cannot install | `TestLabLeaseBindingsThroughHTTP` | `lease-future-issue` |
| A07 | lease cannot exceed pinned per-use expiry | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-pinned-deadline` |
| A07 | selected lifetime must equal activation ceiling | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-lifetime` |
| A07 | expired material cannot install | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-expired` |
| A07 | authorized interval stays within selected lifetime | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-interval` |
| A07 | lease respects earliest authority_until | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-authority_until` |
| A07 | lease respects earliest qualification_until | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-qualification_until` |
| A07 | lease respects earliest time_until | `TestLabLeaseBindingsThroughHTTP` | `lease-ignore-time_until` |
| A07 | renewed lease cannot regress observed revocation sequence | `TestLabSequenceThroughHTTP` | `revocation-regress` |
| A09 | current check cannot regress observed sequence | `TestLabSequenceThroughHTTP` | `check-sequence-regress` |
| A07 | in-flight use never acquires a newer deadline | `TestLabVersionRaceThroughHTTP` | `call-version-unbound` |
| A09 | source retirement cancels actual upstream call context | `TestLabAuthorityCancellationThroughHTTP` | `call-source-unbound` |
| A08 | active floor hold prevents command startup | `TestLabRunStartupFloor` | `startup-floor-hold-ignored` |
| A08 | committed hold must bind operation | `TestLabRunHoldBinding` | `hold-any-operation` |
| A08 | committed hold must bind digest | `TestLabRunHoldBinding` | `hold-any-digest` |
| A08 | committed hold must bind context | `TestLabRunHoldBinding` | `hold-any-context` |
| A08 | committed hold must bind caller | `TestLabRunHoldBinding` | `hold-any-caller` |
| A09 | the shipped command closes listener and all downstream connections | `TestLabRunAuthorityTeardown` | `main-ignore-ended` |
| A08 | UNKNOWN hold keeps the closed command alive | `TestLabRunHoldBinding` | `main-skip-hold-wait` |
| A08 | an active read cannot report a hold after command exit | `TestLabRunLateLeak` | `main-skip-handler-drain` |
| A09 | RPC time cannot extend the 500-ms observation budget | `TestLabWatchdogAgeThroughHTTP` | `watchdog-forgets-rpc-age` |
| A03 | command mapping must join protected caller account | `TestLabRunAdmission` | `main-caller-account` |
| A03 | command mapping must join protected caller uid | `TestLabRunAdmission` | `main-caller-uid` |
| A03 | command mapping must join protected caller generation | `TestLabRunAdmission` | `main-caller-generation` |
| A03 | command mapping must join protected caller launch | `TestLabRunAdmission` | `main-caller-launch` |
| A01 | untagged graph excludes lab intake | `TestLabBuildTagIsolation` | `untag-intake` |
| A01 | untagged graph excludes lab command | `TestLabBuildTagIsolation` | `untag-command` |
| A01 | untagged graph excludes lab testkit | `TestLabBuildTagIsolation` | `untag-testkit` |
| A02 | canonical beta must exist exactly once | `TestLabBetaCanonicalThroughHTTP` | `canonical-beta-deleted` |
| A08 | every inbound value is scanned before shape rejection | `TestLabMultiValueHeadersThroughHTTP` | `inbound-header-first-value` |
| A08 | every value of a forwarded response header is scanned | `TestLabMultiValueHeadersThroughHTTP` | `response-header-first-value` |
| A08 | split inbound material matches across value boundaries without a separator | `TestLabMultiValueHeadersThroughHTTP` | `inbound-header-delimited-values` |
| A08 | split response material cannot escape through separate values | `TestLabMultiValueHeadersThroughHTTP` | `response-header-delimited-values` |
| A08 | known material is held before reservation rather than only at the post-load scan | `TestLabEarlyBodyScanThroughHTTP` | `early-body-scan-unwired` |
| A09 | gateway closure independently cancels an in-flight request while source authority is live | `TestLabAuthorityCancellationThroughHTTP` | `intake-authority-unbound` |
| A09 | the initial check is bounded before watchdog initialization | `TestLabColdCheckTimeoutThroughHTTP` | `cold-check-rpc-timeout-off` |
| A09 | drained dispatch cannot forward to a still-live gateway | `TestLabRunRetiredDispatch` | `main-retired-dispatch-reopened` |
| A09 | listener failure must close active connections before waiting for handlers | `TestLabRunAuthorityTeardown` | `main-second-close-unwired` |
| A07 | the composed pinned-deadline class cannot rely on redundant neighbouring checks | `TestLabLeaseBindingsThroughHTTP` | `pinned-deadline-class-unwired` |
| A07 | cold expired authority cannot even request a lease | `TestLabPinnedDeadlineThroughHTTP` | `value-pinned-deadline-unwired` |
| A07 | pinned expiry retires authority without acquiring the lease mutex | `TestLabPinnedDeadlineThroughHTTP` | `check-pinned-deadline-unwired` |
| A01 | startup reconnects must not be misclassified as idle polling failures | `TestManagedSourceRecovery` | `production-idle-absolute-count` |
| A01 | broker events must detect absent autonomous idle polling | `TestManagedSourceRecovery` | `production-idle-poll-disabled` |

Total: 91 distinct overlays. Exact replacement literals and invocation
are in `service/scripts/check-lab-plants.py`; `--filter` selects bounded reruns.

## Review classes

| Review | Composed regression witnesses |
| --- | --- |
| B1 / F2 | TestLabRunAuthorityTeardown; TestLabAuthorityCancellationThroughHTTP; TestLabRunHoldBinding |
| B2 / F3 | TestLabRunHoldBinding; TestLabPostLoadHoldThroughHTTP |
| B3 | TestLabLeaseBindingsThroughHTTP |
| B4 | TestLabSequenceThroughHTTP |
| B5 | TestLabRunStartupFloor |
| B6 / F1 | TestLabPostLoadHoldThroughHTTP; TestLabServeHTTPWireCatalogue; TestLabServeHTTPResponseGates |
| F4 | TestLabVersionRaceThroughHTTP |
| F5 | TestLabBuildTagIsolation |
| Late-read hold race | TestLabRunLateLeak |
| Conservative observation age | TestLabWatchdogAgeThroughHTTP |

## Round-2 delta verdict closure

| Reviewer survivor | Composed witness | Narrowing overlay |
| --- | --- | --- |
| Canonical beta Set-line deletion (repeat F1) | TestLabBetaCanonicalThroughHTTP: canonical, reversed, SP, HTAB, mixed | canonical-beta-unwired (actual line deletion); canonical-beta-deleted (separate missing-field control) |
| Inbound/response first-value scans | TestLabMultiValueHeadersThroughHTTP: second, split, empty-first/middle; clean controls | inbound-header-first-value; response-header-first-value |
| Values joined with a delimiter | Same: split needle over allowlisted response Request-Id and inbound diagnostic | inbound-header-delimited-values; response-header-delimited-values |
| Retired request dispatcher reopened | TestLabRunRetiredDispatch: Unix HTTP, real still-live source/gateway, 200 before drain / 503 after | main-retired-dispatch-reopened |
| Intake authority unbound | TestLabAuthorityCancellationThroughHTTP/gateway-closed: source stays live | intake-authority-unbound |
| Early inbound body scan removed | TestLabEarlyBodyScanThroughHTTP: no reservation on known material (post-load scan is too late) | early-body-scan-unwired |
| RPC timeout removed | TestLabColdCheckTimeoutThroughHTTP: first check, no watchdog initialized | cold-check-rpc-timeout-off |
| CredentialValue pinned deadline removed | TestLabPinnedDeadlineThroughHTTP/cold-expired: zero lease RPCs | value-pinned-deadline-unwired |
| check pinned deadline removed | TestLabPinnedDeadlineThroughHTTP/issued-lock: retire at first poll without waiting on blocked lease mutex; watchdog too late | check-pinned-deadline-unwired |
| Second server.Close removed | TestLabRunAuthorityTeardown/listener-failure: actual listener closes while source remains live | main-second-close-unwired |
| Command timer-only overlay surviving in command package | Existing TestLabAuthorityCancellationThroughHTTP/watchdog and TestLabWatchdogAgeThroughHTTP use the real source; command stalled-poll subtest renamed accurately | Existing watchdog timer and RPC-age overlays, killed through HTTP |
| Original production absolute connection count / missing idle polling | TestManagedSourceRecovery/idle-aged and idle: real managedSource, broker events across idle horizon | production-idle-absolute-count; production-idle-poll-disabled |

The combined pinned-deadline-class overlay additionally removes all three
neighbouring lease/value/check bounds together; it is not substituted for the
two separate value/check overlays above. A narrower first-value overlay and an
actual canonical Set-line deletion are required: whole-scan deletion or Set-to-Del
alone are not credited for these round-2 classes. The production test overlays
are test-instrument controls, not lab runtime changes. No site is excused merely
because its earlier overlay survived in the wrong package.
