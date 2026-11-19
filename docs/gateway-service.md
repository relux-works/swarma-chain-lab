# Credential gateway service boundary

The separable Linux module is `experiments/model-proxy/service`; the installer
neutral unit template is `experiments/model-proxy/service/deploy/credential-gateway.service.in`.
It implements the broker client, request-adapter seam and structural source
used by the existing model-proxy command. This wiring is not a qualified or
installable gateway release.
The template cannot satisfy installer S-20 until the runtime qualification
and A3 release inputs in its [open questions](../experiments/model-proxy/service/UNRESOLVED_QUESTIONS.md)
are supplied. No service is installed or enabled by this change.

The binding broker revision is
[`698d9e40f57058addd80a82d56c356009239dea6`](https://github.com/relux-works/swarma-credential-broker/tree/698d9e40f57058addd80a82d56c356009239dea6):
`spec/broker.md` v0.13 §§4.1, 12.3, 13.1;
`spec/secret-free-service-v0.md` §§2, 3, 5.3–5.8, 7;
`spec/secret-free-gateway.md` §§2–7, 9–10; and
`spec/secret-free-adapters.md` §§1, 3–4. The service role is resolved from kernel
credentials and an active broker binding, not a hello role field. The unchanged
hello is `{versions:[1]}`. Request and renewal carry stable operation IDs;
renewal never retargets a caller/account. The lease ceiling is 900 seconds;
a larger configured value refuses. Revocation/unavailability/connection loss
closes cached use at its affected scope. Ordinary method refusals preserve
unrelated leases and the current socket. Renew and Check close their target on
every error, including ordinary method refusals; Release closes its target
before calling the broker. Hold closes its account before calling the broker;
hold refusals on Request or Renew also block that account. Principal loss
(`role_not_permitted`, `principal_ledger_mismatch`, owned-handle
`lease_not_owner`) closes all connection-owned use. This matches
`internal/server/services.go:95-100`, including the stale-principal paths at
`internal/service/broker.go:478-484,534-536`, at the pinned revision. The client
only sends broker-issued handles of its own bound principal; an arbitrary
non-owner id is never an API input. `revocation_state_unavailable` and every
`grant_*` refusal preserve the socket; a `revoked` or `unavailable` check verdict
closes only the target (`internal/service/broker.go:1142-1170`). Unknown wire
codes are protocol failures, not a default broker-code bucket. The complete
reviewed code set is pinned in `service/internal/wire/types.go` and exhaustively
checked by `TestBrokerRefusalTable`. Caller
strings follow `internal/service/broker.go:323-324` (`validCaller`) and
`internal/wire/frame.go:160-169` (`ASCII`): 1–128 ASCII bytes for account,
generation and launch ID, including slash in `owner/claude/...` labels. These
wire identifiers are never interpreted as installer path components.
`account.hold` carries only the lease, account, operation ID
and closed reason `leak_match`; UNKNOWN acknowledgment keeps local use closed.
The holder must retain the blocked-account state across redials and reconcile
with the same hold operation ID before any new request for that account. The
client's block map alone lasts only for its connection and never clears on an
owner lift. A fresh client still requires the holder's explicit reconciliation
of the account block; redial itself grants no use.

The design reuses the Swarma installation book, `install-book/ru/01-chto-stavitsya.md`
("Parts and their accounts") and `03-shagi.md` (step 6), for separate service
accounts and dependency ordering; the accepted gateway service dialect refines
that lifecycle without enabling it. Installer contract
`relux-works/swarma-installer` revision `d1b9499e`,
`contract/installer-v0/04-install-plan-colony1.md` S-20 owns privileged placement,
account verification, unit activation and after-reboot readback. Its
`02-release-manifest-v0.md` requires a `tar.gz` product artifact with purpose
`platform-root`; a source checkout is not an installer input.

The following suffixes are fixed relative to the installer-supplied platform
root. No concrete host, root path or account is embedded in the unit template.

| Item | Installed contract |
| --- | --- |
| Account | `@SERVICE_ACCOUNT@`, the user manager's admitted local service account at `@SERVICE_GENERATION@`; never an agent, workplace, root or DynamicUser account |
| Executable | `@PLATFORM_ROOT@/credential-gateway/bin/credential-gateway`; runtime artifact/CLI still required |
| State | `@PLATFORM_ROOT@/state/credential-gateway`, 0700, owned by that service account; material is never persisted there |
| Listener | `@PLATFORM_ROOT@/run/credential-gateway/@SERVICE_GENERATION@/gateway.sock`; gateway-owned; caller access and kernel routing must match the qualified tuple, with no old-generation path reuse |
| Unit | installer system-unit directory, `credential-gateway.service`; installed atomically and bound to the verified artifact member |
| Configuration | `LoadCredential=gateway-config:@CONFIG_LOCATION@`, an installer-supplied location; `%d/gateway-config` is passed by location only |
| Dependency | `Requires`, `After` and `BindsTo` the installer-supplied `@BROKER_UNIT@`; restart is disabled pending explicit recovery |

Configuration is protected nonsecret policy, paths and identity pins; it is not
a token input. Broker material never enters a unit, file, argv, environment,
log or error. Provision broker/account bindings first, then enable the broker,
then the gateway, and only then admit callers after independent qualification.
A generation replacement closes the old mapping; it does not reuse leases or
listeners. No template field or successful status read supplies caller authority.

S-20 readback, once the missing runtime/release inputs land: verify the owner-
approved set's gateway artifact digest, member path and placed bytes; verify the
unit digest and all substitutions; read `User`, `ExecStart`, dependency
and credential-location properties with `systemctl show`; establish the process
UID, primary GID from the managed account record, and current service generation; establish listener ownership,
mode and generation path; establish that broker hello returns that exact triple;
then repeat unit/activity/account/listener readback after reboot. Inspect no
credential values. Unit active, a successful broker lease, harness qualification
and effective caller isolation remain distinct observations.

`RenderUnit` performs pure, bounded substitution and rejects missing inputs,
root/nobody accounts, relative or interpolated paths, injected unit names and
unresolved placeholders. Listener generations start with an alphanumeric and
then contain at most 127 alphanumerics, dots, underscores or hyphens; `.` and
`..` refuse. It does not verify protected ownership or managed
ledger records; the installer retains those duties. Tests and narrowing plants
are described in the [module README](../experiments/model-proxy/service/README.md).

## Managed source wiring

The approved dependency direction is model-proxy to service, with the import
only in `experiments/model-proxy/cmd/model-proxy`. The exported `ManagedSource`
interface has only standard-library method types. `service.Source` satisfies
it structurally; an in-package adapter retains the existing private marker,
opaque carriers, tripwire and managed-mode refusals. Existing FileSource and
plain CredentialSource wrappers remain inadmissible in managed mode. A trusted
structural implementation can read a file, so the command must attest the
source origin; the private marker alone is not that attestation.

The command takes the nonsecret installed broker mapping by `-broker-config`
location, checks the fixed Messages recipient and constructs the source. The
[command documentation](../experiments/model-proxy/README.md#managed-broker-wiring)
defines the canonical mapping fields. Missing protected mapping refuses; no
worker-selected identity or file-token fallback is added. This is one static
caller tuple per process and supplies no dynamic launch-registry authority.

The worker's binding bearer stays a placeholder. Only the gateway's existing
provider-authentication boundary replaces it with material obtained through
the service source. A fake Unix broker and fake HTTP transport exercise the
managed path, renewal, wrong-placeholder refusal, broker refusal and revocation,
and check worker output, audits, state, formatting, environment and broker
parameters for fixture canaries. The command holder now supervises renewal,
idle-safe authority checks and source rebuilds, with per-session in-flight
cancellation inside the documented one-second local freshness bound. The
pinned broker protocol remains unchanged. Production provider reflection,
production launch/account reconciliation and system-wide final outbound
revocation qualification remain the integration boundaries listed above.

## Claude launch intake v1

The owner decision `DECISION-claude-gateway-launch-contract-v1.md`, dated
2026-11-19, section "Gateway side (A4, the intake)", refines the request adapter
boundary above. Its evidence is the Claude Code 2.1.328 wire probe, sections
3, 7 and 8. It retains the installation book chapters and broker specs already
named here; it neither changes broker/1 nor authorizes installation or activation.

The explicit command flag `-gateway-socket` selects plaintext HTTP/1.1 on
`<root>/run/credential-gateway/<service-generation>/gateway.sock`. The existing
protected broker mapping supplies the caller account, UID, generation and launch
ID; the supervised holder must bind that exact tuple and service generation.
The listener generation directory must already exist, belong to the service UID,
be non-writable by group/others and have no symlink components. A pre-existing
socket is not removed or adopted. The created socket is mode 0660; the installer
still owns qualified directory/group access and launch custody. The kernel
SO_PEERCRED UID is required on every request; HTTP fields and the public marker
cannot supply or override that authority. There is still one protected caller
tuple per process, not a dynamic launch registry.

Only these shapes are admitted:

| Method and path | Worker credential shape |
| --- | --- |
| `POST /v1/messages` with its query bytes preserved | Exactly one `Authorization: Bearer ssh-placeholder`; no `x-api-key` or other credential header |
| `GET /api/claude_code/policy_limits` without query or body | No credential header, including an empty one |

Other paths, methods, escaped path variants, credential trailers and HTTP versions
refuse before leasing. Messages input is bounded to 128 MiB, with a two-minute
request-read budget; the exact boundary is admitted and one extra byte refuses.
Admission reserves the input window before allocation: at most 128 MiB plus one
sentinel byte in aggregate, and at most eight concurrent body-owning calls.
Known lengths allocate exactly once; unknown/chunked lengths reserve the whole
window. Exhaustion returns 503 before reading or leasing, and capacity remains
reserved until the call exits. This is a bounded in-memory intake, not spooling:
one maximum-sized body can temporarily exclude all other bodies. The JSON meter
also refuses more than 65,536 values or depth greater than 32, bounding parser
structure amplification. The concurrent-body test measures the raw buffer heap;
it does not claim that parsing has no additional bounded allocations.
This covers the first-party Messages API's documented 128 MB request limit
([API errors, request size limits](https://platform.claude.com/docs/en/api/errors#request-size-limits),
checked 2026-11-19). The launch contract specifies no smaller bound. The wire
probe established the two shapes and streaming, but did not measure body sizes;
neither 64 KiB nor any claimed measured size can be derived from that probe.
Synthetic boundary tests are not a measurement of real conversation sizes.
Model JSON bytes are preserved,
including the client's streaming options; the earlier closed `Claude` fixture
classifier is not used to normalize real harness input. Its mapping marker is
also fixed to `ssh-placeholder`.

The service `Gateway` constructs the upstream target only from
`https://api.anthropic.com` and the admitted path/query. It copies supported
end-to-end protocol headers, strips worker credentials, injects the leased OAuth
value only into the private upstream request, and never follows redirects or
uses an ambient HTTP proxy. The same holder retains round-1 renewal, reconnect,
account-hold and per-version cancellation behavior. Source/transport failures
have constant diagnostics; upstream statuses and error bodies are not changed
into synthetic success or retried on 401 by this intake.

Responses stream read by read with a flush after each safe prefix. SSE events,
JSON and error metadata are otherwise unchanged. There is no whole-exchange
client timeout or fixed server write timeout: active streams can exceed 65 s
and continue across renewals. Time to upstream headers has a separate ten-minute
generation budget, including non-streaming requests; it is not the body idle
interval and does not cap an exchange after headers arrive. The budgets are
injectable for boundary tests;
each upstream-read stall and downstream-write stall is bounded to one minute.
One progress timer cancels the call on either stall. Cancellation expires the
worker write deadline and closes the upstream body, so both blocked Write and
Flush paths end; authority loss uses the same fence without waiting for idle.
Lease/session cancellation and the one-second authority freshness fence remain
effective throughout. Encoded upstream responses refuse before worker output,
because the byte matcher cannot inspect compressed material. Retry hints,
including `x-should-retry`, are preserved. A bounded suffix matcher keeps
known token bytes from crossing read boundaries; reflected material is redacted
and material-bearing response headers are dropped. At most 256 issued values are
remembered. A worker leak or inventory exhaustion cancels registered upstream
use and blocks this intake for its remaining lifetime. These process-local
guards do not claim durable UNKNOWN-hold
reconciliation or arbitrary encoded-reflection detection. Fixture tests are not
live harness, broker activation, account/launch reconciliation or final outbound
revocation qualification.

Omitting `-gateway-socket` preserves the existing TLS/per-slot command path and
its durable accounting/tripwire behavior. Socket startup refuses a zero or
omitted daily ceiling and requires the same explicitly initialized accounting
directory. Before any Messages lease or provider call, the intake enforces the
configured model allow-list and a positive `max_tokens` no greater than that
model's context bound. It atomically charges full configured context input plus
requested maximum output against the durable daily ceiling. JSON meter keys are
exact and case-sensitive; aliases (including Unicode folds), escaped keys and
duplicates refuse. HTTP protocol header names are canonicalized, with duplicate
or case-aliased forms refused rather than resolved by arrival order.

Configured prices must cover the worst standard/global token rates throughout
the configured model context, including long-context price tiers. The intake
adds the request's worst cache-write premium to the entire input window (1.25x
for default/5-minute caching, 2x for one hour), and US inference multiplies both
token categories by 1.1. Each category is rounded up to an integer nano-unit;
overflow refuses. Cache controls admit only `type`, `ttl` and an optional
exact `scope:"global"`. Unknown scope values, aliases and other members refuse.
Global scope uses the ordinary TTL premium under the explicit owner price
assumption in the model-proxy `UNRESOLVED_QUESTIONS.md`; this is not provider
pricing qualification. The wire evidence measured the OAuth beta header profile,
not full Messages bodies. The structural 2.1.328 fixture reconstructs static
system blocks with global cache control, dynamic text, tools and mixed TTLs from
the reviewed client builder; all fixture content is synthetic.
Fast speed, non-standard service tiers, server-side tool types,
unknown cache/geography settings and unknown beta flags refuse before forwarding.
Custom client-executed tools remain supported. The allowed beta set is pinned in
`pricedBetaProfile` to the measured Claude Code 2.1.328 OAuth launch profile,
including its extended-cache-TTL flag; those header bytes are preserved, not
stripped. Duplicate beta flags refuse. Adding a price-changing beta or server
tool requires a priced contract and tests first. A first-use beta refusal can
acquire material only to retain the existing worker-leak tripwire; it never
forwards, and the reservation is not refunded.
Parallel calls, restarts, upstream failures and cancellation cannot refund this
conservative exposure; missing or corrupted accounting refuses. Policy GET does
not reserve generation spend. The Unix intake is not a per-slot metering API:
it has no slot identity/caps or verified-usage settlement, so full reservation
remains charged even after a successful response. Those are explicit integration
limits, not an unmetered exception to the ceiling. No listener is inferred from
environment variables or mappings,
and the inactive service template is unchanged.
