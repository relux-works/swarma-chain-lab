# Credential gateway service boundary

The separable Linux module is `experiments/model-proxy/service`; the installer
neutral unit template is `experiments/model-proxy/service/deploy/credential-gateway.service.in`.
It implements a client and adapter seam, not a runnable or qualified gateway.
The template cannot satisfy installer S-20 until the runtime and A3 release
inputs in its [open questions](../experiments/model-proxy/service/UNRESOLVED_QUESTIONS.md)
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
