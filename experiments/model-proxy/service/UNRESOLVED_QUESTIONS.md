# Integration inputs

1. The assigned base has the older flat deploy-kit release builder, not the
   named A3 per-product release template or set-fragment contract. Supply the
   accepted A3 template/revision before extending its artifact inventory. The
   existing release contract is not silently replaced or reinterpreted.
2. Source wiring now lives in the existing model-proxy command. An installable
   gateway artifact and the template executable still belong to the separate
   release round; no template activation or runtime qualification is claimed.
3. A production protected launch/authority/matcher provider and listener
   custody implementation, final submission/response fences and restart
   reconciliation are not qualified by fixture tests. Missing evidence stays
   closed; no permissive production guard is provided.

4. Account blocks are connection-local. The holder must preserve its blocked
   account registry across disconnects and redials. For an UNKNOWN hold it must
   retain the exact operation ID, lease/account arguments and service-generation
   binding, then retry that same hold on the fresh identically bound client
   before any request for that account. A new connection is not an unblock.
5. The pinned broker retires an idle service socket after 30 seconds
   (`internal/server/services.go:54`). Integration must schedule checks strictly
   below that limit with time for scheduling and I/O, or explicitly reconnect and
   rebuild closed sources while preserving account blocks. A closed source never
   reacquires automatically; `Poll` alone does not enforce an idle-safe interval.
6. The Claude classifier currently admits only Authorization and Content-Type
   on the legacy inbound preparation fixture. The owner-decided launch intake
   now has a separate protocol-preserving `Gateway` with positive/refusal plants
   for both measured request shapes. Its static protected tuple, real peer UID,
   source fencing and exact-byte reflection tests do not qualify a production
   dynamic launch registry, arbitrary encoded reflections or a live harness.
7. `Prepare` and `Source` mint operation IDs internally and do not expose a lost
   request/renewal ID. They cannot currently reconcile UNKNOWN issue/renewal
   outcomes. The holder must resolve this API/lifecycle contract before using
   these helpers for durable recovery; minting a new ID is not reconciliation.
8. Natural expiry prevents use but does not schedule memory erasure. Material is
   cleared by a later lifecycle close/check/renew/release/hold or client close.
   Closed handles also remain in the client's lease map until the client is
   discarded. Long-lived production holders need bounded eviction and an expiry
   cleanup design that cannot race renewal; these are not secure-erasure claims.
9. The repository-wide credential-carrier inventory does not cover this module's
   lease value, decoded payload or temporary Source copies. Existing inventory
   success is not evidence for these carriers. Local canary, closed diagnostic
   and codec-erasure tests cover their stated paths only; inventory extension is
   an integration gate.
10. The inactive unit includes the requested capability, kernel, namespace,
    device, process and IPC hardening. The installer/runtime owner must qualify
    the actual binary's syscall allow-list (including `@system-service`) before
    activation. No syscall profile is inferred from fixture-only client tests;
    privileged placement, effective hardening readback and runtime compatibility
    remain installer responsibilities.
11. Resolved snapshot-floor gate: the parent-to-service require edge and
   recorded floor select `v0.0.0-20261119004354-f239a7e42695`, the service
   source landed on main at `f239a7e426950b2f4965ea2b8c326a4d35cc8333`.
   The module inventory records that full commit and its UTC committer time
   `20261119004354` as explicit provenance. The local service replacement
   remains consistent with the parent module's other internal edges. This
   records source selection, not public-proxy or release qualification; no
   checker exception is supplied.

These are delivery/integration gates, not claims of contradictory broker wire
semantics. No alternative provider, exposed-mode fallback or secret input is
introduced to compensate for them.
