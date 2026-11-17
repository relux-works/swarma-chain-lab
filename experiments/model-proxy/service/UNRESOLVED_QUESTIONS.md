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
   on the inbound fixture. Real server/harness headers, including Content-Length,
   User-Agent and Anthropic-Version, require a qualified ingress normalization
   contract with refusal tests before live integration. The allow-list remains
   closed in this source slice.
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
11. The new parent-to-service require edge selects the real signed source
   checkpoint `f6edf6fa2114930458b98779a4d644eba1fadf28` with a local service
   replacement. The unchanged graph checker requires a published snapshot
   floor. The API source has landed, but the accepted floor is still absent
   from the published-module inventory. Recording that baseline is required
   before this edge can pass the graph gate. No fabricated floor or checker
   exception is supplied.

These are delivery/integration gates, not claims of contradictory broker wire
semantics. No alternative provider, exposed-mode fallback or secret input is
introduced to compensate for them.
