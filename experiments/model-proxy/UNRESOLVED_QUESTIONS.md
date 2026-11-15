# Deployment decisions and qualification limits

- The OpenAI Responses profile supports a bounded stateless text/function-tool
  subset. Actual Codex/Muse wire compatibility, reasoning items, provider models
  discovery and bootstrap leaf-pin enforcement remain a separate integration
  unit. The documented base URL/env configuration alone does not qualify a CLI.
- A Meta Responses variant is deferred until sanitized protocol evidence is
  available. Its reported post-completion subscription event, DONE marker and
  non-v1 models route are not implemented or silently accepted by this profile.
- Existing model-profile fingerprint changes require a deliberate state
  migration. Never reset state to erase existing reservations or revive bearers.
- The operator must choose exact model IDs, verified context-window bounds,
  standard/global integer prices and source notes. No production default model
  or price is selected. Guarantees depend on the provider honoring those pinned
  bounds and the priced request profile; response validation cannot retroactively
  reverse a bill from a provider that violates its contract.
- Linux SO_PEERCRED tests exist, but macOS validation and crossbuilding do not
  prove Linux execution. Hosted Linux checks or a separately authorized fixture
  are required for that platform evidence. No real public host is configured.
- TLS certificates, dedicated proxy user, pinned gateway caller UID/group,
  private key provisioning, network egress and operator startup remain external
  deployment work. No user account, host permission or firewall is changed here.
- The 64-record ledger has no automatic retention/GC or key-recovery service.
  State/config migration needs an explicit plan that preserves outstanding
  exposure and prevents old credentials or budgets being recreated.
- Bearer theft is not prevented by a slot path. Same-UID process compromise,
  root/operator tampering and dishonest provider accounting are outside this
  demo's trust boundary. In-flight cancellation does not prove upstream billing
  stopped; full uncertain exposure remains charged.

- The gateway tail (`mode`, `run_max_window_seconds`) is decoded in this module
  because the published config schema module could not change in the same
  slice. Moving the two fields into the published schema would reduce
  `ParseGatewayConfig` to a pass-through; until then both decoders must agree.
- The repository-level credential-output inventory and the package test
  `TestGatewayRevealInventory` both pin the reveal sites in `credential.go` and
  `tripwire.go`; a new reveal must be added to both after review.
- The broker-backed `CredentialSource` and the managed-mode CLI start are a
  later slice; managed mode currently refuses to start.
- Existing installations need an admin-approved migration preserving credentials,
  outstanding exposure and the admission-day bucket before enabling the new
  ceiling. Automatic ledger initialization on startup and state reset are
  deliberately unavailable. Provisioning a provider-key hard limit remains a
  separate operator action; no provider account is changed by this module.
