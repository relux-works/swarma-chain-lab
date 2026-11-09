# Deployment decisions and qualification limits

- The slot's real agent runtime and its compatibility with this deliberately
  text-only API remain an owner decision. No shim pretending tool/image/MCP
  support is included. Payload support for bootstrap v2 and normal TLS trust
  plus leaf pin must land before optional lifecycle integration is enabled.
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
