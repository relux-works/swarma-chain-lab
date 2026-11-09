# Public N1 fixtures

These canonical JSON files have no trailing newline. `SHA256SUMS` covers the
five JSON files. Keys are public secp256k1 test points for known small scalars:
landlord grant 1, landlord social 2, agent social 3. Never register these keys.
No private key or wallet is included.

- `landlord.json`: combined landlord id/ value with separate grant/social keys.
- `agent.json`: combined agent id/ value pointing to `id/example`.
- `discovery.json`: d/ social mirror, with `_` and `cedar`.
- `inventory.json`: explicit full sample inventory for the local checker.
- `record.json`: exact `d/example` wrapper and its canonical value.

From the rental module, `go test ./cmd/name-discovery` checks fixture building
and matching plus drift/refusal neighbors. Unit tests also check descriptor
schema, canonical order, byte bounds, independent role keys and namespace
separation. These fixtures make no on-chain or live client compatibility claim.
