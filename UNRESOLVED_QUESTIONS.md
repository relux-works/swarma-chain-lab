# Unresolved questions

## Resolved: detached-v2 observer-local identity

Detached v2 retains its first-admitted seal/ID binding as an explicit v2
exception. Only the grant-key holder can produce valid signature twins; both
bind the same grant key, funded seal and name generation. Each observer admits
the seal at most once; a twin is refused as `SEAL_ALREADY_SEEN` without changing
cache or state. Two fresh observers may record different envelope IDs, so that
ID must never key payment, deduplication, journals or audits across observers.
A new detached profile with a per-certificate commitment is the fix, outside
this change; grants v4's content-only stable object IDs remove the issue.
See the [identifier audit](docs/signature-identities.md) and the genuine-Core
same-observer and two-fresh-observer signature tests.

The Darwin `slotdfake` clock also needs a directory-contract decision.
`SOCKET.clock` is read as installed input (immediate parent exactly `0750`),
while the fake transport requires the socket's same parent to be `0700`.
Changing only fixture permissions cannot satisfy both. Should the clock move
to a separately configured installed-input location, or use an explicit
runtime-owned reader in the private socket directory? Both existing checks
remain enforced; the native macOS fixture is not claimed green.
