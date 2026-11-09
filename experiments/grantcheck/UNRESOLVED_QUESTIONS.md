# CG1 integration questions

The routing table and per-identity boundary are accepted. Integration corrections
are recorded in DESIGN.md: closed Retryable classification, Courier-owned bounded
held/exchange queues, full grant-cert only in v1, build-time fork registration,
and Nostr-only grant policies. Matrix owner DM remains outside this path.

## Resolved: Go version

The integration owner initially requested a tagged CG1 module usable by Go 1.25.x.
At the landed base, rental, rental-gateway/kernelbind, rental-gateway, single-use
and sealwatch all declare `go 1.26.0`. Running `GOTOOLCHAIN=local go test ./...`
inside kernelbind with Go 1.25.14 exits before compilation with:

```text
go: go.mod requires go >= 1.26.0 (running go 1.25.14; GOTOOLCHAIN=local)
```

The crypto and sys dependency versions themselves declare Go 1.25.0. This does
not establish that the five application modules are source-compatible with it.
Evidence is retained in the task's `.temp/CG1-01/compat/` logs. The initial
repository-root probe was a module-selection error and is not compatibility
evidence; the direct kernelbind probe establishes the version refusal.

The a2a maintainers resolved this by setting the a2a-link fork and CG1 to Go 1.26. Upstream
a2a stays on Go 1.25.x and never imports chain-lab. No dependency migration,
kernel duplication or toolchain workaround is needed. The early standalone
routing test on Go 1.25 is not a compatibility claim for the complete checker.

## Release prerequisite: tagged transitive module graph

Publication must also make the complete transitive module graph resolvable by an
external consumer. In-tree relative replaces are not inherited by consumers;
tagged versions and their repository/module-path resolution need validation
before claiming that a2a-link can import CG1. No producer push/tag publication is
authorized by this task. The maintainers own review and release coordination.
