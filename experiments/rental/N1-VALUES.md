# N1 name-value profile and discovery sync

This is a local laboratory publishing subset, not a general N0/N1 resolver or
permission to register, update, renew or spend. K1 authority remains in `id/`.

## Authority values

Historical values/builders remain byte-identical. The optional top-level
`nostr` member precedes `swarma`; when absent, no social identity is inferred.
When present its exact fields are `names`, then optional `relays`:

```text
nostr.names = {"_": "<social x-only public key>"}
nostr.relays = {"<same social key>": ["wss://relay.example/"]}
```

`NostrDescriptor` and `NostrNames` are typed. The root is a lowercase 64-hex
mathematically valid secp256k1 x-only public key. The names object has exactly
one `_` entry. A supplied relay map has exactly that key and a nonempty array
of distinct absolute `ws` or `wss` URLs with a nonempty hostname. Userinfo and
nonempty fragments are excluded in this subset; URL spelling is preserved and
duplicates mean exact string equality. Nothing fetches or connects to a relay.

Explicit null, empty objects/arrays, unknown fields, scalar shorthand, `pubkey`,
N2 arrays, aliases, imports and delegated maps refuse. Shared strict JSON
validation also rejects duplicate/case-fold-equivalent/escaped duplicate keys.
Exact Go marshal bytes are required, including field/map order and escaping;
trailing whitespace or another document refuses. The final UTF-8 JSON value,
without newline or RPC wrapper, must be at most 520 bytes in builders and parsers.

For agents, `nostr.names._` must equal `swarma.agent.nostr`. For landlords the
social key is independent of `swarma.landlord.grant`; equal keys are allowed,
not inferred or required. Relay hints bind to the social key. The grant key
alone remains grant authority. No namespace, key primitive, signed grant or
confirmed/pending transition rule changes. Both confirmed and pending values
use the upgraded parser; social-only updates preserve a grant, while observed
pointer/grant-key rotations retain the existing closure rules.

Public APIs:

- Existing `AgentBindingValue`, `LandlordValue`, `ParseAgentBinding` and
  `ParseLandlordValue` retain their binding types and historical shape.
- `CombinedAgentBindingValue` / `CombinedLandlordValue` take the binding and an
  explicit `NostrDescriptor`; they never infer a landlord social key.
- `ParseAgentIdentity` / `ParseLandlordIdentity` return binding, optional
  descriptor and error. Failures return zero binding and nil descriptor.

Exact public fixtures and their hashes are in `testdata/n1-values/`. Their keys
are known small-scalar test keys, never publication candidates.

## Separate d/ mirror

The `discovery` package and `cmd/name-discovery` operate on local public files.
The authority package and its consumers never import them. A mirror has exactly
`{"nostr":{"names":{"_":"<landlord social key>","cedar":"<agent social key>"}}}`.
Keys are valid x-only points; map keys are sorted. No `swarma`, relay, wildcard,
import or delegation field is accepted here. This narrower discovery tool is
not a parser for all valid N1 documents. A d/ shape cannot be used as an id/
authority value, and an id/ combined value cannot be used as a mirror.

Labels are flat lowercase ASCII letters/digits/hyphens, length 1–63, no leading,
trailing or repeated hyphen. `_` is reserved for the landlord. The landlord
`id/<label>` determines the exact expected `d/<label>` name. Agent id/ names
are explicit inventory entries, not derived from labels, and their embedded
landlord pointers must agree. Agent labels and full names must each be unique.

Inventory has `landlord`, its canonical `value` string, and an explicit `agents`
array (empty allowed, null refused), each with `label`, `name`, `value`. Every
id/ value must have a valid combined descriptor. At most 32 inventory entries
are admitted before semantic checks; the final 520-byte mirror budget normally
limits the useful count much further. A `Record` wrapper has `name` and `value`.
Outer local-file JSON need not be compact; its embedded name-value bytes do.
The CLI reads at most 64 KiB inventory / 4 KiB record and emits JSON to stdout.

```sh
mkdir -p .temp/n1
go build -trimpath -o .temp/n1/name-discovery ./cmd/name-discovery
.temp/n1/name-discovery -inventory testdata/n1-values/inventory.json > .temp/n1/expected.json
.temp/n1/name-discovery -inventory testdata/n1-values/inventory.json \
  -record testdata/n1-values/record.json > .temp/n1/check.json
```

Exit 0 means built or exact match; exit 1 means well-formed drift; exit 2 means
invalid input. Drift output contains `ok`, sorted `missing`, `extra` and
`mismatched` label lists, including `_` if the landlord social key differs.
Invalid input returns only `{"error":"INPUT"}`. The tool neither publishes
names nor verifies chain freshness or inventory completeness.

## Checked add/remove procedure

1. Upgrade all K1 consumers before publishing any combined id/ value. Preserve
   the complete operator-owned inventory of agents for each landlord.
2. After the separately authorized agent add/remove/key-update operation,
   obtain fresh confirmed landlord and retained-agent id/ values using the
   normal trusted observer. Reconcile the full inventory, including removals.
   A removed agent's former social entry must not remain in the desired mirror.
3. Build the expected d/ record from that full snapshot, then compare the
   current confirmed d/ readback with the same inventory using `-record`.
   Missing, extra and mismatched keys are actionable drift. Do not advertise
   the mirror as synchronized while the checker refuses or reports drift.
4. If needed, have the authorized name custodian update the d/ value. After
   confirmation, refresh every input and rerun the checker against readback.
   Retain the inventory, readback and check output with the operation evidence.

There is no atomic update across names and no automatic publication or retry.
An incomplete/stale inventory can yield a misleading match: this offline tool
cannot discover omitted on-chain records. A stale/unavailable mirror affects
social discovery only; it must never grant, revoke, widen or gate K1 authority.
Existing seal, issuance, sender, name-generation and freshness checks still run.

## Upgrade and validation

All in-repo consumers resolve the same rental source through existing relative
module replacements. Rebuild rental commands, grantcheck, kernelbind/gateway,
signer-service, agent-wallet, rental-executor, grant-store and booking integrations.
Transport-only relay/station integrations are also checked for dependency drift.
Published `v0.1.0` modules and installed binaries do not auto-update: release the
reviewed parser and rebuild/install external consumers separately before names
change. Old binaries reject the new member. This change does not attest a host
upgrade, publish tags or change external consumers' pinned versions.

From this module with Go 1.26.8:

```sh
go test -race ./...
go run .scripts/n1-guards.go -out .temp/n1-guards
go run .scripts/n1-dependencies.go -out .temp/n1-dependencies
```

The guard runner uses an isolated copy, requires passing baselines, records
source/mutant hashes and requires the named assertion to fail for each plant.
Compile failures, crashes and skipped tests do not qualify. Shared canonical
and strict-decode guards are tested as one boundary (one may mask the other).
The dependency runner checks 13 production graphs, verifies local rental
resolution and proves the fence with a compilable blank import into grantcheck
through a Go overlay. Source files stay untouched. Logs/results go under fresh
`run-*` subdirectories; dependency output includes local source paths.

Genuine Core `TestCoreN1Values` and `TestCoreN1Pointer` require the pinned binaries
and separate fresh roots described in README. Run them beside existing
`TestCoreGrantLandlordRotation`, `TestCoreGrantPointerRotation` and
`TestCoreGrantNameRecovery`. They exercise actual name updates and issuance,
not a mocked observer. Default unit runs explicitly skip opt-in Core suites.
