# Staged signed static-set validation

ValidateStagedSet(StagedSet, StagedPolicy) error is the public, pure provisioning
boundary. It validates custody-checked bytes before a root installer writes any
final paths. It performs no filesystem access, does not call a Reader, does not
synthesize ownership, does not rewrite a signature or manifest, and returns only
an error (nil means the byte contract passed).

This is additional admission for provisioning, not a substitute for installed
OpenSignedSet/ServiceSet checks. No daemon integration or provisioning
transaction is implemented here.

## Inputs and trust

StagedSet supplies:

- Anchor: exact approved 10-install.conf bytes in the existing closed DK5 format,
  with independently approved public key and manifest/release pins.
- Manifest and Signature: exact existing signed static-set bytes.
- Files: a map from final absolute config paths to custody-checked staged
  contents. Keys are final names; no staging path is interpreted or opened.

StagedPolicy is independent trusted root provisioning policy:

- ManifestPath, SignaturePath: expected final metadata paths, matched against
  the anchor. The existing anchor requires distinct clean absolute paths in
  one parent directory.
- ReleaseSHA256: approved lowercase SHA256 release digest, matched against
  both anchor and manifest.
- Service, GID: nonempty trusted service identifier and positive group, matched
  against the manifest. No process EUID is inferred or required: this pure call
  is usable by the root provisioner.
- Paths: exact sorted, distinct, clean absolute final config paths, between
  1 and 256; cannot alias the manifest or signature. Membership and order
  must match the signed manifest exactly.

Do not derive expected policy from the staged manifest. Root must establish
anchor provenance/approval, source ancestry, owner/group/mode, regular-file and
single-link identity, no symlink traversal, bounded stable reads, and custody of
every byte slice before invoking this function. The function cannot attest to
that history, ACLs, mounts, race freedom or the real destination. An arbitrary
self-signed set plus caller-invented policy is not an approved install.

All slices/maps remain caller-owned and unmodified on both success and refusal.
They must not change concurrently. After success, retain the checked byte
snapshot under root custody through transactional installation; a nil error is
not a reusable authorization for subsequently changed bytes. Installed service
admission must still verify actual final metadata, signature and content.

## Exact checks and refusal codes

First failure returns the existing configguard.Reason, without embedding input
data, paths or keys. This API adds no new refusal codes.

| Order | Check | Refusal |
| --- | --- | --- |
| 1 | empty expected service or nonpositive GID | DK5_SERVICE_IDENTITY |
| 2 | malformed expected release pin | DK5_MANIFEST_ANCHOR |
| 3 | invalid or identical expected metadata paths | DK5_PATH |
| 4 | invalid expected file count/order/path or metadata alias | DK5_MANIFEST_PATH |
| 5 | absent/empty/oversized anchor (limit 32768 bytes), then anchor parse | DK5_ANCHOR_FILE, DK5_ANCHOR_SCHEMA |
| 6 | anchor final paths or release differ from policy | DK5_MANIFEST_BINDING |
| 7 | absent/empty/oversized manifest (limit 1 MiB), then anchor digest | DK5_MANIFEST_READ, DK5_MANIFEST_HASH |
| 8 | absent/empty/oversized signature (limit 32768 bytes), then real signature | DK5_SIGNATURE_FILE, existing signature schema/key/invalid codes |
| 9 | shared manifest schema, version, release/service/GID, sorted path/hash validation | DK5_MANIFEST_SCHEMA, DK5_MANIFEST_BINDING, DK5_MANIFEST_PATH |
| 10 | manifest files differ from exact policy membership | DK5_MANIFEST_BINDING |
| 11 | supplied byte-map contains any unlisted path | DK5_UNLISTED_PATH |
| 12 | in manifest order: absent byte-map entry; present empty/oversized file (16 MiB); content digest | DK5_FILE_OPEN, DK5_FILE_SIZE, DK5_CONTENT_HASH |

Nil and empty anchor/manifest/signature bytes both mean unreadable staged
material at this boundary; their installed path uses the same wrapper code.
For config files, absent map entry differs from a present empty/nil slice.

Both paths share the production anchor parser, domain-separated Ed25519 or
RSA-PSS-SHA256 verifier, and pure manifest decoder. The installed reader still
loads actual files and validates custody on every read. The staged validator
intentionally adds independent exact expected-path/release checks and rejects
extra supplied bytes; installed OpenSignedSet learns its member list from its
root-approved signed manifest and has no staged byte map. Do not claim universal
verdict equivalence between these different input contracts.

## Verification tools

From the repository root, using a physical task-owned checkout with absolute
isolated HOME/config/cache/temp/toolchain directories:

    go -C experiments/single-use test -race -count=1 ./configguard
    go -C experiments/single-use vet ./configguard
    go run .scripts/dk5-guards.go -out /absolute/task-scratch/dk5-controls

Tests pair exact refusals with real signed positive controls and assert unchanged
inputs. Both signature algorithms are exercised. A signed relocation is rejected
by the independent path policy and accepted when that trusted policy is
deliberately changed. Focused installed/staged comparisons share explicitly
named byte-contract cases; their installed ownership seam is test-only.

The existing guard runner adds real staged content-hash, expected-final-path
and signature bypass plants. Each baseline must pass; each plant must fail its
specific assertion rather than merely crash or fail to compile. Logs, overlays,
PIDs, hashes and exit codes go to the new absolute output directory. Native
tests do not qualify an actual Linux install or root metadata.
