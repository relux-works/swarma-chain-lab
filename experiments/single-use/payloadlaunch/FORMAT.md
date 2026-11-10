# DK5b dynamic manifest and anchor v1

This Grants-owned byte contract complements the [journal codec](../payloadjournal/FORMAT.md)
and [typed launch profile](LAUNCH.md). It is implemented by the standard-library-only
`github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch`
package. It performs no filesystem access, provisioning, signing or execution.
A passing byte check is not proof of root custody, a current slot or admission.

## Canonical encoding

Every standalone profile, dynamic manifest and dynamic anchor is one UTF-8 JSON
object with exactly the fields in the order below, no insignificant whitespace,
and one terminal LF byte. Nested objects have no internal LF. Decimal unsigned
integers use no leading zeros, sign, fraction or exponent. Strings use their
literal ASCII spelling for these schemas, not alternate JSON escapes. Unknown,
duplicate, omitted or case-aliased fields, trailing data, BOM/CRLF, invalid types
and noncanonical encodings refuse. All fields are required; no defaults exist.

Version is a positive uint64; zero is corrupt. Supported version is 1. A
structurally valid canonical positive version other than 1 is unsupported.
Future schemas with unknown fields are corrupt to this implementation; neither
verdict permits fallback. Limits include the LF: profile4096, manifest16384,
anchor2048 bytes. Readers must bound reads before calling the codec.

SHA256 fields contain exactly 64 lowercase hex characters. The creation
`generation` contains exactly 32 lowercase hex characters; slotd must generate
128 fresh unpredictable bits when a new creation is admitted, not derive them
from UID, time or booking ID. The codec checks representation, not entropy.

## Manifest fields, in order

Location: `/var/lib/swarma-slotd-demo-payload/<U>/inputs/slot.json`.
This is root:exclusiveSlotGID0640 beneath root:exclusiveSlotGID0750 inputs and
envelope directories. Expected root ownership, exact GID/modes, no ACLs,
single-link regular files, protected physical ancestry and namespace/mount
receipts must be established before bytes are read.

| Field | Type and meaning |
| --- | --- |
| `v` | uint64, 1 |
| `slot` | uint32, 0..9999; OS slot number, not booking ID |
| `uid` | uint32, U; matches slotd policy `uid_base + slot` |
| `gid` | uint32, exactly U; exclusive primary group, no supplementary groups |
| `generation` | creation identifier, unchanged through stop/start/recovery |
| `booking_id` | 64 lowercase hex; must equal decoded canonical bootstrap booking ID |
| `not_after` | UTC RFC3339 to whole seconds, exact `YYYY-MM-DDTHH:MM:SSZ` spelling |
| `profile` | complete typed profile object in [LAUNCH.md](LAUNCH.md), including its version |
| `static_manifest_sha256` | digest of exact existing DK5 signed static manifest bytes |
| `bootstrap` | object `{ "path", "sha256" }` in that order; exact private bootstrap digest |
| `ca` | same file-pin shape; CA certificate bundle digest, no private key |
| `model_config` | same file-pin shape; canonical public model-profile copy digest |
| `journal` | object `{ "v", "path", "directory" }`; v=1 names the journal binding/lock codec |

`directory` is exactly `{ "device", "inode", "mount_id" }`, all uint64.
Inode and Linux mount ID must be nonzero; device zero is representable. These
are observations persisted at creation, not caller-selected desired numbers.
They identify the journal directory, not its mutable turn contents. The
journal v names only DK5b binding/lock v1. DA1b owns its separately versioned
turn records and proxy result registry; neither is embedded in this manifest
or allowed to redefine the binding/lock version. After a
reboot/remount any changed receipt must cause refusal/reconciliation, not an
automatic rewrite of the manifest to new numbers.

The codec checks the complete slotd allocation-range constraint using
`base = uid - slot`: base must be positive; base+9999 must remain below the
uint32 sentinel; the full policy range must exclude UID65534. Runtime slotd
must also compare base with its actual root policy. Numeric consistency does
not establish allocation ownership or current account/group membership.

For U, the paths are fixed and must match literally:

| Object | Derived path |
| --- | --- |
| Envelope | `/var/lib/swarma-slotd-demo-payload/U` |
| Bootstrap | `.../U/inputs/bootstrap` |
| CA | `.../U/inputs/ca.pem` |
| Model config | `.../U/inputs/model.json` |
| Dynamic manifest | `.../U/inputs/slot.json` |
| Journal | `.../U/journal` |
| DK5 static manifest / signature | `.../U/static/manifest.json`, `.../U/static/manifest.sig` |
| DK5 static anchor | `/etc/swarma/payload-anchors/U/10-install.conf` |
| Dynamic anchor | `/etc/swarma/payload-anchors/U/20-slot.conf` |

U is canonical decimal without leading zeros. `PathsFor` derives paths; it does
not resolve symlinks or prove custody. The protected envelope prevents the slot
from replacing the journal directory or changing the envelope's traversal mode.
The actual writable bind is only the journal within this envelope; inputs and
static material remain read-only. Existing H may remain a separate work-home
bind, never an alternate bootstrap/journal authority.

The codec validates time spelling only. Root lifecycle and payload admission
must enforce the deadline against current authority/time, including slotd's
late-start refusal. An expired but syntactically valid fixture is not admitted.

## Namespace observation boundary

The journal.directory {device, inode, mount_id} receipt is a HOST-VIEW custody
observation recorded at Create and compared only by slotd in the host view
(CheckReceipt). Each service view (ExecStartPre, payload main) independently
checks pinned device/inode plus its own exact local mount topology and read-only
flags with its own local IDs; it never compares the host mount_id literally.
The payload proves its own main view before any effect. Prestart proves only its
own view plus the intended unit settings and never claims to have observed the
main namespace. ProtectSystem=strict and two writable binds remain required;
there is no wrapper or manifest rewrite.

## Dynamic anchor fields, in order

`20-slot.conf` is **canonical JSON plus LF**, not the INI format of the existing
DK5 `10-install.conf`. It is root:root0644 beneath root:root0755 ancestry and
contains public pins only. The payload derives its location from actual EUID;
no environment variable, caller argument, bootstrap or arbitrary manifest path
selects it.

| Field | Meaning |
| --- | --- |
| `v` | uint64, 1 |
| `slot`, `uid`, `gid`, `generation` | same typed identity as the manifest |
| `executable_sha256` | exact root-policy payload executable digest |
| `manifest_path` | exact derived `P/inputs/slot.json` |
| `manifest_sha256` | SHA256 of the complete canonical manifest bytes, including LF |

`EncodeSet(manifest)` returns `(manifestBytes, anchorBytes, error)` and returns
no partial bytes on failure. The anchor digest is computed only after complete
manifest validation. `EncodeManifest`, `DecodeManifest` and `DecodeAnchor` are
also available; decoding alone grants no authority.

Root custody is the dynamic authority. This anchor does not replace DK5's
independently approved signed static set, does not authorize a changed CA/model
copy and does not require a release private key in slotd. Static verification
must still verify DK5 signature/key, release digest, primary GID, exact paths,
file membership and hashes; it must agree with the dynamic static-manifest,
release, CA and model pins. Only the Infra station install provisioner via the
deploy lane supplies approved per-UID static sets, within the actual policy UID
range. No manifest expands that scope.

## Byte API, receipt comparison and errors

`File{Present:true, Bytes:raw}` represents a custody-checked existing file.
`File{}` means proved absent. Existing zero-byte files are corrupt, not absent;
an absence claim with nonempty bytes is corrupt. Never map arbitrary read,
permission or symlink failures into absence. Bytes are borrowed read-only;
callers must not mutate them concurrently.

`ValidateSet(anchorFile, manifestFile, actualUID, actualGID)` checks actual UID
and equal primary GID, presence, anchor schema, anchor-to-process identity,
manifest size and anchored hash, manifest schema, then exact repeated
slot/UID/GID/generation/executable binding. It returns the complete Manifest
only on success; every failure returns a zero object. Anchor metadata/location
must already be trusted. A caller-created pair with a matching hash is not an
admitted root anchor.

Slotd additionally calls `CheckReceipt(manifestFile, receipt)`, using its
**previously persisted protected creation record**, never a receipt reconstructed
from candidate bytes. The typed receipt pins:

- slot, UID, GID and generation;
- manifest SHA256, bootstrap SHA256 and executable SHA256;
- not_after and journal device/inode/mount ID.

The manifest digest transitively pins the complete typed profile, booking ID,
static release/set and all input paths/digests. `CheckReceipt` checks schema,
digest and each repeated binding. Root state serialization and its versioned
migration/refusal policy remain Infra's responsibility; Receipt is a Go value,
not a replacement slotd wire/state schema.
`CheckProfile(manifest, currentTrustedProfile)` additionally requires the exact
current typed root policy; a changed valid profile returns ErrBinding. Current
account/group, executable/input metadata, deadline, unit namespace and
enforcement checks are still required. A new self-consistent pair cannot supersede an old receipt.

| Code | Meaning |
| --- | --- |
| `PAYLOAD_LAUNCH_MISSING` | A required file is proved absent; never create/fallback on payload launch |
| `PAYLOAD_LAUNCH_UNSUPPORTED` | Structurally valid record/profile/journal names another positive version |
| `PAYLOAD_LAUNCH_CORRUPT` | Schema/encoding/size/path/value violation, existing empty file, invalid expected receipt, contradictory presence |
| `PAYLOAD_LAUNCH_BINDING` | Actual UID/GID, anchored manifest hash, repeated identity/executable or independently persisted receipt does not match |

Decoders check presence, bounded canonical encoding, semantic constraints, then
supported version. Manifest semantic validation includes its profile before the
outer/journal version checks. ValidateSet first rejects invalid actual UID/GID,
then any contradictory presence claim, then either absent file; it then follows
the anchor/hash/manifest/binding order above. CheckReceipt rejects an invalid
expected receipt before decoding candidate manifest. All codes are fixed and
contain no raw bytes, credentials or underlying diagnostics. Any refusal must
precede journal recovery/network/model/delivery effects; the byte functions
have no I/O and never repair inputs.

## Root write and payload read sequence

Root validates the complete typed policy/approved static set/bootstrap and new
allocation first. It records provisioning intent, creates the protected envelope
and fixed files, initializes journal v1 once, and obtains actual journal identity.
It then prepares the complete manifest/anchor, writes and fsyncs immutable input
material, persists the corresponding creation receipt and publishes the anchor
last. Created state is not reported until all phases are proven durable. Failure
retains explicit failed/reconciliation state and does not authorize a fresh retry.

At every new exec, slotd compares receipt and current root policy, proves actual
input metadata/content and group/process/namespace/enforcement state, and builds
only the typed argv. The root prestart fence must include these checks alongside
its existing cgroup/BPF/NFT proof. A repeat Start of a running slot remains
read-only and does not open journal recovery against the live process.

The payload derives its anchor from actual EUID, validates every required file's
metadata before credential values are read, validates this set and the signed
static set, and checks the canonical bootstrap against its hash and booking ID.
It compares the exact launch argv/settings to the admitted manifest, verifies
actual journal identity and v1 binding/lock, acquires the existing lock without
creation, then validates all retained turns. Only complete admission permits DA1
recovery and transport. Use the same validated descriptors/bytes; no pathname
check followed by an unprotected reopen. Root signatures, UID ownership and
hashes do not waive these race/namespace checks.

These actions are future Infra/payload integration, not implemented by 2a. No
new v1r4 request fields, host changes or old-state migration are introduced here.
Successful Destroy must retire the per-slot envelope and both anchor
materializations before reuse; root-only approved static staging may remain.
Failed cleanup retains receipts and forbids reuse. Same-UID malicious turn
rollback and root compromise remain outside the agreed assurance boundary.

## Public golden vectors

Fixtures are synthetic, include no usable bootstrap, key or live endpoint, and
are not a deployment recipe. Their bootstrap digest is the journal's public
SHA256("abc") vector; all other repeating digests are inert placeholders.

| File | Bytes | Complete-file SHA256 |
| --- | ---: | --- |
| [testdata/manifest-v1.json](testdata/manifest-v1.json) | 1351 | `12142db8f6c6caa00e2356aa79df94753cd1308f6ceb1f6a9329254bb5e6bf02` |
| [testdata/anchor-v1.json](testdata/anchor-v1.json) | 341 | `117ccc3760b5ef98c1cfb484de7c62813aa424a0bc467f731ac5ebeeb9097c31` |

The tests use independently written structs and precomputed fixture hashes;
producer/consumer agreement alone is not the oracle. Exact reviewed source pin
and all golden hashes accompany the delivery packet.
