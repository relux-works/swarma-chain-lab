# DK5b payload journal initialization codec v1

This is the Grants-owned **byte contract** for slotd's one-time journal
initialization and the payload's subsequent admission. It is separate from
DA1 turn records and from slotd's protected creation record/dynamic manifest.
It does not authorize Create, validate a bootstrap schema, prove filesystem
custody, acquire a lock, migrate old state or perform any I/O.

Binding and lock v1 are owned exclusively by this DK5b package. DA1b owns and
versions its added per-turn records (including request_id/request_hash) and
proxy result registry separately. Those fields do not belong in binding/lock,
and their version numbers must not bump or reinterpret this codec version.
Follow the accepted DA1b turn/registry format documents for those records; this
package neither defines nor migrates them. At this delivery, DA1b is pending.

Package: `github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadjournal`.
It uses only the Go standard library. Version is the on-disk integer `1`, not a
module release tag. Pin the reviewed source commit when consuming this package.
The producer packet identifies that commit and its golden-vector hashes.

## Exact files and bytes

Both files are required. `h` below is exactly 64 lowercase ASCII hexadecimal
characters: SHA256 of the **exact canonical bootstrap bytes**, without trimming,
normalizing, re-encoding or adding a newline. The bootstrap itself is validated
by the existing canonical bootstrap codec before provisioning/use. Slotd's
protected Create receipt and the admitted dynamic manifest must independently
agree with that digest; the files do not choose their own expected value.

`binding.json` is exactly the following ASCII sequence, followed by **one LF
byte (0x0a)**:

```json
{"v":1,"kind":"binding","bootstrap_sha256":"h"}
```

`delivery.lock` is exactly the following ASCII sequence, followed by **one LF**:

```json
{"v":1,"kind":"lock","bootstrap_sha256":"h"}
```

Replace `h` with the 64-character digest, not a JSON object or a quoted string
inside the string. No BOM, spaces, CR, extra LF, alternate field order, unknown
or duplicate field, escaped ASCII spelling, case alias, trailing value or
noncanonical numeric representation is permitted. `v` is an unsigned decimal
integer with no leading zero; zero is corrupt. Supported v1 files are exactly
111 bytes (binding) and 108 bytes (lock). Each file's bounded admission limit is
256 bytes, including the LF. A structurally valid canonical positive version
other than 1 is unsupported; it is never read using v1 semantics.

The kind discriminators prevent swapping the two files. Lock bytes are not
empty and must not change when acquiring/releasing the OS lock. Both files
bind the same bootstrap digest; neither is a signature or a grant credential.
Creation generation, slot UID/GID, journal directory identity and release pins
belong to the separate protected manifest/receipt, not this codec's v1 schema.

## Public golden vector

For an independently reproducible byte vector, use the SHA256 of the three
ASCII bytes `abc`:
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
`abc` is deliberately not a valid payload bootstrap and must never be used to
launch a slot. This vector proves byte interoperability only.

| File | Bytes | SHA256 of the complete file, including LF |
| --- | ---: | --- |
| [testdata/binding-v1.json](testdata/binding-v1.json) | 111 | `6a571370e26e50f10deb6c035cb2795bba234b62ff3d1e0dd3675ceb1570ebf6` |
| [testdata/lock-v1.json](testdata/lock-v1.json) | 108 | `25e0a619c7e762ef54271cda77ecd831b14056a86b7db6cdf606fa3b3657c62e` |

These checked-in files and the independently written test literals are the
normative golden bytes. Tests do not derive their expected bytes with Encode.

## Go API and refusal codes

`Encode(expectedDigest)` returns `(bindingBytes, lockBytes, error)`, with fresh
slices containing the exact v1 bytes. A malformed digest returns ErrCorrupt
and two nil outputs. No partial initialization bytes are returned on error.

`Validate(binding File, lock File, expectedDigest string)` returns nil only for
the exact supported pair bound to the independently established expectation.
`File{Present: true, Bytes: raw}` means an existing file, including an existing
empty/nil byte slice. `File{}` means **proved absent**. Presence must come from
validated descriptor/path evidence; do not turn permission, I/O or symlink
errors into absence. The bytes are borrowed, never modified or cleared.
Callers must not mutate the slices concurrently with validation.

| Code / constant | Meaning |
| --- | --- |
| `PAYLOAD_JOURNAL_MISSING` / `ErrMissing` | At least one required file is proved absent. Never initialize it during payload startup. |
| `PAYLOAD_JOURNAL_UNSUPPORTED` / `ErrUnsupported` | A bounded, structurally valid canonical record with the expected kind/digest syntax names a positive version other than 1. No fallback or migration. |
| `PAYLOAD_JOURNAL_CORRUPT` / `ErrCorrupt` | Existing empty file, malformed/oversize/noncanonical record, wrong kind, invalid digest syntax, invalid expected digest, or contradictory presence/bytes input. Legacy unversioned DA1 bytes are corrupt for this contract. |
| `PAYLOAD_JOURNAL_BINDING` / `ErrBinding` | A structurally valid supported record names a different bootstrap digest from the independent expectation. |

Precedence is deterministic: validate expected-digest syntax; reject any
absent-file claim carrying nonempty bytes; require both files; validate binding,
then lock. Within one record: size/encoding/schema/kind/digest syntax first,
then version, then expected digest. Thus a missing lock takes precedence over
corrupt binding bytes, while unsupported binding takes precedence over corrupt
lock bytes when both exist. Error strings contain no file path, bytes or
underlying diagnostics. Metadata and read failures outside this byte codec must
fail closed before calling it; they must not become a valid empty file or a
repair operation.

## What slotd writes once

Infra owns filesystem and lifecycle enforcement; this package supplies bytes.
For a newly authorized creation only:

1. Validate the independent bootstrap/creation binding and the complete
   provisioning plan. Obtain both outputs from Encode before starting writes.
2. Under the protected root-owned per-slot envelope, create the journal directory
   as slotUID:exclusiveSlotGID0700 and record its identity. No shared group or
   writable ancestor is allowed. Create binding.json and delivery.lock with
   exclusive descriptor-relative no-follow operations. Require new regular
   files, exactly slotUID:exclusiveSlotGID0600, one link, no ACL or special bits.
3. Write each complete output, establish final metadata, fsync both files and
   their directory, then persist the root-owned creation/initialization receipt.
   Publish the generation-bound anchor only after all provisioning obligations
   succeed. A partial write or crash is not a completed initialization receipt.

The codec cannot make two file writes atomic. Slotd must use its durable
intent/receipt discipline and retain an incomplete creation as failed; a
payload must never observe it as a fresh empty journal to repair. No repeat
Create, Start, crash recovery or Stop may truncate, recreate or replace these
files or change the lock inode. Successful Destroy retires them together with
the journal and its protected receipts before UID/GID reuse.

## What the payload verifies

Before any credential use, journal mutation, network connection, ACK or model
call, the installed payload must establish the trusted manifest/receipt,
expected bootstrap digest and exact slot identity. It must verify protected
physical ancestry and the journal-directory receipt, metadata of both files and
all retained entries, then bounded-read them through the same verified
descriptors. No symlink, special file, hardlink, foreign UID/GID, broad/special
mode, ACL, unexpected mount or untrusted path is accepted. Metadata rejection
precedes reading content; a digest/format check necessarily reads bytes first.

Call Validate on the admitted bytes; require both files even on the first
payload launch. Acquire only the already existing delivery.lock inode using a
nonblocking exclusive OS lock, without O_CREAT/truncation/replacement. Recheck
identity/content as needed across lock acquisition and validate retained turns
while holding the lock. Keep that inode and lock for the entire journal use.
Only after complete admission may the existing DA1 recovery phase mutate
in-flight records to ready/uncertain and initiate transport. Lock contention
refuses a second consumer. A version/missing/corrupt/binding refusal performs no
initialization, repair or recovery write. Sanitized refusal telemetry and lock
acquire/release are permitted by the agreed DK5b contract.

These obligations are **not implemented by this codec-only step**. In particular,
DA1 at base `1bed89ba0db4c4cba44ca5a9d28766f435fdc337` writes the old unversioned
`{"hash":"..."}` binding and an empty lock, and can initialize missing state.
This change does not wire Encode/Validate into that consumer or change its turn
format. Step 2b and Infra's slotd delta must adopt v1 together. There is no
in-place migration or auto-detection of the old format. Existing unsupported
state is retained for explicit reconciliation, not erased to retry.

Checksums and bootstrap binding do not establish anti-rollback, detect every
same-UID deletion of a turn, prove power-loss durability or defend against root
compromise. Slotd's protected generation/directory custody and DA1's delivery
semantics remain separate required contracts.

## Tools and validation

After preparing the repository-required isolated absolute HOME, cwd, caches and
temporary directories under task scratch, run from `experiments/single-use`:

```sh
gofmt -l payloadjournal/*.go
go test -race -count=1 -v ./payloadjournal
go vet ./payloadjournal
go test -run '^$' -fuzz '^FuzzValidateExactPair$' -fuzztime=10s -parallel=2 ./payloadjournal
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /absolute/task-scratch/payloadjournal-linux.test ./payloadjournal
```

Go 1.26.8 is the validation toolchain. Package tests read the public golden files
and use no runtime credentials, network or OS-account provisioning. Fuzzing
compares acceptance with literal golden bytes for a fixed expected digest and
checks input preservation. Native race tests exercise supported byte behavior;
Linux cross-compilation is compilation evidence only. Logs, coverage, fuzz cache
and cross-built binaries belong in task-owned `.temp/`, not in the repository.
