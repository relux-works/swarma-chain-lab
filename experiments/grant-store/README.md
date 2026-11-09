# Signed Blossom grant store

S1 is a bounded Go HTTP service and client for storing exact grant bytes by
SHA-256. Every upload and retrieval requires a signed Nostr authorization event.
Each blob has one immutable putter and reader set. K1's grant kernel is unchanged;
being able to download a grant does not establish its current authority.

## Protocol and authorization

The wire surface follows [BUD-01](https://github.com/hzrd149/blossom/blob/master/buds/01.md)
and [BUD-02](https://github.com/hzrd149/blossom/blob/master/buds/02.md), including
extensions, HEAD, ranges, CORS, descriptors and 201-new/200-existing upload status.
Current [BUD-11](https://github.com/hzrd149/blossom/blob/master/buds/11.md) defines
authorization; [BUD-12](https://github.com/hzrd149/blossom/blob/master/buds/12.md)
defines management. This private-store policy requires signed GET with an `x` tag
and adds upload `p` tags as readers. Public anonymous Blossom retrieval is disabled.
Optional upload preflight, mirroring and reporting BUDs are outside this MVP.

| Request | Authorization and result |
| --- | --- |
| `PUT /upload` | Kind 24242, `t=upload`, exactly one `x=SHA256(body)`, writer allowlist; `p` keys become readers and the putter is always included. Descriptor contains `url`, `sha256`, `size`, `type`, `uploaded`. |
| `GET /<hash>[.ext]` or `HEAD` | Kind 24242, `t=get`, matching `x`, signer in this blob's readers. Hash is 64 lowercase hex characters. Extensions contain 1–16 ASCII letters/digits. |
| `DELETE /<hash>[.ext]` | Kind 24242, `t=delete`, matching `x`, signer is this blob's putter. Returns 204. |
| `GET /list/<pubkey>` | Kind 24242, `t=list`, signer equals the requested pubkey. Returns only that putter's descriptors. `limit` is 1–100 (default 100); `cursor` is the last returned hash. Descending upload time, ascending hash for ties. |
| `OPTIONS` | Unauthenticated CORS capabilities, no blob metadata. |

`Authorization: Nostr <event>` uses unpadded base64url; older padded standard
base64 is accepted. The reviewed `rental-gateway/nostr` package checks duplicate
JSON keys, shape, NIP-01 event ID and BIP-340 signature. Auth requires one matching
`t`, one canonical integer expiration strictly in the future, and a nonempty
human-readable content string. Both expiration-minus-now and
expiration-minus-created_at are at most 300 seconds. Future creation is limited
by configured skew. Optional `server` tags match the configured lowercase hostname,
not the untrusted HTTP Host header; their BUD scope has no port. Clients always
emit server scope and a random nonce so fresh requests within one second differ.
Auth is bounded to 8 KiB decoded, 80 two-field tags and 64 unique reader tags.

Missing/invalid auth returns 401 independently of blob existence. A valid signer
who lacks access receives the identical 403 body/headers for missing and forbidden
blobs. Responses use `Cache-Control: no-store`. This is a response-content
non-disclosure contract, not a constant-time network anonymity claim.

An existing hash can be uploaded again only by its original putter with the same
normalized ACL (including the putter); this returns 200 without modifying state.
A competing writer or any ACL change returns 409. Deletion allows a later fresh
upload. Reader ACLs are not encryption: the private storage operator can read disk.
All data is served as `application/octet-stream`.

## Durable state and limits

An existing absolute 0700 owner-controlled root is locked through the reused
`single-use/durable` primitive. One process owns `store.lock` for its lifetime.
Each hash directory contains a 0600 `blob` and adjacent canonical
`metadata.json` with owner/readers/descriptor. Upload fsyncs both files and the
staging directory, atomically renames the directory, then fsyncs the parent.
Delete renames the whole directory out of the visible namespace, fsyncs, and
removes it. Startup cleans unpublished staging directories, validates private
files, content hashes, metadata and configured bounds, and rejects corruption.
Returned descriptor URLs follow the current configured endpoint after restart.

The canonical `replay.json` journal reserves each valid auth ID durably before
any operation or response, including later ACL/cap rejections. Retries need a
freshly signed event. Expired entries are evicted, and a persisted time high-water
rejects clock rollback with 503. Journal errors and uncertain post-rename effects
fail closed until reopen; a consumed event stays consumed after a failed effect.
A client that loses an upload response can retry with fresh auth and the same ACL.

| Config key | Default | Accepted nonzero range |
| --- | ---: | ---: |
| `max_blob_bytes` | 1 MiB | 1 byte–64 MiB |
| `max_blobs` | 1024 | 1–4096 |
| `max_total_bytes` | 64 MiB | At least `max_blob_bytes`, at most 1 GiB |
| `max_replay` | 512 | 1–512 |
| `skew_seconds` | 30 s | 1–60 s (zero selects default) |

The replay ceiling fits the reused journal's 64 KiB bound even with int64 expiry
values. Defaults reserve at most 512 valid requests in any 300-second window;
429 indicates replay/storage capacity. Blob quotas bound payload bytes and object
count, not filesystem overhead. Startup hashes bounded stored data. Requests are
serialized through authorization and storage, including bounded upload reads.
The CLI supplies read/header/write timeouts; library hosts must do the same.
This is a small single-process store, without distributed transactions, rate
limiting or protection against a hostile owner of its private root. Do not reset
or restore old journal state independently of the blob store.

## Tools and local CLI

Use Go 1.26.8 on macOS or Linux (the durable dependency uses Unix flock).
Dependencies are pinned; no `go-nostr` is added. The upstream MIT client pattern
is attributed in [NOTICE](NOTICE) and its [license](LICENSE.a2a-transport-nostr).
The inspected upstream in-memory test server is unsuitable for mandatory signed
GET and persistent ACL/replay, so it is not imported as this server.

From this module:

```sh
go mod download
go mod verify
go vet ./...
go test -race -count=1 ./...
go build -trimpath -o ../../.temp/grant-store ./cmd/grant-store
go run .scripts/guard-controls.go -out .temp/guards
```

The CLI verbs are `serve`, `put`, `get`, `delete`, `list`. `serve` accepts only a
loopback IP listen address and prints a JSON URL/PID record; SIGTERM/interrupt
shuts it down. Create a private local store root and supply a JSON config:

```json
{
  "root": "/absolute/private/store-root",
  "writers": ["<64-hex-writer-public-key>"],
  "public_url": "http://127.0.0.1:8091"
}
```

`public_url` may be omitted for the actual bound address, including port zero.
`root` must already exist with mode 0700. A client `-key` file must be an
owner-private, single-link regular 0600 file containing exactly 64 hex bytes
without a newline. Supply it through existing key custody; the CLI never prints
keys or generates wallet keys. The library requires HTTPS for remote hosts and
allows HTTP only for loopback hosts; all automated checks use localhost.

```sh
../../.temp/grant-store serve -config .temp/store-config.json -listen 127.0.0.1:8091
../../.temp/grant-store put -server http://127.0.0.1:8091 -key .temp/writer.key -in .temp/grant.json -readers '<reader-pubkey>,<agent-pubkey>'
../../.temp/grant-store get -server http://127.0.0.1:8091 -key .temp/reader.key -hash '<sha256>' -out .temp/download.json
../../.temp/grant-store list -server http://127.0.0.1:8091 -key .temp/writer.key
../../.temp/grant-store delete -server http://127.0.0.1:8091 -key .temp/writer.key -hash '<sha256>'
```

CLI transfers are capped at 1 MiB. `get` verifies the full hash before creating
its exclusive 0600 output; existing output is preserved. CLI/library `List`
returns the first page (up to 100); HTTP callers can paginate. Client requests
refuse redirects, bound response sizes and verify upload descriptors and fetched
hashes. `Client.MaxBytes` can raise the library transfer cap up to 64 MiB.

`Client.PutGrant(ctx, server, canonicalSignedGrant, landlordKey, agentKey)` first
calls K1 `rental.ParseSignedGrant` and sets readers to grantee, landlord and agent,
plus the putter. Caller-supplied landlord/agent keys are explicit trust pins.
`Client.GetGrant(ctx, server, grantID)` verifies content hash and canonical signed
grant ID. The issuance locator/presentation and live authority checks remain with
K1 and its caller. These helpers neither issue a grant nor spend funds.

## Validation contract

Tests carry specific claims beside each group. They include 26 named malformed
upload/auth controls with valid put/read neighbors, missing/forbidden response
equality, cross-blob readers, putter-only management, immutable ownership/ACL,
replay across restart, three concurrent race scenarios, unknown-length body caps,
private-file corruption, changed endpoint restart, hostile server responses,
canonical signed-grant helpers, and compiled CLI/private-key checks.

Injected errors and six child-process exits cover reservation, file sync,
publication and deletion boundaries. They prove process-interruption behavior
on the host filesystem; power-loss durability and deployment performance are
not measured. The grant fixture proves cryptographic storage glue offline and
makes no live chain/issuance claim. The crash-child helper skips when invoked
alone; its parent invokes every stage explicitly and requires exit 73.

The Go guard runner copies this module into private `.temp/guard-work-*`
fixtures, uses unchanged in-tree dependencies, and removes one guard at a time.
It first requires a passing baseline, then requires exit 1, the named failed test,
and its intended assertion text. Compilation errors, crashes, setup errors and
non-applied mutations cannot count. Twenty-four plants exercise crypto admission,
writer/reader/owner checks, replay/durable reservation, ownership/ACL immutability,
quotas, clock rollback and client hash/redirect checks. The combined crypto plant
removes both ID and signature admission because the reused verifier also checks
the event ID; the separate signature plant leaves the ID check intact.
Evidence is `.temp/guards/run-*/{baseline.log,*.log,results.json}`. These are local
controls; independent review and hosted CI must still assess the delivered head.
