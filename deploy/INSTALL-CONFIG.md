# DK5 signed installed inputs

This is the Linux installation contract for Infra, not host acceptance evidence.
Root compromise is out of scope. The checker never installs, signs, repairs or
falls back to an unsigned/default input. Install-key custody belongs to Infra.
The recommended signer keeps its ephemeral private key in memory; any alternative signer must keep private keys root-only
and outside every agent-readable path.

## Generator ownership at creation

Generate secrets directly at their final paths with final ownership:

```sh
deploy-kit g2-keygen -out "$KEY" -mode 0640 -owner "$OWNER" -group "$GROUP"
deploy-kit g2-rpcauth -params "$PARAMS" -wallet-public "$PUBLIC" \
  -wallet-config-out "$CONFIG" -owner "$OWNER" -group "$GROUP"
```

`-owner` and `-group` independently accept names or canonical decimal IDs
(no sign/leading zeroes except `0`; the all-ones syscall sentinel is refused).
Both specified identities are resolved before exclusive creation. Unknown names
or lookup errors refuse without output; absent flags preserve creation
ownership. The key mode remains `0600` by default or `0640`; wallet configuration
mode is always `0640` and has no `-mode` option. Creation starts at `0600`, then
uses `fchown` and `fchmod` on the same descriptor before writing any content.
Metadata failure removes the original created inode without writing secrets;
file and parent are synced before successful public output.

When using the [attempt ledger](G2-LEDGER.md#exclusive-external-creators), pass
these flags to the generator after `--`: **no chown after exec-create**. The
ledger commits the final uid/gid/mode along with device and inode; changing
ownership afterwards invalidates that identity. Do not generate a staged copy
and then copy it into place: that leaves a second plaintext credential file.

## Provisioning and binding

1. Verify the accepted public release and its existing release signature. Its
   public manifest remains the binary/template inventory; no secret hashes go in it.
2. Provision each service's static configs/secrets as root:swarma-SERVICE0640,
   inside root:swarma-SERVICE0750 directories. All ancestors must be root-owned,
   non-group/world-writable, with no special mode bits or symlinks. Files must be
   regular, single-link and nonempty. Keep each private group exclusive. Infra
   must check actual NSS membership and ACLs; mode checks do not inspect ACLs.
3. Write one private resolved manifest per service from Infra's independently
   resolved and approved bytes. Do not derive approval by re-reading installed
   disk content. Re-provision formerly service-writable secrets from custody;
   chowning those bytes and hashing them does not establish trusted provenance:

```json
{"v":1,"release_sha256":"ACCEPTED_PUBLIC_MANIFEST_SHA256","service":"model","gid":1234,"files":[{"path":"/etc/swarma/model/service.json","sha256":"EXACT_FILE_SHA256"}]}
```

The placeholders above are schema notation, not valid install values. Digests
are64 lowercase hex characters. Service is one of issuer, gateway, model,
booking, store, relay, wallet, stations, payload; gid must equal that service's
approved private group (positive integer). Include EVERY referenced static input,
including route credentials, certificates, keys and public model/profile copies.
Paths must be canonical absolute paths, strictly sorted and unique; do not list
the manifest itself. Files array has1–256 entries. Unknown/duplicate JSON fields,
extra values, invalid types and malformed encodings refuse. Manifest is bounded
to1MiB; individual config files have tighter native bounds, never above16MiB.
The CLI credential `NodeConfig` used by booking is admitted before its external
reader starts; mutable CLI datadir stays service-owned outside `/etc`.

4. Use the in-memory signer on the independently approved manifest bytes:

```sh
deploy-kit g2-install-sign -manifest "$MANIFEST" -sig-out "$SIGNATURE" -pub-out "$PUBLIC_KEY_FILE"
```

Use new absolute output paths in existing directories with no symlink ancestors.
Both outputs must be absent (including dangling symlinks); a collision found at
preflight refuses with exit 1 before reading the input or generating a key.
Exclusive creation also refuses a collision introduced after preflight. The signer generates a
fresh Ed25519 key with `crypto/rand`, signs EXACT manifest bytes prefixed by
`swarma-config-install-v1` followed by one NUL, and writes only these two files:

- `-sig-out`: detached signature JSON, with a final newline:

```json
{"v":1,"algorithm":"ed25519","signature":"STANDARD_BASE64_SIGNATURE"}
```

- `-pub-out`: canonical standard-base64 PKIX SubjectPublicKeyInfo DER, without a
  newline, directly usable as `render-install-anchor --public-key
  "$(cat "$PUBLIC_KEY_FILE")"`. It contains no private key.

`-manifest` is recommended so callers never construct the domain prefix.
For callers that already have the framed input, the compatible interface is
`deploy-kit g2-install-sign -input "$SIGNED_INPUT" -sig-out "$SIGNATURE" -pub-out
"$PUBLIC_KEY_FILE"`. Choose exactly one of `-manifest` and `-input`; `-input` must
start with the exact domain and NUL and contain nonempty manifest bytes after it.
The manifest is bounded to 1 MiB in either mode. Signing does not approve the
manifest schema, provenance or deployment policy; configguard still checks them.

Each output is opened with `O_CREAT|O_EXCL|O_NOFOLLOW`, set to mode 0644, written
with a complete-count check and fsynced, along with its parent directory. Any
write failure returns nonzero and rolls back only outputs created by this call,
after checking the path's device and inode against the creating descriptor.
An observed replacement is preserved and cleanup refusal is reported. Keep the
parent directories under exclusive provisioner control during the operation;
identity lookup and unlink do not form an atomic compare-and-delete against a
concurrent privileged directory writer. Abrupt termination can leave public
outputs; inspect them and use new paths rather than automatic deletion/retry.

The private key is never written, printed or logged. Owned seed and private-key
buffers are cleared after use, before output publication. This is best effort:
Go, the cryptographic implementation, runtime copies, swap and crash dumps are
outside the buffer-clearing guarantee. The command prints nothing on success
and only generic errors on failure. Its fresh key cannot sign a later revision;
provision a newly approved anchor with every newly signed manifest.

Alternative external signers (including OpenSSL where already provisioned) must
produce the same domain-separated signature JSON and public-key encoding.
Supported verification algorithms remain `ed25519` (direct signature over
domain+bytes) and `rsa-pss-sha256` (SHA256 of domain+bytes, RSA3072–8192 bits,
exponent65537, PSS salt length32). Unknown algorithms and key/algorithm
mismatches refuse. Signature base64 is canonical. External private-key custody
and cleanup are the provisioner's responsibility; do not infer file ownership
from a writer PID or delete a key merely because that process has exited.

5. Install manifest and signature root:swarma-SERVICE0644 INSIDE that service's
   private0750 directory. Do not publish either file or private hashes. Render
   the six-pin drop-in using `deploy-kit render-install-anchor` (README command).
   Install it root:root0644 at
   `/etc/systemd/system/swarma-SERVICE.service.d/10-install.conf`, whose immediate
   parent is root:root0755. It pins manifest path, signature path, manifest hash,
   accepted release-manifest hash, algorithm and public key. Use the exact
   renderer output: a closed `[Service]` section and six ordered `Environment=`
   lines with final newline. Extra comments/lines, shell syntax and expansion
   characters refuse. The loader reads this fixed root file directly; process
   environment values cannot substitute authority. The private digest is
   deliberately visible in this root-owned public anchor; per-file secret hashes
   stay private. Never put the signing private key in a drop-in.
6. Every daemon's first ExecStartPre runs its OWN executable `--check-installed`.
   This verifies anchor metadata, exact manifest hash, real signature, release/
   service/GID binding and ALL listed file metadata/hashes before constructors.
   Gateway then performs its existing native schema validation. Ordinary loaders
   repeat signed-set validation and membership/hash checks for each load, so a
   successful earlier preflight never waives drift. Provision/reseal changes
   atomically through Infra's controlled stop/update/start procedure; no live
   root-update consistency guarantee is implied.

## Service and socket groups

Wallet daemon uses `Group=swarma-wallet-peer`, `SupplementaryGroups=swarma-wallet`;
only the latter can read its config. The agent receives only the peer group.
Model proxy analogously uses `swarma-model-peer` and private `swarma-model`;
gateway receives only the peer group. Service loaders resolve the private group
by fixed NSS name, independently of the process's socket GID. Keep state0700.
No other peer may join a private configuration group.

Booking's provider key and CLI credential move from mutable `/var/lib` paths to
`/etc/swarma/booking/provider.hex` and `/etc/swarma/booking/namecoin.conf`. Update
the native route, unit and deployment descriptor together; no alternate path or
old-mode fallback is provided. RPC client datadir remains under `/var/lib`.

Gateway's agent key moves from `/var/lib/swarma-gateway/agent.key` to
`/etc/swarma/gateway/agent.key`, with a root:swarma-gateway0750 parent and
root:swarma-gateway0640 file. Update both the native config and private signed
manifest. Mutable `/var/lib/swarma-gateway` stays gateway-owned0700.

Native `swarma-relay -check` and `gateway validate` now require the signed
installed set. They no longer validate `$STAGING` paths: missing anchors refuse
with `DK5_ANCHOR_FILE`, root invocation with `DK5_SERVICE_IDENTITY`, and an
unlisted staging path with `DK5_UNLISTED_PATH` (NSS may refuse earlier). Use
`deploy-kit validate` for the resolved public staging descriptor/config, then
the unit's own post-install preflights as its service user. There is no unsigned
staging mode or alternate native reader.

The relay's Caddy TLS front and certificate/key custody are outside DK5
(`templates/relay/Caddyfile.in`); Infra qualifies those separately.

Payload has no standalone systemd unit and no shared readable payload group.
For static CA/model assets, Infra provisions an exclusive slot group and a
root:root0644 anchor at `/etc/swarma/payload-anchors/<numeric EUID>/10-install.conf`
in root:root0755 ancestry, bound to service `payload` and the slot's effective
GID. The assets/manifest use root:exclusive-slot-group0640/0644 and0750 parents.
Dynamic bootstrap and slotd launch enforcement are DK5b, a separate gate before
outside testers. Static DK5 checks do not qualify those dynamic boundaries.

## Refusal and evidence

`DK5_FILE_MODE`, `DK5_DIRECTORY_MODE`, `DK5_FILE_OWNER`, `DK5_FILE_GROUP`,
`DK5_DIRECTORY_OWNER`, `DK5_DIRECTORY_GROUP`, `DK5_ANCESTOR_MODE`,
`DK5_FILE_KIND`, `DK5_FILE_LINKS`, `DK5_FILE_SIZE`, `DK5_FILE_CHANGED`,
`DK5_FILE_OPEN`, `DK5_DIRECTORY_OPEN`, `DK5_SERVICE_IDENTITY`, `DK5_PATH` cover
metadata/admission. Anchors/signatures use `DK5_ANCHOR_FILE`, `DK5_ANCHOR_SCHEMA`,
`DK5_MANIFEST_READ`, `DK5_MANIFEST_HASH`, `DK5_MANIFEST_SCHEMA`,
`DK5_MANIFEST_BINDING`, `DK5_MANIFEST_PATH`, `DK5_UNLISTED_PATH`,
`DK5_CONTENT_HASH`, `DK5_SIGNATURE_FILE`, `DK5_SIGNATURE_SCHEMA`,
`DK5_SIGNATURE_KEY`, `DK5_SIGNATURE_ALGORITHM`, `DK5_SIGNATURE_INVALID`.
Native parsing/pinning errors remain distinct after installed admission.

Tests use explicitly synthetic ownership/identity/NSS and task-owned traversal
roots, real modes/descriptors/crypto and throwaway scratch keys. Native-loader
tests cover file/parent admission. Configguard fixtures cover real ancestor
modes and the composed ServiceSet, ReadService and subprocess CheckMain paths.
Native production traversal always starts at `/`; source guards forbid consumer
use of the unsigned Reader/Native/Read/OpenSignedSet surface. No local test is
proof of Linux NSS/ACLs/systemd ownership, real custody or a deployed service.
Infra must run positive startup plus changed-file, absent-signature, wrong-key,
unlisted-path and peer-access refusals in its authorized disposable install
fixture, preserving state and checking no listener or journal change on refusal.
Historical opt-in Core scenarios with owner0600 configs are not DK5 installation
qualification; they require separately provisioned installed fixtures. Never
weaken production checks or label skipped scenarios as passing host evidence.

## Admission before final-path installation

A root provisioner can validate approved, custody-checked staged bytes with
[configguard.ValidateStagedSet](../experiments/single-use/configguard/STAGED.md),
using independent expected final paths, release digest, service and GID. This
pure API verifies the original signature and content without opening final paths,
rewriting signed material or using synthetic metadata. It does not prove source
custody or implement transactional installation. Retain the verified byte snapshot
under root custody, then preserve the existing installed admission checks.
