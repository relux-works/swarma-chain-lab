# Gateway Linux pre-releases (test profile)

The [workflow](../.github/workflows/release.yml) produces a **PRE-RELEASE draft**
for one product, **gateway**, with purpose **`platform-root`**: the two target
archives `gateway_linux_amd64.tar.gz` and `gateway_linux_arm64.tar.gz`, `SHA256SUMS`,
`provenance.json` and the canonical `release-set.json` fragment. The optional
bot checksum signature is labelled exactly:

> agent-held key, proves nothing about origin

The bot key is available to agents. Neither that key, a tag signature, nor a
checksum signature establishes product origin or release authority. Installer v0
trusts **only the digest of the aggregate release-set manifest**, listing every
artifact digest. The owner approves that one digest **in person before any root
step** (OD-3 plan digest). Two independent reads of each release PR must compare
artifact digests with a second independent build before assembling that set.
The helper below supplies a rebuild comparison, not either review verdict or the
owner's approval. A dedicated release key outside agent sessions remains an
owner key-custody decision (OD-2).

## Book and specification boundary

The Swarma installation book's
[Trust: signatures, manifest, notarization, package channels](https://github.com/relux-works/swarma-docs/blob/main/install-book/ru/04-doverie.md)
chapter describes component signers and a manifest selecting artifact digests.
**Same:** artifact digests belong in the release-set manifest.
**Conflict resolved by the binding interim test-profile ruling:** the shared bot
key cannot supply the book's component trust root; use the owner's in-person
approval of the aggregate set digest until dedicated custody is decided. This
interim profile does not implement the book's future update-key roles.
The gateway service contract in `docs/gateway-service.md` (introduced by
[service PR #159](https://github.com/relux-works/swarma-chain-lab/pull/159))
requires separate runtime integration and qualification. Packaging the existing
`model-proxy` daemon under the product member name does not wire the service
client into it, qualify managed mode, or activate a service. The template reuses
the broker A3 release policy at commit `b72677f54ca40c896a26908782799c666179ee62`;
owner decision 2(a) authorizes this per-product port.

## Default-branch workflow and admission

GitHub loads a tag-push workflow from the tag itself. This template therefore
has **no tag-push trigger**. After pushing a tag, an authorized operator dispatches
`release.yml` **on main**, passing the tag as data. Both jobs require the dispatch
ref and repository default branch to be `main`; both check out `main` with full
history. The draft job requires the identical policy commit used by the build.
If the repository renames its default branch, revise this contract first.

```bash
# After the release controls have landed on main:
git tag -s gateway/v1.2.3 -m 'Test pre-release gateway/v1.2.3'
git push origin refs/tags/gateway/v1.2.3
gh workflow run release.yml --ref main -f tag=gateway/v1.2.3
```

Configure a repository **gateway/v* tag ruleset** restricting creation, update and deletion
to the authorized release role. Check that setting when adopting this template;
the workflow cannot establish that external setting. Repository workflow/ruleset
administration remains an owner boundary. An independently modified workflow on
a malicious tag is not an execution authority for this main-dispatched flow.
GitHub writers can still create arbitrary release records; the independent build
and owner-approved aggregate digest remain necessary.

[release-admit.sh](../.scripts/release-admit.sh) resolves its policy root from its
own location, requires that checkout at `origin/main`, and refuses local changes
in `.scripts`, `.github/release` or `.github/workflows/release.yml`. It requires:

- An ASCII `gateway/vX.Y.Z` tag name with three nonempty decimal components.
  Existing module and deploy-kit tag namespaces are not admitted or modified.
- An annotated SSH-signed tag directly targeting a commit, with the internal
  tag name equal to the requested name; lightweight and unsigned tags fail.
- The commit to be an ancestor of `origin/main`. Shallow history and grafts fail;
  replacement objects are ignored. An ancestor can be released, so there is no
  rollback protection.
- The tagged tree's entire `.scripts`, `.github/release` and release workflow
  content/modes to equal the default branch. This intentionally refuses older
  tags whose release controls differ, including a changed admission script or
  allowlist. No script from the tagged tree is executed to admit or build it.
- The tag object and commit to match supplied bindings when present.
- SSH verification using **main's** [allowed_signers](../.github/release/allowed_signers),
  without ambient GPG fallback. This file is **only for TAG verification as a
  consistency check**, under principal `release-tag`, namespace `git`; it is
  **not a trust root**. It is never used to authenticate checksum files.

All actions use full SHA pins. Build has `contents: read`; only draft creation
has `contents: write`. Checkout does not persist credentials. No CI signing key,
OIDC or external signer is configured. Draft creation uses the automatic
`github.token`, not an operator key. Immediately before creation the job rechecks
remote main and tag objects, repeats main's admission and validates the artifact
set. Existing releases are refused; assets are never overwritten. GitHub cannot
atomically bind release creation to ref movement; operator rechecks and the
aggregate owner approval remain required.

## Reproducible build and metadata

[release-build.sh](../.scripts/release-build.sh) requires Go **1.26.8** and a clean
source checkout. Its optional second argument is an absolute source checkout;
the executable builder and metadata helper remain in the default-branch checkout.
Only the command named in main's
[input table](../.github/release/gateway-inputs.json) is built for amd64 and arm64
with `CGO_ENABLED=0`,
`-mod=readonly -p=2 -trimpath -buildvcs=false -ldflags=-buildid=`, `GOAMD64=v1`,
`GOARM64=v8.0`, empty `GOEXPERIMENT`, `GOTOOLCHAIN=local`, `GOWORK=off`,
`GOENV=off`, `LC_ALL=C` and `TZ=UTC`. Modules are pinned by `go.mod`/`go.sum`.
`SOURCE_DATE_EPOCH` is the tag commit's committer timestamp, recorded as an input;
Go does not use it to normalize binaries. Missing inputs, symlinked input
ancestry, unsafe paths, duplicate archive members and widened input inventories
fail. The table is policy; it is never loaded from the tagged source tree.

The table lists exactly one Go command, its module/package, archive member and
mode, plus the unit template and service document. It is the single build-input
inventory. The daemon is `experiments/model-proxy` package `./cmd/model-proxy`;
its archive member is `credential-gateway/bin/credential-gateway` (0755). The
unit source is `experiments/model-proxy/deploy/credential-gateway.service.in`,
placed at `credential-gateway/templates/credential-gateway.service.in` (0644).
`docs/gateway-service.md` is placed at
`credential-gateway/docs/gateway-service.md` (0644). Directories are 0755.

The unit and document are pending service PR #159. Until they land, builds from
main deliberately refuse `missing-input` before creating output. Scratch controls
use a committed fixture tree with those exact paths; this is packaging evidence,
not a claim that the service inputs or runtime have landed. Do not substitute the
deploy kit's unrelated gateway template or relax the input list.

Archives use sorted USTAR entries, commit-time mtime, uid/gid zero, empty owner
names, fixed directory/file modes, and gzip level 9 with zero mtime and no source
filename. No source mtimes, ownership, umask, absolute paths or wall clock enter
the archive. The deploy kit is separate: `deploy/release.go`, its Go 1.26.8 pin,
artifact inventory and release tests are unchanged.

`provenance.json` records the source commit, Go version, flags, environment and
`SOURCE_DATE_EPOCH`, the complete product input table and archive normalization.
It describes build inputs; it is not an origin attestation.
`SHA256SUMS` covers both gateway archives and provenance. `release-set.json` lists the
name and SHA-256 of each archive, provenance and `SHA256SUMS` for incorporation
into the installer's aggregate release-set manifest. Each archive row carries
`"purpose":"platform-root"`; the metadata rows do not describe installable products. The fragment cannot hash
itself; optional `SHA256SUMS.sig` is ancillary consistency evidence and is not an
installer input. JSON uses sorted object keys, sorted artifact names, ASCII,
compact separators and exactly one trailing newline. Example shape:

```json
{"artifacts":[{"name":"gateway_linux_amd64.tar.gz","purpose":"platform-root","sha256":"<64 lowercase hex>"}],"schema":"release-set-fragment/1"}
```

The fragment is an interchange fragment, not a claim that an installer schema
has been implemented here. The aggregate must preserve every included digest.

For local checks, use two independent physical source checkouts at the same
commit and toolchain. Resolve absolute scratch paths before launching Go; set
`HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `TMPDIR`, `TMP`, `TEMP`,
`GOCACHE`, `GOMODCACHE` and `GOPATH` inside each owned scratch root, and unset
`GOTELEMETRYDIR`. The workflow and operator helper do this automatically.
From a trusted default-branch checkout:

```bash
GO=/absolute/path/to/go1.26.8/bin/go .scripts/release-build.sh \
  /absolute/scratch/dist /absolute/scratch/source
cmp /absolute/first/dist/SHA256SUMS /absolute/second/dist/SHA256SUMS
cmp /absolute/first/dist/release-set.json /absolute/second/dist/release-set.json
```

The output directory must not exist. Matching hashes prove reproducibility for
that pair of builds, source and environment; they do not establish origin.

## Independent operator rebuild and optional bot signature

Use the trusted current-main checkout, not a downloaded script or the tag tree.
The operator's GitHub CLI needs release-write access. The helper fetches main
and the requested tag without forcing a moved tag, then runs main's admission.
It requires a draft marked pre-release and the exact bot-key label in its body.

```bash
GO=/absolute/path/to/go1.26.8/bin/go .scripts/release-sign.sh gateway/v1.2.3
# Optional repository argument when adopting the template:
GO=/absolute/path/to/go1.26.8/bin/go .scripts/release-sign.sh gateway/v1.2.3 OWNER/REPO
```

[release-sign.sh](../.scripts/release-sign.sh) copies the admitted tag to a fresh
source checkout and independently rebuilds under `.temp/release-sign.*`, with
fresh absolute home/config/cache/temp paths. It compares the local canonical
`SHA256SUMS`, provenance and fragment byte for byte with the pre-release. **Any
mismatch refuses before signature creation or upload.** This compares every
artifact digest with a second build, rather than signing arbitrary downloaded
checksums. It then rechecks admission, remote tag/main and draft state, signs
**the local rebuilt** `SHA256SUMS` using `git config user.signingkey`, uploads
without clobbering, and verifies byte-identical readback of the signature and
metadata. The signature is ancillary; the tag-only allowlist is not consulted
for checksum verification. The helper does not publish or approve a release.
Evidence is retained. Concurrent external publication cannot be prevented by
these CLI checks.

After both required release PR reads compare independent build digests, assemble
the aggregate release-set manifest and obtain the owner's in-person approval of
its digest before any root step. Publishing the pre-release is an explicit
operator action; retain the pre-release flag:

```bash
gh release edit gateway/v1.2.3 --repo relux-works/swarma-chain-lab \
  --draft=false --prerelease
```

## Artifact consistency check

Download both archives and all metadata into a fresh directory. Use a separately
obtained expected **fragment** digest from the reviewed aggregate manifest:

```bash
.scripts/release-verify.sh /absolute/assets EXPECTED_FRAGMENT_SHA256
```

[release-verify.sh](../.scripts/release-verify.sh) and
[release-metadata.py](../.scripts/release-metadata.py) check the supplied fragment
digest, canonical fragment/list, each artifact digest, mandatory provenance and
target archive entries. Both architectures are mandatory. Traversal, duplicate entries and symlinked artifacts fail.
This establishes consistency with the supplied digest, not origin, freshness,
owner approval or runtime qualification. Fetching the expected digest from the
same release supplies no independent approval. The installer must verify the
owner-approved **aggregate** digest and its entire selected artifact set.

## Controls and adoption

```bash
actionlint .github/workflows/release.yml  # If installed; otherwise report missing.
for script in .scripts/release-*.sh; do bash -n "$script" || exit; done
GO=/absolute/path/to/go1.26.8/bin/go .scripts/release-test.sh /absolute/new/scratch
```

The scratch test owns its empty home/config/caches, Git repositories and ephemeral
keys, with ambient signing config and SSH agent disabled. Real Git/SSH objects
exercise main/ancestor admission and lightweight, unsigned, inconsistent,
tampered, renamed, off-main, binding and dirty-policy refusals. On-main ancestor
tags that replace admission or its allowlist must fail beside a valid tag.
Real Go builds exercise reproducibility, canonical metadata, changed artifacts,
traversal, duplicates and symlinks. A local GitHub CLI double exercises off-main,
mismatched-digest, missing-label and non-prerelease refusals, plus rebuild/sign,
readback and no-overwrite controls. This is not hosted workflow evidence.
No credential, service activation or live release API is touched by the tests.

When copying the template, include `.scripts/release-*` (including the Python 3
metadata helper), `.github/release/gateway-inputs.json`, workflow and docs. Change the repository default in the signing
helper, install the public **tag consistency** pin, verify the gateway/v* tag ruleset,
land controls on main, and run scratch controls plus two independent full builds.
Preserve the interim owner-approved aggregate trust boundary. Dedicated key
custody and runtime qualification remain separate owner gates.
