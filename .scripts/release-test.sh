#!/usr/bin/env bash
# Scratch controls use real Git, SSH and Go; GitHub is an explicit local double.
set -euo pipefail
export LC_ALL=C
fail() { printf 'release controls: %s\n' "$1" >&2; exit 1; }
[[ $# == 1 && $1 == /* ]] || fail absolute-fresh-scratch-directory-required
source_root=$(cd "$(dirname "$0")/.." && pwd -P)
go_bin=$(command -v "${GO:-go}")
mkdir "$1"
scratch=$(cd "$1" && pwd -P)
mkdir -p "$scratch"/{home,config,cache,tmp,go-build,go-mod,go-path,bin,work}
export HOME="$scratch/home" USERPROFILE="$scratch/home"
export XDG_CONFIG_HOME="$scratch/config" XDG_CACHE_HOME="$scratch/cache"
export TMPDIR="$scratch/tmp" TMP="$scratch/tmp" TEMP="$scratch/tmp" GOTMPDIR="$scratch/tmp"
export GOCACHE="$scratch/go-build" GOMODCACHE="$scratch/go-mod" GOPATH="$scratch/go-path"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GO="$go_bin" GOTOOLCHAIN=local GOENV=off GOWORK=off GOTELEMETRY=off
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
unset SSH_AUTH_SOCK GOTELEMETRYDIR GH_TOKEN GITHUB_TOKEN RELEASE_TAG_OBJECT RELEASE_COMMIT
ssh-keygen -q -t ed25519 -N '' -C '' -f "$scratch/key"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$scratch/other-key"
cd "$scratch/work"
git init -q -b main
git config user.name 'Release fixture'
git config user.email 'release-fixture@example.invalid'
git config gpg.format ssh
git config user.signingkey "$scratch/key"
git config commit.gpgsign true
git config tag.gpgsign true
mkdir -p .github/release .github/workflows .scripts experiments/model-proxy/cmd/model-proxy experiments/model-proxy/deploy docs
read -r kind public_key _ < "$scratch/key.pub"
printf 'release-tag namespaces="git" %s %s\n' "$kind" "$public_key" > .github/release/allowed_signers
cp "$source_root"/.scripts/release-* .scripts/
cp "$source_root/.github/workflows/release.yml" .github/workflows/
cp "$source_root/.github/release/gateway-inputs.json" .github/release/
printf 'module example.invalid/releasefixture\n\ngo 1.25\n' > experiments/model-proxy/go.mod
printf 'package main\nfunc main() { println("inert release fixture") }\n' > experiments/model-proxy/cmd/model-proxy/main.go
printf '[Service]\nExecStart=@PLATFORM_ROOT@/credential-gateway/bin/credential-gateway\n' > experiments/model-proxy/deploy/credential-gateway.service.in
printf '# Inert gateway service fixture\n' > docs/gateway-service.md
printf 'main fixture\n' > content
git add .
git commit -q -S -m 'Create isolated release fixture'
base=$(git rev-parse HEAD)
git tag -s gateway/v1.0.0 -m 'Valid release control'
git tag -s gateway/v1.0.6 refs/tags/gateway/v1.0.0 -m 'Nested tag control' 2> "$scratch/nested-tag-create.log"
git tag --no-sign gateway/v1.0.1
git tag --no-sign -a gateway/v1.0.2 -m 'Unsigned annotated control'
git -c "user.signingkey=$scratch/other-key" tag -s gateway/v1.0.3 -m 'Inconsistent signer control'
git tag -s gateway/v1.0.4 -m 'Original tag payload'
git cat-file tag refs/tags/gateway/v1.0.4 > "$scratch/original-tag"
sed 's/Original tag payload/Changed tag payload/' "$scratch/original-tag" > "$scratch/tampered-tag"
tampered=$(git hash-object -t tag -w "$scratch/tampered-tag")
git update-ref refs/tags/gateway/v1.0.4 "$tampered"
git update-ref refs/tags/gateway/v1.0.5 refs/tags/gateway/v1.0.0

# R1 witnesses: both malicious trees are main ancestors, but cannot select policy.
printf '#!/usr/bin/env bash\nexit 0\n' > .scripts/release-admit.sh
git add .scripts/release-admit.sh
git commit -q -S -m 'Fixture tag edits admission'
git tag -s gateway/v1.1.0 -m 'Admission replacement control'
git restore --source="$base" -- .scripts/release-admit.sh
read -r kind other_public _ < "$scratch/other-key.pub"
printf 'release-tag namespaces="git" %s %s\n' "$kind" "$other_public" > .github/release/allowed_signers
git add .scripts/release-admit.sh .github/release/allowed_signers
git commit -q -S -m 'Fixture tag edits signer policy'
git -c "user.signingkey=$scratch/other-key" tag -s gateway/v1.2.0 -m 'Allowlist replacement control'
git restore --source="$base" -- .github/release/allowed_signers
git add .github/release/allowed_signers
git commit -q -S -m 'Restore default-branch policy'
printf '{"product":"widened"}\n' > .github/release/gateway-inputs.json
git add .github/release/gateway-inputs.json
git commit -q -S -m 'Fixture tag edits product inputs'
git tag -s gateway/v1.3.0 -m 'Product input replacement control'
git restore --source="$base" -- .github/release/gateway-inputs.json
git add .github/release/gateway-inputs.json
git commit -q -S -m 'Restore default-branch product inputs'
git update-ref refs/remotes/origin/main HEAD
main=$(git rev-parse HEAD)
git switch -q -c side
printf 'side fixture\n' >> content
git add content
git commit -q -S -m 'Isolated off-main fixture'
git tag -s gateway/v2.0.0 -m 'Signed off-main control'
git switch -q main
git clone --quiet --bare . "$scratch/origin.git"
git remote add origin "$scratch/origin.git"

expect_ok() {
  local name=$1
  shift
  if "$@" > "$scratch/$name.log" 2>&1; then
    printf 'PASS %s (exit 0)\n' "$name"
  else
    local status=$?
    cat "$scratch/$name.log" >&2
    fail "$name: unexpected exit $status"
  fi
}
expect_refusal() {
  local name=$1 reason=$2
  shift 2
  if "$@" > "$scratch/$name.log" 2>&1; then
    fail "$name: unexpected acceptance"
  else
    local status=$?
    [[ $status == 1 ]] || fail "$name: unexpected exit $status"
    grep -F -- "$reason" "$scratch/$name.log" > /dev/null || fail "$name: wrong refusal"
    printf 'PASS %s (expected refusal exit %s: %s)\n' "$name" "$status" "$reason"
  fi
}
admit="$scratch/work/.scripts/release-admit.sh"
verify="$scratch/work/.scripts/release-verify.sh"
sign="$scratch/work/.scripts/release-sign.sh"

# Real signed objects prove each distinct admission refusal beside a valid ancestor.
expect_refusal legacy_tag_namespace invalid-tag "$admit" v1.0.0
expect_refusal malformed_gateway_version invalid-tag "$admit" gateway/v1.0
expect_ok ancestor_tag_on_main "$admit" gateway/v1.0.0
expect_refusal lightweight_tag annotated-tag-required "$admit" gateway/v1.0.1
expect_refusal unsigned_tag ssh-signature-required "$admit" gateway/v1.0.2
expect_refusal untrusted_tag inconsistent-tag-signature "$admit" gateway/v1.0.3
expect_refusal tampered_tag inconsistent-tag-signature "$admit" gateway/v1.0.4
expect_refusal renamed_tag tag-name-mismatch "$admit" gateway/v1.0.5
expect_refusal nested_tag direct-commit-required "$admit" gateway/v1.0.6
expect_refusal mismatched_event_object tag-object-mismatch env RELEASE_TAG_OBJECT="$base" "$admit" gateway/v1.0.0
expect_refusal mismatched_event_commit commit-mismatch env RELEASE_COMMIT=invalid "$admit" gateway/v1.0.0
expect_refusal signed_off_main commit-not-on-main "$admit" gateway/v2.0.0
expect_refusal tagged_admission_edit tagged-release-policy-differs "$admit" gateway/v1.1.0
expect_refusal tagged_allowlist_edit tagged-release-policy-differs "$admit" gateway/v1.2.0
expect_refusal tagged_input_table_edit tagged-release-policy-differs "$admit" gateway/v1.3.0
expect_ok signed_tag_on_main "$admit" gateway/v1.0.0
git switch -q --detach "$base"
expect_refusal wrong_checkout default-checkout-required "$admit" gateway/v1.0.0
git switch -q main
printf '\n# local policy drift\n' >> .scripts/release-admit.sh
expect_refusal dirty_policy dirty-release-policy "$admit" gateway/v1.0.0
git restore --source="$main" -- .scripts/release-admit.sh

# Real Go build of an inert fixture; every digest/metadata control uses its output.
git clone --quiet --no-local --no-checkout . "$scratch/build-source"
git -C "$scratch/build-source" checkout --quiet --detach "$base"
printf 'untracked source\n' > "$scratch/build-source/untracked.go"
expect_refusal dirty_build_source dirty-build-source .scripts/release-build.sh "$scratch/refused-dist" "$scratch/build-source"
[[ ! -e $scratch/refused-dist ]] || fail dirty-source-partial-output
rm "$scratch/build-source/untracked.go"
expect_ok fixture_build .scripts/release-build.sh "$scratch/assets" "$scratch/build-source"
# Claim: the single product has exactly the independent member inventory, target
# ELF machines, verbatim service inputs, and normalized tar/gzip metadata.
gateway_archive_layout() {
  python3 - "$scratch" <<'ARCHIVE'
import json
import pathlib
import struct
import sys
import tarfile
root = pathlib.Path(sys.argv[1])
files = {
    "credential-gateway/bin/credential-gateway": 0o755,
    "credential-gateway/templates/credential-gateway.service.in": 0o644,
    "credential-gateway/docs/gateway-service.md": 0o644,
}
directories = {str(p) for n in files for p in pathlib.PurePosixPath(n).parents if str(p) != "."}
expected = sorted(set(files) | directories)
provenance = json.loads((root / "assets/provenance.json").read_bytes())
assert provenance["product"]["product"] == "gateway"
assert provenance["product"]["purpose"] == "platform-root"
for arch, machine in (("amd64", 62), ("arm64", 183)):
    path = root / f"assets/gateway_linux_{arch}.tar.gz"
    header = path.read_bytes()[:10]
    assert header[:4] == b"\x1f\x8b\x08\x00" and header[4:8] == bytes(4)
    with tarfile.open(path) as archive:
        assert archive.getnames() == expected, "archive-inventory-or-order"
        for member in archive:
            assert member.mtime == provenance["SOURCE_DATE_EPOCH"], "archive-mtime"
            assert (member.uid, member.gid, member.uname, member.gname) == (0, 0, "", ""), "archive-owner"
            assert member.mode == files.get(member.name, 0o755), "archive-mode"
            assert not member.pax_headers
            if member.name in directories:
                assert member.isdir()
            else:
                assert member.isfile()
        binary = archive.extractfile("credential-gateway/bin/credential-gateway").read()
        assert binary[:4] == b"\x7fELF" and struct.unpack_from("<H", binary, 18)[0] == machine
        for source, member in (
            ("experiments/model-proxy/deploy/credential-gateway.service.in", "credential-gateway/templates/credential-gateway.service.in"),
            ("docs/gateway-service.md", "credential-gateway/docs/gateway-service.md"),
        ):
            assert archive.extractfile(member).read() == (root / "build-source" / source).read_bytes()
fragment = json.loads((root / "assets/release-set.json").read_bytes())
products = [row for row in fragment["artifacts"] if "purpose" in row]
assert {row["name"] for row in products} == {f"gateway_linux_{a}.tar.gz" for a in ("amd64", "arm64")}
assert all(row["purpose"] == "platform-root" for row in products)
print("Gateway archive inventory, ELF targets, exact service bytes, purpose and normalized headers: OK")
ARCHIVE
}
expect_ok gateway_archive_layout gateway_archive_layout

# Bounded controls prove the layout checker catches each claimed archive
# property. These mutate fixture archive bytes, not production source code.
cp "$scratch/assets/gateway_linux_amd64.tar.gz" "$scratch/original-archive"
for mutation in mtime owner mode order inventory; do
  python3 - "$scratch" "$mutation" <<'MUTATE'
import gzip
import io
import pathlib
import sys
import tarfile
root, mutation = pathlib.Path(sys.argv[1]), sys.argv[2]
with tarfile.open(root / "original-archive") as source:
    members = [(info, source.extractfile(info).read() if info.isfile() else None) for info in source]
for info, data in members:
    if info.name == "credential-gateway/bin/credential-gateway":
        if mutation == "mtime": info.mtime += 1
        if mutation == "owner": info.uid = 1
        if mutation == "mode": info.mode = 0o644
if mutation == "order": members.reverse()
if mutation == "inventory": members = [(i, d) for i, d in members if i.name != "credential-gateway/docs/gateway-service.md"]
with (root / "assets/gateway_linux_amd64.tar.gz").open("wb") as raw:
    with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as target:
            for info, data in members:
                target.addfile(info, io.BytesIO(data) if data is not None else None)
MUTATE
  reason="archive-$mutation"
  [[ $mutation != order && $mutation != inventory ]] || reason=archive-inventory-or-order
  expect_refusal "archive_${mutation}_plant" "$reason" gateway_archive_layout
  cp "$scratch/original-archive" "$scratch/assets/gateway_linux_amd64.tar.gz"
done
expect_ok restored_gateway_archive_layout gateway_archive_layout

# Claim: absent or symlinked service inputs refuse before output creation;
# each source state is committed, so dirty-source refusal cannot mask the gate.
fixture_source_commit() {
  git -C "$scratch/build-source" -c user.name='Release fixture' \
    -c user.email=release-fixture@example.invalid -c gpg.format=ssh \
    -c "user.signingkey=$scratch/key" commit -q -S -am "$1"
}
for input in docs/gateway-service.md experiments/model-proxy/deploy/credential-gateway.service.in; do
  git -C "$scratch/build-source" rm -q "$input"
  fixture_source_commit 'Remove required service fixture'
  expect_refusal "missing_${input##*/}" missing-input .scripts/release-build.sh "$scratch/missing-input-dist" "$scratch/build-source"
  [[ ! -e $scratch/missing-input-dist ]] || fail missing-input-partial-output
  git -C "$scratch/build-source" checkout --quiet --detach "$base"
done
rm "$scratch/build-source/docs/gateway-service.md"
ln -s ../content "$scratch/build-source/docs/gateway-service.md"
git -C "$scratch/build-source" add docs/gateway-service.md
fixture_source_commit 'Symlink required service fixture'
expect_refusal symlinked_service_input symlinked-input .scripts/release-build.sh "$scratch/symlink-input-dist" "$scratch/build-source"
[[ ! -e $scratch/symlink-input-dist ]] || fail symlink-input-partial-output
git -C "$scratch/build-source" checkout --quiet --detach "$base"

# Claim: the policy table cannot select traversal or duplicate archive members.
python3 - <<'TABLE'
import json
import pathlib
path = pathlib.Path(".github/release/gateway-inputs.json")
value = json.loads(path.read_text())
value["inputs"][1]["source"] = "../outside"
path.write_text(json.dumps(value))
TABLE
expect_refusal table_traversal invalid-input-path python3 .scripts/release-metadata.py inputs "$scratch/build-source"
git restore --source="$main" -- .github/release/gateway-inputs.json
python3 - <<'TABLE'
import json
import pathlib
path = pathlib.Path(".github/release/gateway-inputs.json")
value = json.loads(path.read_text())
value["inputs"][2]["member"] = value["inputs"][1]["member"]
path.write_text(json.dumps(value))
TABLE
expect_refusal duplicate_table_member invalid-input-inventory python3 .scripts/release-metadata.py inputs "$scratch/build-source"
git restore --source="$main" -- .github/release/gateway-inputs.json

fragment=$(sha256sum "$scratch/assets/release-set.json")
fragment=${fragment%% *}
expect_ok digest_control "$verify" "$scratch/assets" "$fragment"
printf 'changed\n' >> "$scratch/assets/gateway_linux_amd64.tar.gz"
expect_refusal changed_binary artifact-digest-mismatch "$verify" "$scratch/assets" "$fragment"
# Restore a single owned fixture artifact by rebuilding it, without replacing policy.
rm "$scratch/assets/gateway_linux_amd64.tar.gz"
# A separate directory also proves deterministic Go outputs and metadata.
git clone --quiet --no-local --no-checkout . "$scratch/second-source"
git -C "$scratch/second-source" checkout --quiet --detach "$base"
fixture_second_build() (
  umask 077
  chmod 0600 "$scratch/second-source/docs/gateway-service.md"
  touch -t 200101010101 "$scratch/second-source/docs/gateway-service.md"
  .scripts/release-build.sh "$scratch/second" "$scratch/second-source"
)
expect_ok fixture_second_build fixture_second_build
cp "$scratch/second/gateway_linux_amd64.tar.gz" "$scratch/assets/gateway_linux_amd64.tar.gz"
expect_ok fixture_reproducibility cmp "$scratch/assets/SHA256SUMS" "$scratch/second/SHA256SUMS"
expect_ok metadata_reproducibility cmp "$scratch/assets/release-set.json" "$scratch/second/release-set.json"
cp "$scratch/assets/SHA256SUMS" "$scratch/original-sums"
cp "$scratch/assets/release-set.json" "$scratch/original-fragment"
printf '%064d  ../escape_linux_amd64\n' 0 > "$scratch/assets/SHA256SUMS"
expect_refusal path_entry invalid-checksum-entry "$verify" "$scratch/assets" "$fragment"
cat "$scratch/original-sums" "$scratch/original-sums" > "$scratch/assets/SHA256SUMS"
expect_refusal duplicate_entry duplicate-checksum-entry "$verify" "$scratch/assets" "$fragment"
cp "$scratch/original-sums" "$scratch/assets/SHA256SUMS"
# Claim: both target archives are mandatory even when remaining hashes match.
grep -v 'gateway_linux_arm64.tar.gz' "$scratch/original-sums" > "$scratch/assets/SHA256SUMS"
expect_refusal missing_target_archive incomplete-manifest "$verify" "$scratch/assets" "$fragment"
cp "$scratch/original-sums" "$scratch/assets/SHA256SUMS"
mv "$scratch/assets/gateway_linux_amd64.tar.gz" "$scratch/binary"
ln -s "$scratch/binary" "$scratch/assets/gateway_linux_amd64.tar.gz"
expect_refusal symlinked_binary missing-or-symlinked-artifact "$verify" "$scratch/assets" "$fragment"
rm "$scratch/assets/gateway_linux_amd64.tar.gz"
cp "$scratch/binary" "$scratch/assets/gateway_linux_amd64.tar.gz"
printf ' ' >> "$scratch/assets/release-set.json"
expect_refusal changed_fragment fragment-digest-mismatch "$verify" "$scratch/assets" "$fragment"
noncanonical=$(sha256sum "$scratch/assets/release-set.json")
expect_refusal noncanonical_fragment release-set-mismatch-or-noncanonical "$verify" "$scratch/assets" "${noncanonical%% *}"
cp "$scratch/original-fragment" "$scratch/assets/release-set.json"
mv "$scratch/assets/provenance.json" "$scratch/provenance"
expect_refusal missing_provenance missing-or-symlinked-artifact "$verify" "$scratch/assets" "$fragment"
mv "$scratch/provenance" "$scratch/assets/provenance.json"
mv "$scratch/assets/SHA256SUMS" "$scratch/sums"
ln -s "$scratch/sums" "$scratch/assets/SHA256SUMS"
expect_refusal symlinked_manifest missing-or-symlinked-artifact "$verify" "$scratch/assets" "$fragment"
rm "$scratch/assets/SHA256SUMS"
mv "$scratch/sums" "$scratch/assets/SHA256SUMS"
expect_ok restored_digest_control "$verify" "$scratch/assets" "$fragment"

# This GitHub double bounds CLI sequencing, not hosted-release behavior.
cat > "$scratch/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$GH_FIXTURE/calls"
[[ $1 == release ]]
case $2 in
  view)
    printf '42\t%s\t%s\t%s\t%s\n' "${GH_FIXTURE_DRAFT:-true}" "${GH_FIXTURE_PRERELEASE:-true}" "$3" "${GH_FIXTURE_LABEL:-true}"
    ;;
  download)
    shift 3
    patterns=()
    while [[ $# -gt 0 ]]; do
      case $1 in
        --repo) shift 2 ;;
        --pattern) patterns+=("$2"); shift 2 ;;
        --dir) destination=$2; shift 2 ;;
        *) exit 70 ;;
      esac
    done
    for name in "${patterns[@]}"; do cp "$GH_FIXTURE/$name" "$destination/$name"; done
    ;;
  upload)
    [[ $# == 6 && $5 == --repo ]]
    if [[ -e $GH_FIXTURE/SHA256SUMS.sig ]]; then
      printf 'existing-asset\n' >&2
      exit 1
    fi
    [[ $4 == */dist/SHA256SUMS.sig ]] || exit 70
    cp "$4" "$GH_FIXTURE/SHA256SUMS.sig"
    ;;
  *) exit 70 ;;
esac
GH
chmod +x "$scratch/bin/gh"
export PATH="$scratch/bin:$PATH" GH_FIXTURE="$scratch/draft"
mkdir "$GH_FIXTURE"
cp "$scratch/assets"/{SHA256SUMS,provenance.json,release-set.json} "$GH_FIXTURE/"
cd "$scratch/work"
# Rejection must occur before any signature/upload; nearby successful build signs.
expect_refusal operator_off_main commit-not-on-main "$sign" gateway/v2.0.0
[[ ! -e $GH_FIXTURE/calls && ! -e $GH_FIXTURE/SHA256SUMS.sig ]] || fail off-main-side-effects
expect_refusal published_release labelled-prerelease-draft-required env GH_FIXTURE_DRAFT=false "$sign" gateway/v1.0.0
expect_refusal non_prerelease labelled-prerelease-draft-required env GH_FIXTURE_PRERELEASE=false "$sign" gateway/v1.0.0
expect_refusal missing_label labelled-prerelease-draft-required env GH_FIXTURE_LABEL=false "$sign" gateway/v1.0.0
printf '%064d  gateway_linux_amd64.tar.gz\n' 0 > "$GH_FIXTURE/SHA256SUMS"
expect_refusal mismatched_draft rebuild-digest-mismatch "$sign" gateway/v1.0.0
[[ ! -e $GH_FIXTURE/SHA256SUMS.sig ]] || fail mismatch-uploaded-signature
[[ ! -e $(find .temp -path '*/dist/SHA256SUMS.sig' -print -quit) ]] || fail mismatch-created-signature
cp "$scratch/original-sums" "$GH_FIXTURE/SHA256SUMS"
expect_ok draft_local_signing "$sign" gateway/v1.0.0
cp "$GH_FIXTURE/SHA256SUMS.sig" "$scratch/uploaded-signature"
# Check the exact local file bytes with the fixture key, independently of the helper.
printf 'fixture namespaces="file" %s %s\n' "$kind" "$public_key" > "$scratch/fixture-file-signers"
expect_ok rebuilt_signature ssh-keygen -Y verify -f "$scratch/fixture-file-signers" \
  -I fixture -n file -s "$GH_FIXTURE/SHA256SUMS.sig" < "$scratch/original-sums"
expect_refusal existing_signature existing-asset "$sign" gateway/v1.0.0
expect_ok no_signature_overwrite cmp "$scratch/uploaded-signature" "$GH_FIXTURE/SHA256SUMS.sig"
# Finite template assertions cover the reviewed workflow contract, not hosted execution.
workflow_policy() {
  python3 - "$source_root" <<'POLICY'
import pathlib
import re
import sys
root = pathlib.Path(sys.argv[1])
workflow = (root / ".github/workflows/release.yml").read_text()
assert "  workflow_dispatch:" in workflow and not re.search(r"^  push:", workflow, re.M)
assert workflow.count("if: github.ref == 'refs/heads/main' && github.event.repository.default_branch == 'main'") == 2
assert workflow.count("          ref: main\n") == 2
assert "--draft --prerelease" in workflow
assert "agent-held key, proves nothing about origin" in workflow
assert "python3 .scripts/release-metadata.py check" in workflow
assert "persist-credentials: true" not in workflow
assert "secrets." not in workflow and "id-token:" not in workflow
assert "permissions: {}" in workflow and workflow.count("contents: write") == 1
assert all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in re.findall(r"uses: [^@]+@(\S+)", workflow))
signers = (root / ".github/release/allowed_signers").read_text()
assert 'namespaces="git"' in signers and 'namespaces="git,file"' not in signers
assert "allowed_signers" not in (root / ".scripts/release-verify.sh").read_text()
docs = (root / "docs/releasing.md").read_text()
readme = (root / "README.md").read_text()
assert "agent-held key, proves nothing about origin" in docs and "agent-held key, proves nothing about origin" in readme
assert "in person before any root" in docs
assert "not a trust root" in docs
assert "SOURCE_DATE_EPOCH" in docs and "provenance.json" in readme
print("Default-branch dispatch, pre-release label, action pins, permissions, docs and tag-only pin: OK")
POLICY
}
expect_ok workflow_default_branch_and_prerelease_policy workflow_policy
printf 'Release controls passed; scratch evidence retained at %s\n' "$scratch"
