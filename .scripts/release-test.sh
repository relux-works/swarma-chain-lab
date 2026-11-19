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
mkdir -p .github/release .github/workflows .scripts experiments/model-proxy/cmd/model-proxy experiments/model-proxy/service/deploy docs
read -r kind public_key _ < "$scratch/key.pub"
printf 'release-tag namespaces="git" %s %s\n' "$kind" "$public_key" > .github/release/allowed_signers
cp "$source_root"/.scripts/release-* .scripts/
cp "$source_root/.github/workflows/release.yml" .github/workflows/
cp "$source_root/.github/release/gateway-inputs.json" .github/release/
printf 'module example.invalid/releasefixture\n\ngo 1.25\n' > experiments/model-proxy/go.mod
printf 'package main\nfunc main() { println("inert release fixture") }\n' > experiments/model-proxy/cmd/model-proxy/main.go
printf '[Service]\nExecStart=@PLATFORM_ROOT@/credential-gateway/bin/credential-gateway\n' > experiments/model-proxy/service/deploy/credential-gateway.service.in
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

# The hook exercises policy reads and the workflow's bundle transfer, not a real second UID.
expect_ok policy_head_scoped_trust env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  git -c safe.directory="$scratch/work" rev-parse HEAD
expect_ok policy_admission_scoped_trust env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "$admit" gateway/v1.0.0
expect_git_refusal() {
  local name=$1 reason=$2
  shift 2
  if env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "$@" > "$scratch/$name.log" 2>&1; then
    fail "$name: unexpected acceptance"
  else
    local status=$?
    [[ $status == 128 ]] || fail "$name: unexpected exit $status"
    grep -F -- "$reason" "$scratch/$name.log" > /dev/null || fail "$name: wrong refusal"
    printf 'PASS %s (expected Git refusal exit %s: %s)\n' "$name" "$status" "$reason"
  fi
}
expect_ownership_refusal() {
  local name=$1
  shift
  expect_git_refusal "$name" 'detected dubious ownership' "$@"
}
expect_ownership_refusal policy_head_trust_not_persisted \
  env GIT_CONFIG_GLOBAL="$HOME/.gitconfig" git rev-parse HEAD
# A planted scratch-home exception must be visible to that same ownership probe.
git config --file "$HOME/.gitconfig" --add safe.directory "$scratch/work"
expect_ok policy_head_persisted_trust_visible env GIT_CONFIG_GLOBAL="$HOME/.gitconfig" \
  GIT_TEST_ASSUME_DIFFERENT_OWNER=1 git rev-parse HEAD
rm "$HOME/.gitconfig"
expect_ownership_refusal policy_head_persisted_control_removed \
  env GIT_CONFIG_GLOBAL="$HOME/.gitconfig" git rev-parse HEAD
expect_ownership_refusal policy_head_wrong_trust \
  git -c safe.directory="$scratch/other-source" rev-parse HEAD

# Execute the actual workflow transfer commands so a direct-clone regression is observable.
mkdir "$scratch/bundle-transfer"
python3 - "$source_root/.github/workflows/release.yml" > "$scratch/container-source-transfer.sh" <<'TRANSFER'
import pathlib
import sys
workflow = pathlib.Path(sys.argv[1]).read_text()
build = workflow.split("\n  build:\n", 1)[1].split("\n  draft:\n", 1)[0]
print("set -euo pipefail")
for line in build.splitlines():
    if " bundle create " in line or (" clone " in line and '"$work/source"' in line):
        print(line.strip())
TRANSFER
expect_ok policy_bundle_clone_scoped_trust env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  policy_root="$scratch/work" work="$scratch/bundle-transfer" bash "$scratch/container-source-transfer.sh"
expect_ok policy_bundle_clone_head env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  git -c safe.directory="$scratch/bundle-transfer/source" -C "$scratch/bundle-transfer/source" rev-parse HEAD
expect_ok policy_bundle_clone_matches_policy cmp \
  "$scratch/policy_head_scoped_trust.log" "$scratch/policy_bundle_clone_head.log"
expect_ok policy_bundle_clone_release_commit env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 \
  git -c safe.directory="$scratch/bundle-transfer/source" -C "$scratch/bundle-transfer/source" rev-parse 'refs/tags/gateway/v1.0.0^{commit}'
printf '%s\n' "$base" > "$scratch/expected-release-commit"
expect_ok policy_bundle_clone_preserves_release cmp \
  "$scratch/expected-release-commit" "$scratch/policy_bundle_clone_release_commit.log"
# Bundle's gentle setup reports unsafe repositories as unavailable, on both tested Git versions.
expect_git_refusal policy_bundle_without_trust 'Need a repository to create a bundle.' \
  git bundle create "$scratch/untrusted.bundle" --all
expect_git_refusal policy_bundle_wrong_trust 'Need a repository to create a bundle.' \
  git -c safe.directory="$scratch/other-source" bundle create "$scratch/wrong-trust.bundle" --all
[[ ! -e $scratch/untrusted.bundle && ! -e $scratch/wrong-trust.bundle ]] || fail refused-bundle-partial-output
expect_refusal policy_admission_rejects_changed_tree tagged-release-policy-differs \
  env GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "$admit" gateway/v1.3.0

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
import hashlib
import pathlib
import platform
import struct
import sys
import tarfile
import zlib
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
assert provenance["go_version"] == "go1.26.10", "toolchain-provenance"
assert provenance["archive"]["python_version"] == platform.python_version(), "compressor-provenance"
assert provenance["archive"]["python_implementation"] == platform.python_implementation(), "compressor-provenance"
assert provenance["archive"]["zlib_version"] == zlib.ZLIB_VERSION, "compressor-provenance"
assert provenance["archive"]["zlib_runtime_version"] == zlib.ZLIB_RUNTIME_VERSION, "compressor-provenance"
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
            ("experiments/model-proxy/service/deploy/credential-gateway.service.in", "credential-gateway/templates/credential-gateway.service.in"),
            ("docs/gateway-service.md", "credential-gateway/docs/gateway-service.md"),
        ):
            assert archive.extractfile(member).read() == (root / "build-source" / source).read_bytes()
        assert provenance["archive"]["members"][path.name] == {
            member: hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            for member in files
        }, "member-provenance"
fragment = json.loads((root / "assets/release-set.json").read_bytes())
assert fragment["schema"] == "release-set-fragment/1", "fragment-schema"
assert all(set(row) == {"name", "sha256"} for row in fragment["artifacts"]), "fragment-row-shape"
assert {row["name"] for row in fragment["artifacts"]} == {
    "gateway_linux_amd64.tar.gz", "gateway_linux_arm64.tar.gz", "provenance.json", "SHA256SUMS"
}, "fragment-inventory"
print("Gateway inventory, ELF targets, exact service bytes, compressor/member provenance and headers: OK")
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

# These bounded plants prove the checker rejects missing compressor/member
# provenance and the old incompatible fragment extension, then accepts restoration.
cp "$scratch/assets/provenance.json" "$scratch/original-provenance"
cp "$scratch/assets/release-set.json" "$scratch/layout-fragment"
for mutation in compressor member fragment_shape; do
  python3 - "$scratch/assets" "$mutation" <<'PROVENANCE'
import json
import pathlib
import sys
root, mutation = pathlib.Path(sys.argv[1]), sys.argv[2]
path = root / ("release-set.json" if mutation == "fragment_shape" else "provenance.json")
value = json.loads(path.read_bytes())
if mutation == "compressor":
    value["archive"]["python_version"] = "unrecorded"
elif mutation == "member":
    value["archive"]["members"]["gateway_linux_amd64.tar.gz"]["credential-gateway/bin/credential-gateway"] = "0" * 64
else:
    value["artifacts"][0]["purpose"] = "platform-root"
path.write_text(json.dumps(value))
PROVENANCE
  case $mutation in
    compressor) reason=compressor-provenance ;;
    member) reason=member-provenance ;;
    fragment_shape) reason=fragment-row-shape ;;
  esac
  expect_refusal "layout_${mutation}_plant" "$reason" gateway_archive_layout
  cp "$scratch/original-provenance" "$scratch/assets/provenance.json"
  cp "$scratch/layout-fragment" "$scratch/assets/release-set.json"
  expect_ok "restored_layout_after_$mutation" gateway_archive_layout
done

# Claim: absent or symlinked service inputs refuse before output creation;
# each source state is committed, so dirty-source refusal cannot mask the gate.
fixture_source_commit() {
  git -C "$scratch/build-source" -c user.name='Release fixture' \
    -c user.email=release-fixture@example.invalid -c gpg.format=ssh \
    -c "user.signingkey=$scratch/key" commit -q -S -am "$1"
}
for input in docs/gateway-service.md experiments/model-proxy/service/deploy/credential-gateway.service.in experiments/model-proxy/go.mod experiments/model-proxy/cmd/model-proxy/main.go; do
  git -C "$scratch/build-source" rm -q "$input"
  fixture_source_commit 'Remove required service fixture'
  expect_refusal "missing_${input##*/}" missing-input .scripts/release-build.sh "$scratch/missing-input-dist" "$scratch/build-source"
  [[ ! -e $scratch/missing-input-dist ]] || fail missing-input-partial-output
  git -C "$scratch/build-source" checkout --quiet --detach "$base"
done
for input in docs/gateway-service.md experiments/model-proxy/service/deploy/credential-gateway.service.in; do
  rm "$scratch/build-source/$input"
  ln -s "$scratch/build-source/content" "$scratch/build-source/$input"
  git -C "$scratch/build-source" add "$input"
  fixture_source_commit 'Symlink required service fixture'
  case $input in
    docs/gateway-service.md)
      expect_refusal symlinked_service_input symlinked-input .scripts/release-build.sh "$scratch/symlink-input-dist" "$scratch/build-source" ;;
    *)
      expect_refusal symlinked_unit_input symlinked-input .scripts/release-build.sh "$scratch/symlink-input-dist" "$scratch/build-source" ;;
  esac
  [[ ! -e $scratch/symlink-input-dist ]] || fail symlink-input-partial-output
  git -C "$scratch/build-source" checkout --quiet --detach "$base"
done
for directory in experiments/model-proxy/service experiments/model-proxy/cmd/model-proxy; do
  mv "$scratch/build-source/$directory" "$scratch/build-source/$directory-original"
  ln -s "${directory##*/}-original" "$scratch/build-source/$directory"
  git -C "$scratch/build-source" add -A
  fixture_source_commit 'Symlink required input ancestry'
  expect_refusal "symlinked_directory_${directory//\//_}" symlinked-input .scripts/release-build.sh "$scratch/symlink-directory-dist" "$scratch/build-source"
  [[ ! -e $scratch/symlink-directory-dist ]] || fail symlink-directory-partial-output
  git -C "$scratch/build-source" checkout --quiet --detach "$base"
done
expect_ok restored_input_inventory python3 .scripts/release-metadata.py inputs "$scratch/build-source"

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

# Each widened or malformed table refuses its specific contract beside the valid table.
for mutation in fourth_row second_go wrong_mode outside_member outside_package parent_child non_mapping; do
  python3 - "$mutation" <<'TABLE'
import json
import pathlib
import sys
path = pathlib.Path(".github/release/gateway-inputs.json")
value = json.loads(path.read_text())
rows = value["inputs"]
mutation = sys.argv[1]
if mutation == "fourth_row":
    rows.append(dict(rows[1], member="credential-gateway/extra"))
elif mutation == "second_go":
    rows[1] = dict(rows[0], member="credential-gateway/bin/second")
elif mutation == "wrong_mode":
    rows[1]["mode"] = "0755"
elif mutation == "outside_member":
    rows[1]["member"] = "other/template"
elif mutation == "outside_package":
    rows[0]["package"] = "./other/model-proxy"
elif mutation == "parent_child":
    rows[1]["member"] = rows[0]["member"] + "/child"
elif mutation == "non_mapping":
    rows[1] = None
path.write_text(json.dumps(value))
TABLE
  case $mutation in
    fourth_row|second_go|parent_child) reason=invalid-input-inventory ;;
    wrong_mode|outside_member) reason=invalid-input-member-or-mode ;;
    outside_package) reason=invalid-command-package ;;
    non_mapping) reason=invalid-input-row ;;
  esac
  expect_refusal "table_$mutation" "$reason" python3 .scripts/release-metadata.py inputs "$scratch/build-source"
  git restore --source="$main" -- .github/release/gateway-inputs.json
  expect_ok "valid_table_after_$mutation" python3 .scripts/release-metadata.py inputs "$scratch/build-source"
done

fragment=$(sha256sum "$scratch/assets/release-set.json")
fragment=${fragment%% *}
expect_ok digest_control "$verify" "$scratch/assets" "$fragment"
# Rehashing a false member claim cannot bypass the archive/provenance binding.
python3 - "$scratch/assets" <<'PROVENANCE'
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
provenance = json.loads((root / "provenance.json").read_bytes())
provenance["archive"]["members"]["gateway_linux_arm64.tar.gz"]["credential-gateway/bin/credential-gateway"] = "0" * 64
(root / "provenance.json").write_bytes(canonical(provenance))
names = ["gateway_linux_amd64.tar.gz", "gateway_linux_arm64.tar.gz", "provenance.json"]
def digest(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()
(root / "SHA256SUMS").write_text("".join(f"{digest(name)}  {name}\n" for name in names), encoding="ascii")
(root / "release-set.json").write_bytes(canonical({"schema": "release-set-fragment/1", "artifacts": [
    {"name": name, "sha256": digest(name)} for name in sorted(names + ["SHA256SUMS"])]}))
PROVENANCE
false_fragment=$(sha256sum "$scratch/assets/release-set.json")
expect_refusal rehashed_false_member_provenance archive-member-digest-mismatch "$verify" "$scratch/assets" "${false_fragment%% *}"
cp "$scratch/original-provenance" "$scratch/assets/provenance.json"
python3 .scripts/release-metadata.py create "$scratch/assets" "$base" go1.26.10 "$(git show -s --format=%ct "$base")"
expect_ok restored_member_provenance "$verify" "$scratch/assets" "$fragment"
# Claim: draft binding rejects ancestor, rehashed forged inputs, open shapes and
# noncanonical bytes; compressor labels must be strings, not local policy values.
metadata="$scratch/work/.scripts/release-metadata.py"
epoch=$(git show -s --format=%ct "$base")
expect_ok admitted_provenance_binding python3 "$metadata" bind "$scratch/assets" "$base" "$epoch"
[[ $base != "$main" ]] || fail ancestor-provenance-fixture-requires-distinct-commits
expect_ok provenance_ancestor_relationship git merge-base --is-ancestor "$base" "$main"
expect_refusal ancestor_provenance_input_mismatch provenance-input-mismatch \
  python3 "$metadata" bind "$scratch/assets" "$main" "$(git show -s --format=%ct "$main")"
expect_ok admitted_binding_after_ancestor_refusal python3 "$metadata" bind "$scratch/assets" "$base" "$epoch"
mkdir "$scratch/binding-original"
cp "$scratch/assets/"{provenance.json,SHA256SUMS,release-set.json} "$scratch/binding-original/"
forge_provenance() {
  python3 - "$scratch/assets" "$1" <<'FORGE'
import hashlib
import json
import pathlib
import sys
root, field = pathlib.Path(sys.argv[1]), sys.argv[2]
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
provenance = json.loads((root / "provenance.json").read_bytes())
parent = provenance
parts = field.split(".")
for part in parts[:-1]:
    parent = parent[part]
key = parts[-1]
if field == "product":
    parent[key]["inputs"][0]["source"] = "experiments/other-daemon"
elif field == "epoch_boolean":
    parent["SOURCE_DATE_EPOCH"] = True
elif field == "extra_top_level_key":
    provenance["ldflags_extra"] = "-X main.mode=insecure"
    provenance["cgo"] = True
elif field == "extra_archive_key":
    provenance["archive"]["compressor"] = "pigz -11"
elif field == "labels_removed":
    for label in ("python_version", "python_implementation", "zlib_version", "zlib_runtime_version"):
        del provenance["archive"][label]
elif field.startswith("missing_label_"):
    del provenance["archive"][field.removeprefix("missing_label_")]
elif field.startswith("non_string_label_"):
    provenance["archive"][field.removeprefix("non_string_label_")] = 1
elif field == "archive_uid_boolean":
    provenance["archive"]["uid"] = False
elif field == "archive_gzip_mtime_boolean":
    provenance["archive"]["gzip_mtime"] = False
elif field == "archive_gzip_level_float":
    provenance["archive"]["gzip_level"] = 9.0
elif field not in ("duplicate_commit_first", "noncanonical_provenance"):
    value = parent[key]
    parent[key] = value + 1 if isinstance(value, int) else ([] if isinstance(value, list) else "forged")
raw = canonical(provenance)
if field == "duplicate_commit_first":
    raw = ("{\"commit\":\"" + "f" * 40 + "\",\"SOURCE_DATE_EPOCH\":1,").encode("ascii") + raw[1:]
elif field == "noncanonical_provenance":
    raw = json.dumps(provenance, indent=2).encode("ascii") + b"\n"
(root / "provenance.json").write_bytes(raw)
names = ["gateway_linux_amd64.tar.gz", "gateway_linux_arm64.tar.gz", "provenance.json"]
def digest(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()
(root / "SHA256SUMS").write_text("".join(f"{digest(name)}  {name}\n" for name in names), encoding="ascii")
(root / "release-set.json").write_bytes(canonical({"schema": "release-set-fragment/1", "artifacts": [
    {"name": name, "sha256": digest(name)} for name in sorted(names + ["SHA256SUMS"])]}))
FORGE
}
draft_provenance_binding_regression() {
  local field=$1
  forge_provenance "$field"
  expect_ok "rehashed_forged_${field}_consistency" python3 "$metadata" check "$scratch/assets"
  expect_ok "rehashed_forged_${field}_checksums" bash -c 'cd "$1" && sha256sum --strict --check SHA256SUMS' _ "$scratch/assets"
  cp "$scratch/assets/provenance.json" "$scratch/forged-provenance"
  expect_refusal "forged_${field}_input_mismatch" provenance-input-mismatch \
    python3 "$metadata" bind "$scratch/assets" "$base" "$epoch"
  expect_ok "forged_${field}_unchanged" cmp "$scratch/assets/provenance.json" "$scratch/forged-provenance"
  cp "$scratch/binding-original/"{provenance.json,SHA256SUMS,release-set.json} "$scratch/assets/"
  expect_ok "restored_binding_after_$field" python3 "$metadata" bind "$scratch/assets" "$base" "$epoch"
}
for field in commit SOURCE_DATE_EPOCH go_version product flags epoch_boolean \
  environment.CGO_ENABLED environment.GOOS environment.GOARCH environment.GOAMD64 \
  environment.GOARM64 environment.GOEXPERIMENT environment.GOTOOLCHAIN environment.GOWORK environment.GOENV \
  archive.format archive.order archive.mtime archive.uid archive.gid archive.uname \
  archive.gname archive.directory_mode archive.gzip_mtime archive.gzip_level \
  extra_top_level_key extra_archive_key labels_removed duplicate_commit_first noncanonical_provenance \
  missing_label_python_version missing_label_python_implementation missing_label_zlib_version missing_label_zlib_runtime_version \
  non_string_label_python_version non_string_label_python_implementation non_string_label_zlib_version non_string_label_zlib_runtime_version \
  archive_uid_boolean archive_gzip_mtime_boolean archive_gzip_level_float; do
  draft_provenance_binding_regression "$field"
done
for field in archive.python_version archive.python_implementation archive.zlib_version archive.zlib_runtime_version; do
  forge_provenance "$field"
  expect_ok "recorded_${field}_consistency" python3 "$metadata" check "$scratch/assets"
  expect_ok "recorded_${field}_binding" python3 "$metadata" bind "$scratch/assets" "$base" "$epoch"
  cp "$scratch/binding-original/"{provenance.json,SHA256SUMS,release-set.json} "$scratch/assets/"
done
# Claim: removing shape, raw-byte or numeric-type binding must fail the same
# regression witness, not an unrelated setup step. Mutants use isolated assets.
mkdir -p "$scratch/binding-mutants/"{.scripts,.github/release}
cp .github/release/gateway-inputs.json "$scratch/binding-mutants/.github/release/"
python3 - "$metadata" "$scratch/binding-mutants/.scripts" <<'MUTANTS'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
source = path.read_text()
guard = "        if raw != canonical(provenance) or canonical(provenance) != canonical(expected):"
assert source.count(guard) == 1
mutants = {
    "projection_only": (
        "        actual = {key: provenance[key] for key in expected}\n"
        "        actual[\"archive\"] = {key: provenance[\"archive\"][key] for key in expected[\"archive\"]}\n"
        "        if raw != canonical(provenance) or canonical(actual) != canonical(expected):"),
    "without_canonical_bytes": "        if canonical(provenance) != canonical(expected):",
    "dictionary_equality": "        if raw != canonical(provenance) or provenance != expected:",
}
for name, replacement in mutants.items():
    (output / ("release-metadata-mutant-" + name + ".py")).write_text(source.replace(guard, replacement))
MUTANTS
binding_mutant_witness() (
  mutation=$1
  field=$2
  metadata="$scratch/binding-mutants/.scripts/release-metadata-mutant-$mutation.py"
  original_assets="$scratch/assets"
  scratch="$scratch/mutant-$mutation-$field"
  mkdir -p "$scratch/assets" "$scratch/binding-original"
  cp "$original_assets/"{gateway_linux_amd64.tar.gz,gateway_linux_arm64.tar.gz,provenance.json,SHA256SUMS,release-set.json} "$scratch/assets/"
  cp "$scratch/assets/"{provenance.json,SHA256SUMS,release-set.json} "$scratch/binding-original/"
  expect_ok admitted_provenance_binding python3 "$metadata" bind "$scratch/assets" "$base" "$epoch"
  draft_provenance_binding_regression "$field"
)
for mutant_case in projection_only:extra_top_level_key projection_only:extra_archive_key \
  without_canonical_bytes:duplicate_commit_first dictionary_equality:archive_uid_boolean \
  dictionary_equality:archive_gzip_level_float; do
  mutation=${mutant_case%%:*}
  field=${mutant_case#*:}
  expect_refusal "mutant_${mutation}_${field}_killed" "forged_${field}_input_mismatch: unexpected acceptance" \
    binding_mutant_witness "$mutation" "$field"
done
expect_ok admitted_binding_after_mutants python3 "$metadata" bind "$scratch/assets" "$base" "$epoch"
cp "$scratch/assets/gateway_linux_arm64.tar.gz" "$scratch/original-arm64"
printf 'changed\n' >> "$scratch/assets/gateway_linux_arm64.tar.gz"
expect_refusal changed_arm64_archive artifact-digest-mismatch "$verify" "$scratch/assets" "$fragment"
cp "$scratch/original-arm64" "$scratch/assets/gateway_linux_arm64.tar.gz"
expect_ok restored_arm64_archive "$verify" "$scratch/assets" "$fragment"
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
  python3 - "$source_root" "${1:-$source_root/.github/workflows/release.yml}" \
    "${2:-$source_root/.scripts/release-admit.sh}" <<'POLICY'
import pathlib
import re
import sys
root = pathlib.Path(sys.argv[1])
workflow = pathlib.Path(sys.argv[2]).read_text()
assert "  workflow_dispatch:" in workflow and not re.search(r"^  push:", workflow, re.M)
assert workflow.count("if: github.ref == 'refs/heads/main' && github.event.repository.default_branch == 'main'") == 2
assert workflow.count("          ref: main\n") == 2
build = workflow.split("\n  build:\n", 1)[1].split("\n  draft:\n", 1)[0]
draft = workflow.split("\n  draft:\n", 1)[1]
binding = 'python3 .scripts/release-metadata.py bind "$RUNNER_TEMP/dist" "$RELEASE_COMMIT" "$(git show -s --format=%ct "$RELEASE_COMMIT")"'
assert re.search(r"(?m)^ {10}" + re.escape(binding) + r"$", draft), "draft-provenance-binding-required"
assert draft.index("python3 .scripts/release-metadata.py check") < draft.index(binding) < draft.index("sha256sum --strict --check") < draft.index("gh release create"), "draft-provenance-binding-before-publication-required"
assert "Not a closure: root use stays blocked" in draft, "draft-not-a-closure-notes-required"
assert not re.search(r"\bgit\b[^\n;]*\bconfig\b", workflow), "workflow-persistent-git-config-forbidden"
assert "GIT_CONFIG_" not in workflow, "workflow-config-env-forbidden"
assert not re.search(r"safe\.directory[^\n]*\*", build), "build-wildcard-trust-forbidden"
assert not re.search(r"safe\.directory[^\n]*\*", workflow), "workflow-wildcard-trust-forbidden"
assert 'git -c safe.directory="$policy_root" bundle create "$work/source.bundle" --all' in build, "build-bundle-scoped-trust-required"
assert 'git clone --quiet --no-checkout "$work/source.bundle" "$work/source"' in build, "build-bundle-clone-required"
assert 'git -c safe.directory="$policy_root" rev-parse HEAD' in build, "build-head-scoped-trust-required"
assert build.index("policy_root=$(pwd -P)") < build.index('safe.directory="$policy_root"'), "build-policy-root-required-before-git"
assert workflow.count("safe.directory") == build.count('safe.directory="$policy_root"') == 2, "workflow-unexpected-trust-forbidden"
admission = pathlib.Path(sys.argv[3]).read_text()
assert not re.search(r"\bgit\b[^\n;]*\bconfig\b", admission), "admission-persistent-git-config-forbidden"
assert "GIT_CONFIG_" not in admission, "admission-config-env-forbidden"
assert not re.search(r"safe\.directory[^\n]*\*", admission), "admission-wildcard-trust-forbidden"
assert 'command git -c safe.directory="$root" -c core.commitGraph=false "$@"' in admission, "admission-scoped-trust-required"
assert admission.count("safe.directory") == 1, "admission-unexpected-trust-forbidden"
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
assert "No root step for this product" in docs
assert "gateway is not deploy service gateway" in docs
assert "open owner decision" in docs and "authoritative" in docs
assert "all of `.scripts`" in docs and "__pycache__" in docs
assert "same" in docs and "deflate implementation" in docs
assert "go-version: '1.26.10'" in workflow and "go1.26.10-required" in (root / ".scripts/release-build.sh").read_text()
print("Default-branch dispatch, pre-release label, action pins, permissions, docs and tag-only pin: OK")
POLICY
}
expect_ok workflow_default_branch_and_prerelease_policy workflow_policy
# Claim: draft policy requires binding to the admitted commit and its epoch
# before publication, and preserves the release notes' no-root-step gate.
sed '/python3 .scripts\/release-metadata.py bind/d' \
  "$source_root/.github/workflows/release.yml" > "$scratch/unbound-draft.yml"
expect_refusal workflow_unbound_draft_rejected draft-provenance-binding-required \
  workflow_policy "$scratch/unbound-draft.yml"
sed '/python3 .scripts\/release-metadata.py bind/s/"$RELEASE_COMMIT"/"$POLICY_COMMIT"/g' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wrong-commit-draft.yml"
expect_refusal workflow_wrong_commit_draft_rejected draft-provenance-binding-required \
  workflow_policy "$scratch/wrong-commit-draft.yml"
sed '/python3 .scripts\/release-metadata.py bind/s/--format=%ct "$RELEASE_COMMIT"/--format=%ct HEAD/' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wrong-epoch-draft.yml"
expect_refusal workflow_wrong_epoch_draft_rejected draft-provenance-binding-required \
  workflow_policy "$scratch/wrong-epoch-draft.yml"
sed '/python3 .scripts\/release-metadata.py bind/{h;d;}; /--notes-file /{G;}' \
  "$source_root/.github/workflows/release.yml" > "$scratch/late-binding-draft.yml"
expect_refusal workflow_late_binding_draft_rejected draft-provenance-binding-before-publication-required \
  workflow_policy "$scratch/late-binding-draft.yml"
sed '/Not a closure: root use stays blocked/d' \
  "$source_root/.github/workflows/release.yml" > "$scratch/missing-gate-notes-draft.yml"
expect_refusal workflow_missing_gate_notes_rejected draft-not-a-closure-notes-required \
  workflow_policy "$scratch/missing-gate-notes-draft.yml"
expect_ok restored_draft_binding_and_notes_policy workflow_policy
# Claim: preserving the bind tokens while commenting out or ignoring the command
# must not satisfy the workflow gate; the unchanged workflow remains valid.
sed "/python3 .scripts\/release-metadata.py bind/s/$/ || true/" \
  "$source_root/.github/workflows/release.yml" > "$scratch/ignored-binding-draft.yml"
expect_refusal workflow_ignored_binding_rejected draft-provenance-binding-required \
  workflow_policy "$scratch/ignored-binding-draft.yml"
sed "/python3 .scripts\/release-metadata.py bind/s/^          /          # /" \
  "$source_root/.github/workflows/release.yml" > "$scratch/commented-binding-draft.yml"
expect_refusal workflow_commented_binding_rejected draft-provenance-binding-required \
  workflow_policy "$scratch/commented-binding-draft.yml"
expect_ok restored_executable_draft_binding_policy workflow_policy
# Each persistent-write spelling must be rejected in both production surfaces.
for config_write in '--global --add' '--system --add' '--file "$HOME/.gitconfig" --add' '--add'; do
  case $config_write in
    --global*) write_scope=global ;;
    --system*) write_scope=system ;;
    --file*) write_scope=file ;;
    *) write_scope=add ;;
  esac
  sed "/safe.directory=\"\$policy_root\" rev-parse HEAD/a\\          git config $config_write safe.directory \"\$policy_root\"" \
    "$source_root/.github/workflows/release.yml" > "$scratch/persisted-$write_scope-build.yml"
  expect_refusal "workflow_persisted_${write_scope}_trust_rejected" workflow-persistent-git-config-forbidden \
    workflow_policy "$scratch/persisted-$write_scope-build.yml"
  sed "/^git() /a\\command git config $config_write safe.directory \"\$root\"" \
    "$source_root/.scripts/release-admit.sh" > "$scratch/persisted-$write_scope-admit.sh"
  expect_refusal "admission_persisted_${write_scope}_trust_rejected" admission-persistent-git-config-forbidden \
    workflow_policy "$source_root/.github/workflows/release.yml" "$scratch/persisted-$write_scope-admit.sh"
done
# Adjacent mutations reject missing, widened and wrong-path bundle/HEAD trust.
sed 's/git -c safe.directory="$policy_root" bundle/git bundle/' \
  "$source_root/.github/workflows/release.yml" > "$scratch/untrusted-build.yml"
expect_refusal workflow_untrusted_build_clone_rejected build-bundle-scoped-trust-required \
  workflow_policy "$scratch/untrusted-build.yml"
sed 's/safe.directory="$policy_root"/safe.directory="*"/g' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wildcard-build.yml"
expect_refusal workflow_wildcard_build_trust_rejected build-wildcard-trust-forbidden \
  workflow_policy "$scratch/wildcard-build.yml"
sed 's/safe.directory="$policy_root"/safe.directory="$work"/g' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wrong-path-build.yml"
expect_refusal workflow_wrong_path_build_trust_rejected build-bundle-scoped-trust-required \
  workflow_policy "$scratch/wrong-path-build.yml"
sed 's/git -c safe.directory="$policy_root" rev-parse/git rev-parse/' \
  "$source_root/.github/workflows/release.yml" > "$scratch/untrusted-head-build.yml"
expect_refusal workflow_untrusted_build_head_rejected build-head-scoped-trust-required \
  workflow_policy "$scratch/untrusted-head-build.yml"
sed 's#git clone --quiet --no-checkout "$work/source.bundle"#git clone --quiet --no-checkout "$policy_root"#' \
  "$source_root/.github/workflows/release.yml" > "$scratch/direct-build-clone.yml"
expect_refusal workflow_direct_build_clone_rejected build-bundle-clone-required \
  workflow_policy "$scratch/direct-build-clone.yml"
# Environment config and other workflow jobs cannot widen the two scoped exceptions.
sed '/POLICY_COMMIT: /a\          GIT_CONFIG_COUNT: "1"\n          GIT_CONFIG_KEY_0: safe.directory\n          GIT_CONFIG_VALUE_0: "*"' \
  "$source_root/.github/workflows/release.yml" > "$scratch/env-wildcard-build.yml"
expect_refusal workflow_env_wildcard_trust_rejected workflow-config-env-forbidden \
  workflow_policy "$scratch/env-wildcard-build.yml"
sed 's#git rev-parse refs/remotes/origin/main#git -c safe.directory="*" rev-parse refs/remotes/origin/main#' \
  "$source_root/.github/workflows/release.yml" > "$scratch/wildcard-draft.yml"
expect_refusal workflow_other_job_wildcard_rejected workflow-wildcard-trust-forbidden \
  workflow_policy "$scratch/wildcard-draft.yml"
sed 's/safe.directory="$root"/safe.directory="*"/' \
  "$source_root/.scripts/release-admit.sh" > "$scratch/wildcard-admit.sh"
expect_refusal admission_wildcard_trust_rejected admission-wildcard-trust-forbidden \
  workflow_policy "$source_root/.github/workflows/release.yml" "$scratch/wildcard-admit.sh"
sed 's/ -c safe.directory="$root"//' \
  "$source_root/.scripts/release-admit.sh" > "$scratch/untrusted-admit.sh"
expect_refusal admission_unscoped_trust_rejected admission-scoped-trust-required \
  workflow_policy "$source_root/.github/workflows/release.yml" "$scratch/untrusted-admit.sh"
printf 'Release controls passed; scratch evidence retained at %s\n' "$scratch"
