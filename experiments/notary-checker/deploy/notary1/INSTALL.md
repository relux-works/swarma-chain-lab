# notary1: regtest installation pack, notary-service v0.1.1

**INSTALLATION BLOCKED pending the positive-smoke ruling below and a reviewed
isolated verifier pin.** This is a reviewable pack, not permission to execute.
Infra executes one reviewed guest installation only after the owner's word.
The producer never installs, runs a node, uses root, or touches host services.
All node/service traffic stays on IPv4 loopback inside the VM; no mainnet.

## Sources and scope

Same contract: [service README](../../README.md#notary-service-regtest-laboratory),
[release procedure](../../RELEASE.md), and [D8 / pinned module spec](../../DESIGN.md#exact-inputs)
(swarma-link-spec v0.1.51, LIP-0010 sections 2/3/9, LIP-0014 sections 6/7).
Book context: [Swarma book, chapter 26, chain and names](https://github.com/relux-works/swarma-docs/blob/b57a9be633c245373b448c3786bcbd49d636fe8a/book/ru/26-cepochka.md).
These sources describe authority; this pack only supplies local deployment
paths and units. Future read-only chain-gateway integration is deferred.
The owner's notary1 ruling overrides the README's general publication example:
record the generated public key **only in the local installation receipt**,
publish it nowhere, and create **no name binding**.

The policy is the repository's exact `testdata/positive/policy.json`, with
`Policy.Mode == ""` (omitted) and no MVP approvals: strict D8. Its two grant
IDs and owner are deliberately public fixture identities, not new authority
or a usable current commissioning request. It cannot authorize arbitrary
bundles. Do not replace it or enable MVP as an installation workaround.

## 0. Admission and prerequisites

Check the owner-approved pack commit, Infra S8 numeric assignments, target VM
identity `notary1`, Linux/amd64, and the approved maintenance window. Check
that both unit names and all leaf paths in [accounts.md](accounts.md) are
unused, or explicitly inventoried as a resumable installation. Inspect
`systemctl cat` and `systemctl show -p FragmentPath -p DropInPaths` to detect
unit overrides. **Abort** on a different host, a collision, missing owner word,
unknown state, unresolved gates below, or unreviewed unit drop-ins.

Required operator tools: systemd with seccomp and working cgroup IP filtering,
coreutils, `runuser`, `getent`, `namei`, `getfacl`, OpenSSH, Git, Python 3,
and Go 1.26.10 for the independent build. Verify each tool/version before use.
`systemd-analyze verify` checks syntax/dependencies; it does not prove runtime
syscalls or IP filtering. Infra must confirm these on the target; unsupported
hardening is an abort, not permission to remove directives. Check no network
namespace, proxy, port forward, or other VM service forwards loopback outward.

## 1. Verify both releases before installing executables

Use the **v0.1.1 worked example** in RELEASE.md, including separate bot/tag and
owner/manifest allowed-signers files, their independently pinned fingerprints,
immutable tag object and exact release commit. The source commit is
`8a47f1a984cd93864402f7fdc09d2eba0d890b90`; the tag is
`notary-service/v0.1.1`. The artifact `notary-service-linux-amd64` must hash to
`9e63953c112b0cf0426a2db4ddc048faff053088d5cd1d447f1e6f598c91f7f5`.
The hash alone is not authentication.

Obtain artifacts on the release workstation and transfer reviewed inputs into
the VM using Infra's guest channel. Do not download from the VM or let service
units fetch anything. Use absolute, operator-controlled paths. The clean
download directory contains only the binary, `SHA256SUMS`, `SHA256SUMS.sig`;
build output and both trust files stay outside it. No symlinks/special files.
Run from a fresh empty working directory, with an empty HOME and isolated Git
configuration, no inherited `GIT_*`, Python module path, or proxy variables.
The independent rebuild uses the exact released source and RELEASE.md flags:
Go 1.26.10, `GOTOOLCHAIN=local`, `GOWORK=off`, `CGO_ENABLED=0`, Linux/amd64,
`GOAMD64=v1`, `-trimpath -buildvcs=false -ldflags='-s -w -buildid='`.

Use a reviewed, immutable follow-up verifier that invokes **all Python with
`python3 -I`**, clears Git configuration/environment, and retains the existing
byte-exact tag, two-role signature, manifest and independent-rebuild checks.
Record its accepted commit and hash in the receipt, then run its documented
eight-argument interface from RELEASE.md. The verifier present at this pack's
base (`65f1cbe61347d58ede11d5514fcfb4fcd5dc76a2`) invokes `python3` without
`-I`; this pack does not patch it or claim it supplies that isolation.
**Abort until the follow-up has landed and its reviewed pin is recorded.**
Do not silently substitute a moving branch, ad-hoc wrapper, or weaker check.

Check: verifier exits 0 with `PASS RELEASE_VERIFIED`, exact artifact SHA above,
both independent builds match it, and signatures have the distinct required
roles/namespaces. Any missing input, refusal or mismatch **aborts** installation.

Core is Infra's independently pinned **Namecoin Core 28.0 Guix release**.
Infra supplies its exact archive/executable SHA-256 values and authenticated
Guix verification record; do not invent hashes or fetch an alternative build.
Check both `namecoind -version` and `namecoin-cli -version` report 28.0 after
provenance verification. Abort on any mismatch. The defined executable paths
are `/opt/namecoin/28.0/bin/namecoind` and `namecoin-cli` in that same directory.

## 2. Create accounts and directories

Infra uses its S8 account mechanism with the contracts in accounts.md. Check
UID/GID, locked password, nologin shell, home field and exact memberships.
Abort on a discrepancy before creating any key or starting any process.

The following are target-operator operations through the authorized guest
installation mechanism, **not commands for the producer to execute**:

```sh
install -d -o root -g root -m 0755 /opt/notary-service /opt/notary-service/v0.1.1
install -d -o root -g root -m 0755 /etc/namecoin /etc/notary-service
install -d -o namecoin-node -g namecoin-node -m 0700 /var/lib/namecoind-regtest
install -d -o notary-service -g notary-service -m 0700 /var/lib/notary-service
install -d -o notary-service -g notary-service -m 0700 /var/lib/notary-service/private
install -d -o root -g root -m 0700 /var/lib/notary1-install
```

Use a fresh protected receipt file, mode 0600, in that last directory. Do not
truncate an existing receipt. Check every path/parent with `stat`, `namei -l`
and `getfacl -p` against accounts.md. Abort on symlinks, unexpected content,
non-root executable/config parents, or excess access. Do not chmod/chown
unknown existing state to make it fit.

## 3. Install verified files and reviewed units

Set `RELEASE_DIR` to the verified immutable download directory and `PACK_DIR`
to this reviewed pack, both absolute paths. Through the guest mechanism:

```sh
install -o root -g root -m 0755 "$RELEASE_DIR/notary-service-linux-amd64" /opt/notary-service/v0.1.1/notary-service
install -o root -g root -m 0644 "$PACK_DIR/service.json" /etc/notary-service/service.json
install -o root -g root -m 0644 "$PACK_DIR/deployment-policy.json" /etc/notary-service/deployment-policy.json
install -o root -g root -m 0644 "$PACK_DIR/namecoin.conf" /etc/namecoin/notary1-regtest.conf
install -o root -g root -m 0644 "$PACK_DIR/namecoind-regtest.service" /etc/systemd/system/namecoind-regtest.service
install -o root -g root -m 0644 "$PACK_DIR/notary-service.service" /etc/systemd/system/notary-service.service
```

Infra installs its already verified Core executables at the paths above.
Check **installed-path** SHA-256 equals the authenticated manifest (renaming
the notary executable does not change its digest); `cmp` each installed
config/unit with the approved pack; check modes/ownership and full parent
chains/ACLs as in RELEASE.md. Neither service account may write executable,
unit or configuration paths. Abort on any difference.

Run `systemd-analyze verify` on the two installed units; require exit 0, no
unknown directive and no missing binary/dependency. Run `systemctl daemon-reload`
and compare `systemctl cat` / effective properties to the reviewed units.
Abort on any override or failed validation; do not enable services yet.

## 4. Start the isolated node and wait for RPC

Run `systemctl start namecoind-regtest.service`. Its `ExecStartPost` waits at
most 60 seconds for authenticated RPC. Check `systemctl is-active` succeeds,
then, as `namecoin-node`, use the exact `namecoin-cli` arguments in that unit
for `getblockchaininfo` and `getconnectioncount`: require `chain=regtest` and
peer count 0. Inspect `ss -ltnp`: RPC is **127.0.0.1:18443 only**, no P2P
listener, no wildcard/IPv6 listener. Confirm effective sandbox properties and
kernel/cgroup IP-filter support. Check `getindexinfo` reports txindex synced.
`txindex=1` is conservative laboratory provisioning; the current reader uses
chain/name/history RPC, not arbitrary raw-transaction lookup.

Verify `/run/namecoind-regtest/.cookie` is regular, node-owned, group
`namecoin-cookie`, mode 0640; verify cookie group cannot traverse node state.
Never print, log, hash, or copy cookie bytes into evidence. **Abort** and stop
this newly started unit on readiness, network, index or permissions failure.

## 5. Generate the key as the service user

Check the target key path is absent (including a dangling symlink). On a
resumed installation with an existing key, stop and reconcile the existing
receipt; do not regenerate, export, overwrite, or derive another recorded copy
of the public key. On a fresh installation:

```sh
runuser -u notary-service -- sh -c 'umask 077; cd /var/lib/notary-service/private; exec /opt/notary-service/v0.1.1/notary-service keygen -out /var/lib/notary-service/private/attestation.key' >> /var/lib/notary1-install/receipt.md
```

Immediately before this command, append the receipt's public-key field label;
stdout goes **directly and only** to its next line. Do not use `tee`, terminal
capture, journal, PR, name operation or external logging. Check exit 0; check
the added line matches exactly 64 lowercase hexadecimal characters without
printing it; check key regularity, service ownership and exact mode 0600.
Check private parent mode 0700. **Abort** on failure; preserve an existing key
for owner-directed recovery, never retry destructively. Do not hash the key.

## 6. Start and check the notary

Run `systemctl start notary-service.service`. The service UID copies the
group-readable cookie into its own 0600 regular file before the loader reads
it. Check that owner/mode and the two runtime directories against accounts.md
without reading credentials. Check both units active, the running executable
path/hash, and the service's effective hardening. `ss -ltnp` must show HTTP
**127.0.0.1:8080 only**. Abort and stop the newly started service on mismatch.

As a bounded refusal control, submit an empty object to the actual route:

```sh
curl --noproxy '*' --silent --show-error --max-time 5 -o /var/lib/notary1-install/refusal.json -w '%{http_code}\n' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:8080/v1/attest
```

Require HTTP 422, body exactly `{"decision":"POLICY_REFERENCE"}` (JSON
whitespace aside), no signed fields, no anchor. Record verdict/HTTP only.
Any signature, unexpected decision, timeout or connection failure aborts.
This is readiness/refusal evidence, **not** the required positive smoke.

## 7. Positive smoke: currently blocked, do not run a substitute

Required acceptance: register one disposable regtest name in this VM, then
POST one valid Grant v3, profile `/2`, depth-1 bundle to the **installed**
service, receive HTTP 200 / `ATTEST`, independently verify BIP-340 using the
receipt's key, and verify the returned 72-byte action-0x04 anchor frame.
Keep the key itself only in the receipt and never publish the response (its
signed attestation also embeds the notary key). Do not broadcast an anchor.

**Exact conflict:** `internal/service/service.go` first resolves
`policy.NotaryName` through the real node; `name.go` requires that name value
to contain `swarma.notary.attest`; the service then requires that key equal
its generated public key (`NOTARY_KEY_MISMATCH` otherwise). No name, no
binding, or an unrelated test name cannot produce `ATTEST`. The current
notary1 ruling expressly forbids that binding. A chain gateway is not an
implemented alternate source in v0.1.1.

The [existing real-node harness](../../scripts/regtest-service.py) shows the
valid transaction order: fund/mature disposable regtest outputs, `name_new`,
mine 12 blocks, `name_firstupdate`, mine a confirmation; then bind the actual
registration outpoint and current tip into fresh signed contracts/grants,
derive pair-bound strict D8 policy, and independently verify signature/frame.
Its positive encoders come from `make-fixtures.py` / `reference.py`. Static
positive JSON is expired and has synthetic txids/tip; it is not a host request.
The harness generates/publishes a throwaway notary binding, starts another
wallet-enabled node and service, and removes its key/state. **Do not run it
against the retained key or claim it tests these installed units.** This node
also has `disablewallet=1`, so its wallet name-registration commands cannot
be reused verbatim; a reviewed VM-local registration procedure is needed.

**Abort point:** keep `positive_smoke=BLOCKED`, leave services disabled (stop
them after diagnostic checks), retain the key, and return the receipt to Infra
and the owner. No successful installation receipt or enablement is permitted.
Required decision: either explicitly authorize a disposable regtest binding
and its registration/fixture procedure, or change the acceptance requirement
to a non-signing commissioning check. A gateway/source-contract change would
be separate reviewed work. Do not add mocks, fixture flags or a loader bypass.

Only after that decision is implemented and reviewed, and the actual positive
smoke passes, enable both units with `systemctl enable namecoind-regtest.service
notary-service.service`; require both `is-enabled` checks and active checks.
Record enablement separately from smoke and deployment approval.

## Local installation receipt (private, do not commit or publish)

Store only at `/var/lib/notary1-install/receipt.md`, root:root 0600. No private
key/cookie content or hash. Hashes below cover public artifacts only. When
recording public config/unit hashes, include both approved and installed values.

```text
unit: NOTARY1-PACK
target: notary1
owner_authorization_reference:
infra_operator_and_S8_account_reference:
pack_accepted_commit:
verifier_accepted_commit_and_sha256:
tag: notary-service/v0.1.1
release_commit: 8a47f1a984cd93864402f7fdc09d2eba0d890b90
artifact_sha256: 9e63953c112b0cf0426a2db4ddc048faff053088d5cd1d447f1e6f598c91f7f5
installed_notary_sha256:
independent_rebuild_sha256_and_toolchain:
tag_and_manifest_signer_fingerprints_and_namespaces:
core_version: Namecoin Core 28.0 Guix
core_archive_and_executable_sha256_and_verification_reference:
service_json_sha256:
deployment_policy_json_sha256:
namecoin_conf_sha256:
namecoind_unit_sha256:
notary_unit_sha256:
accounts_directories_modes_ACLs_checked:
systemd_version_verify_exit_and_sandbox_support:
rpc_ready_chain_peer_count_indexes_and_listeners:
keygen_exit_and_private_file_owner_mode:
regtest_public_key_receipt_only:
[keygen appends its sole output line here; no placeholder is sent to keygen]
refusal_control_http_and_decision:
positive_smoke: BLOCKED
positive_smoke_owner_decision_reference:
test_name_registration_outpoint_tip_and_request_sha256:
positive_smoke_http_decision_signature_and_anchor_verification:
units_active_and_enabled:
rollback_or_retained_state_decision:
installation_outcome: NOT_ACCEPTED
```
