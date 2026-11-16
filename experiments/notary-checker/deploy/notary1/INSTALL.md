# Regtest only: notary1 installation pack, notary-service v0.1.1

**Regtest only. The binding exists only on the VM's private regtest chain.
No mainnet name binding; nothing is published. The public key is recorded in
the private installation receipt only, never in published evidence.** The
VM-local binding necessarily carries that key; it is not external publication.

**Installation remains gated on the landed, reviewed PR #152 verifier pin and
target authorization/checks below.** The private-regtest binding is authorized;
the former no-binding smoke conflict is resolved. This is not permission to execute.
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
The private-regtest ruling overrides the module README's general publication
example: record the generated public key **only in the local installation
receipt**, publish it nowhere, and bind only the policy name on this VM's
private regtest node. Do not export name values, signed responses, node state,
wallets or the receipt. Never bind a mainnet name or broadcast an anchor.

The shipped policy is the exact `testdata/positive/policy.json`, with
`Policy.Mode == ""` (omitted) and no MVP approvals: strict D8. Its grant IDs
are expired synthetic fixtures, not a current commissioning request. Section
5a derives a fresh, equally strict, pair-bound smoke policy using throwaway
in-memory fixture signers and the actual registration outpoint. The operator
reviews/provisions it locally, records both policy hashes, then restores the
shipped policy before enablement. No MVP, loader bypass or new protocol is
introduced. Issuance, seal and checkpoint locators remain synthetic: this
smoke proves service/name/tip/signature behavior, not full live admission.

## 0. Admission and prerequisites

Check the owner-approved pack commit, Infra S8 numeric assignments, target VM
identity `notary1`, Linux/amd64, and the approved maintenance window. Check
that both unit names and all leaf paths in [accounts.md](accounts.md) are
unused, or explicitly inventoried as a resumable installation. Inspect
`systemctl cat` and `systemctl show -p FragmentPath -p DropInPaths` to detect
unit overrides. **Abort** on a different host, a collision, missing owner word,
unknown state, unresolved gates below, or unreviewed unit drop-ins.

Required operator tools: systemd with seccomp and working cgroup IP filtering,
coreutils, `runuser`, `getent`, `namei`, `getfacl`, `ss`, OpenSSH, Git, Python 3,
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

Required verifier once landed: **chain-lab PR #152, immutable head
`c96392594f5296bf546e9e63da1bf6db6c92bc6b`**, specifically
`experiments/notary-checker/scripts/verify-release.sh` and that revision's
RELEASE.md. Confirm that exact reviewed revision has landed (or an explicitly
reviewed immutable successor retaining its isolation), record its commit and
script SHA-256 in the receipt, and use its eight-argument interface. It invokes
**all Python with `python3 -I`** and uses a config-free Git object view with
cleared environment/configuration, retaining byte-exact tag, two-role signature,
manifest and independent-rebuild checks. Do not use the verifier at this pack's
base, which lacks that isolation, or silently substitute a moving branch.

**Until landing/pin acceptance, installation aborts.** Keep all precautions
explicit even after landing: fresh clean working/download directories, empty
HOME, no inherited `GIT_*`, `PYTHON*` or proxy variables; `python3 -I` for every
verifier Python invocation; cleared system/global/local Git configuration and
includes (not merely `HOME` isolation). The pinned verifier's private object
view supplies the local-config isolation. A clean shell around the old
verifier does not. No ad-hoc wrapper or weaker check discharges this gate.

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
capture, journal, PR or external logging. The sole authorized use outside this
receipt is the VM-local name value in section 5a, passed in memory over local
RPC, never as a command-line value or an extra public-key file. Check exit 0; check
the added line matches exactly 64 lowercase hexadecimal characters without
printing it; check key regularity, service ownership and exact mode 0600.
Check private parent mode 0700. **Abort** on failure; preserve an existing key
for owner-directed recovery, never retry destructively. Do not hash the key.

## 5a. Fund and bind the policy name on private regtest only

All commands here are **target-operator operations only**. The helper never
starts a node, generates/reads the retained private key, or broadcasts an
anchor. Run it only from the approved complete source checkout: its reviewed
sibling `scripts/reference.py`, `scripts/make-fixtures.py` and public fixture
inputs are required. Verify the checkout commit, file hashes and root-controlled
parent chain; do not execute it from a writable transfer directory. Keep
shell tracing, terminal/session capture and RPC/debug logging off. Never run
the general `regtest-service.py` harness against this installation.

The production node has `-disablewallet=1`. For this bounded commissioning
only, stop the node (notary has not started), install the exact reviewed
[commissioning.conf](commissioning.conf) drop-in, then verify the effective
unit and restart. The drop-in changes only wallet enablement and a regtest fee
fallback; both unit forms disable debug/console logs and retain every isolation
flag and all production sandboxing. No wallet recovery/import, external funding or
second node is permitted.

```sh
systemctl stop namecoind-regtest.service
install -d -o root -g root -m 0755 /etc/systemd/system/namecoind-regtest.service.d
install -o root -g root -m 0644 "$PACK_DIR/commissioning.conf" /etc/systemd/system/namecoind-regtest.service.d/commissioning.conf
systemd-analyze verify --man=no /etc/systemd/system/namecoind-regtest.service /etc/systemd/system/notary-service.service
systemctl daemon-reload
systemctl start namecoind-regtest.service
```

Check each exit 0, the installed drop-in hash, `systemctl cat` and effective
`ExecStart`, and repeat **all** section 4 chain/peer/listener/cookie/sandbox
checks. Require wallet support from the pinned Core build; abort if unavailable,
if an unknown drop-in exists, or if `id/certifier` or wallet `notary1-smoke`
already exists. Do not reuse/overwrite unknown chain or wallet state.

```sh
env -i PATH=/usr/sbin:/usr/bin:/bin HOME=/var/lib/notary1-install python3 -I "$PACK_DIR/smoke.py" prepare
```

Require exit 0 and only `PASS SMOKE_PREPARE` on stdout. The helper checks
`chain=regtest` and peers=0 before mining, creates one disposable local wallet
and address, mines **110** blocks (mature coinbase), calls `name_new`, mines
**12**, calls `name_firstupdate`, mines **1**, then checks the value, history,
registration and tip. Every failed RPC/check aborts; never continue from a
partial phase or rerun to overwrite state. It reads the receipt key into
memory and passes values with CLI `-stdin` (not argv); name_new randomness
and fresh fixture scalars are never written to files or output. The target
wallet necessarily retains its own throwaway mining/name-control keys in the
protected node state; no such wallet or secret is supplied by the pack.

Exact resolver contract (line citations are for pack base `0daeadfc`):
[README.md:142-144](../../README.md#notary-service-regtest-laboratory),
[DESIGN.md:41](../../DESIGN.md#exact-inputs), `name.go:10-16,17-81`,
`node.go:149-198`, and `internal/service/service.go:219-267`. The service
looks up **`policy.notary_name` = `id/certifier`**, not an unrelated test name.
The exact canonical UTF-8 value (no trailing newline) is
`{"swarma":{"notary":{"attest":"<64-lowercase-hex-receipt-public-key>"}}}`;
`smoke-binding.json` is its non-secret template. Do not add authority members,
spaces inside the authority span, or substitute a grant/nostr key.

The helper independently preflights a fresh Grant v3, `/2`, depth-1 bundle
with the actual registration pin, current tip, bounded current time window,
and strict D8 policy. It creates only protected `smoke-policy.json`,
`smoke-request.json` and `smoke-address.json`, all root:root 0600 under the
receipt directory; none contains the retained service public/private key.
Receipt fields record policy/request hashes and registration/tip, never key
copies. Check file modes, request size <=65536, strict mode omitted, exact
pair bindings and registration, and the independent preflight PASS before
explicitly approving this temporary policy. Failure **aborts** before signing.

```sh
install -o root -g root -m 0644 /var/lib/notary1-install/smoke-policy.json /etc/notary-service/deployment-policy.json
cmp /var/lib/notary1-install/smoke-policy.json /etc/notary-service/deployment-policy.json
```

Require exits 0 and hash equality; append the installed smoke-policy hash and
approval to the receipt. Do not edit service.json, limits, ports or mode. The
service must start **after** this provisioning: policy is loaded only at startup.
Do not mine concurrently; finish certification within the child's 30-minute
window or abort and reconcile the entire one-shot procedure.

## 6. Start and check the notary

Run `systemctl start notary-service.service`. The service UID copies the
group-readable cookie into its own 0600 regular file before the loader reads
it. Check that owner/mode and the two runtime directories against accounts.md
without reading credentials. Check both units active, the running executable
path/hash, and the service's effective hardening. `ss -ltnp` must show HTTP
**127.0.0.1:8080 only**. Abort and stop the newly started service on mismatch.

As a bounded refusal control, submit an empty object to the actual route:

```sh
env -i PATH=/usr/sbin:/usr/bin:/bin HOME=/var/lib/notary1-install python3 -I "$PACK_DIR/smoke.py" readiness
```

Require HTTP 422, body exactly `{"decision":"POLICY_REFERENCE"}` (JSON
whitespace aside), no signed fields, no anchor. Require exit 0 and only
`PASS SMOKE_READINESS` on stdout. The helper keeps even unexpected responses
in memory, never a response file, and records verdict/HTTP only in the receipt.
Any signature, unexpected decision, timeout or connection failure aborts.
This is readiness/refusal evidence, **not** the required positive smoke.

## 7. One positive certification beside the absent-binding refusal

```sh
env -i PATH=/usr/sbin:/usr/bin:/bin HOME=/var/lib/notary1-install python3 -I "$PACK_DIR/smoke.py" certify
```

Require exit 0 and only `PASS SMOKE_CERTIFY` on stdout. The helper checks
installed policy bytes/reference and unchanged tip, creates a one-shot
`certify.started` marker, and submits **ONE** valid Grant v3 `/2`, depth-1
request to the installed `127.0.0.1:8080/v1/attest` service. Require **HTTP 200,
`ATTEST`**, exact candidate bindings, independently verified BIP-340 under the
receipt key, and the exact **72-byte action-0x04 anchor frame**. It verifies
using `reference.py`, not the service's crypto/parser. It retains the response
only in memory: no response file, key copy, terminal/journal output or broadcast.
A timeout, bad status/body, signature/frame mismatch or moved tip **aborts**;
no automatic retry or second positive request is allowed.

Immediately beside it, the helper updates the **same local name** to `{}`
(binding absent), mines one block and verifies that value. It changes **only**
the request statement's necessarily new tip (otherwise `NODE_TIP_MISMATCH`
would mask the intended control), then submits the same signed bundle and
policy reference. Require **HTTP 422, body exactly `{"decision":"NOTARY_KEY"}`**,
with **no signed/candidate/anchor fields**. This exercises the own-node lookup
and the service's actual authority parser, not a wrong policy reference or
mock. The name remains registered and its registration pin is unchanged.
Any other refusal, a signature, timeout or transport failure is a failed smoke.
Both outcome fields and both request hashes go into the private receipt.

A `finally` step restores the correct VM-local binding, mines one confirmation,
and checks its value/history again; no second certification follows. Require
`binding_restored_private_regtest_only: PASS` and wallet unload success. If a
phase or restoration fails, **stop and disable both units**, retain key, wallet,
node state, marker and private receipt for owner-directed recovery under
[ROLLBACK.md](ROLLBACK.md). A marker is not permission to retry. Missing PASS
fields mean NOT_ACCEPTED; never claim a positive-only result as acceptance.

## 8. Return to the reviewed wallet-disabled configuration

Only after both smoke outcomes and restoration pass, stop both units, restore
the shipped strict fixture policy, remove only the receipt-matched temporary
drop-in, reload, and restart in dependency order. Check each exit status:

```sh
systemctl stop notary-service.service namecoind-regtest.service
cmp "$PACK_DIR/commissioning.conf" /etc/systemd/system/namecoind-regtest.service.d/commissioning.conf
# Run the unlink only after the preceding comparison and ownership checks pass.
rm -- /etc/systemd/system/namecoind-regtest.service.d/commissioning.conf
install -o root -g root -m 0644 "$PACK_DIR/deployment-policy.json" /etc/notary-service/deployment-policy.json
systemctl daemon-reload
systemd-analyze verify --man=no /etc/systemd/system/namecoind-regtest.service /etc/systemd/system/notary-service.service
systemctl start namecoind-regtest.service
systemctl start notary-service.service
```

Require installed-policy hash equals the original shipped hash, no remaining
drop-ins, effective `-disablewallet=1`, section 4/6 readiness and all sandbox/
listener checks again. The restored fixture policy authorizes no current fresh
bundle; smoke is not production commissioning or live-admission qualification.
The wallet remains private node state, not an export or separately loaded
service; default rollback keeps it. Do not delete its control keys implicitly.

Only after these checks, target authorization and all receipt PASS fields may
the operator enable both units with `systemctl enable namecoind-regtest.service
notary-service.service`; require both `is-enabled` checks and active checks.
Record enablement separately from smoke and deployment approval. Any failed
check stops/disables execution and follows the default KEEP rollback.

## Local installation receipt (private, do not commit or publish)

Store only at `/var/lib/notary1-install/receipt.md`, root:root 0600. No private
key/cookie content or hash. Hashes below cover public artifacts only. When
recording public config/unit hashes, include both approved and installed values.
The skeleton below names the fields, not commands to append blindly. Create the
public-key label **exactly once**, immediately before keygen, with no placeholder
line. Helper verdicts append to this receipt; the latest verdict supersedes an
initial NOT_RUN for that field, but prior failed outcomes remain for diagnosis.
No field may be marked PASS for an omitted check.

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
private_regtest_binding_authorization_reference:
commissioning_dropin_sha256_and_effective_checks:
binding_registration_and_tip:
smoke_policy_sha256_and_operator_approval:
installed_smoke_policy_sha256:
smoke_request_sha256:
smoke_prepare: NOT_RUN
positive_smoke_http_decision_signature_anchor: NOT_RUN
binding_absent_request_sha256:
binding_absent_control_http_decision_signed_fields: NOT_RUN
binding_restored_private_regtest_only: NOT_RUN
positive_smoke: NOT_RUN
wallet_unloaded_and_production_disablewallet_restored:
restored_installed_policy_sha256:
units_active_and_enabled:
rollback_or_retained_state_decision:
installation_outcome: NOT_ACCEPTED
```
