# DK2 host installation and smoke gates

DK5 prerequisite: follow [INSTALL-CONFIG.md](INSTALL-CONFIG.md) before any native
validation/start below. Static configs/secrets are now root:exclusive-service-group
0640 with0750 parents and a signed private resolved manifest/root anchor. Dynamic
bootstrap and mutable state keep their separate contracts. Qualify actual Linux
permissions and group separation; this runbook is not evidence of execution.

This is an Infra runbook, not a record of executed host commands. All commands
below are for an explicitly authorized installation with the reviewed signed
release and owner-provisioned credentials. This producer task installs nothing.
Never use `set -x`, print a private config, export a wallet/key or put a secret
in argv/environment. Keep failures and existing state; do not reset a ledger,
remove a stale socket or recycle a slot to turn a refusal into success.

## 1. Release workstation: all eight binaries

Follow SMOKE.md's signature/manifest checks first. The product artifact set is
`gateway`, `rental-booking`, `grant-store`, `swarma-relay`, `swarma-signer`,
`model-proxy`, `station-manager`, `station-payload`. All eight have two matching
linux/amd64 build outputs from independent archives/caches. `station-manager`
uses ordinary Linux transport, never the `slotdfake` tag. a2a daemon (a2ad) is still a
pending manifest row. No payload standalone unit exists.

With the reviewed source checkout and cached pinned dependencies:

```sh
go -C "$SOURCE_ROOT/deploy" build -trimpath -o "$DEPLOY_KIT" ./cmd/deploy-kit
"$DEPLOY_KIT" build -repo "$SOURCE_ROOT" -commit "$REVIEWED_COMMIT" -out "$RELEASE_DIR"
(cd "$RELEASE_DIR" && sha256sum -c SHA256SUMS)
```

Use the separate approved release-signing procedure in SMOKE.md; build does not
sign, install or start anything. Provision the same reviewed deploy-kit tool for
public-input validation on each host. Do not rebuild the product binaries on
hosts or combine binaries from different manifests.

Prepare public staged descriptors/native configs. Replace every placeholder,
using only owner-approved values. Preserve model/manager canonical field order
and encode numeric fields as integers. `payload/deploy.json` has empty config,
state and listener because the executable has flags, not a native service file.

```sh
"$DEPLOY_KIT" validate -config "$STAGING/issuer/deploy.json" -public "$STAGING/issuer/service.json"
"$DEPLOY_KIT" validate -config "$STAGING/model/deploy.json" -public "$STAGING/model/service.json"
"$DEPLOY_KIT" validate -config "$STAGING/stations/deploy.json" -public "$STAGING/stations/service.json"
"$DEPLOY_KIT" validate -config "$STAGING/payload/deploy.json"
```

These commands never open referenced credential files and cannot prove mode,
key/cert correspondence or a functioning node. No private route/key file is a
`-public` argument. Do not use signer `-once` as validation: it can process an
issuance or refill and broadcast money-bearing transactions.

## 2. Infra provisioning before any service start

Keep the release paths root-owned and non-writable by services. Select one
`RELEASE_VERSION` from the verified manifest, install each binary under its
corresponding versioned path and retain old signed releases for diagnosis:

```sh
sudo install -d -o root -g root -m 0755 "/opt/swarma/issuer/$RELEASE_VERSION/bin" "/opt/swarma/model/$RELEASE_VERSION/bin" "/opt/swarma/stations/$RELEASE_VERSION/bin" "/opt/swarma/payload/$RELEASE_VERSION/bin"
sudo install -o root -g root -m 0755 "$RELEASE_DIR/bin/swarma-signer" "/opt/swarma/issuer/$RELEASE_VERSION/bin/swarma-signer"
sudo install -o root -g root -m 0755 "$RELEASE_DIR/bin/model-proxy" "/opt/swarma/model/$RELEASE_VERSION/bin/model-proxy"
sudo install -o root -g root -m 0755 "$RELEASE_DIR/bin/station-manager" "/opt/swarma/stations/$RELEASE_VERSION/bin/station-manager"
sudo install -o root -g root -m 0755 "$RELEASE_DIR/bin/station-payload" "/opt/swarma/payload/$RELEASE_VERSION/bin/station-payload"
```

Run only the relevant install lines on each host: issuer on the signer host,
model on the public host, manager/payload on the stations host. The distinct
system users must already be provisioned by Infra. Inspect their UID/GID without
changing an existing identity:

```sh
id swarma-issuer
id swarma-model
id swarma-stations
```

Use the applicable account on its host; pin the gateway UID in model config and
model UID in gateway config. Only the gateway gets the approved model socket
group membership. Only the manager gets the approved slotd socket group. A group
change does not replace peer-UID admission.

Infra provisions private files directly through its existing custody mechanism,
with the exact owner/file/parent modes in README. Never copy keys out of custody
to populate this runbook. Check metadata only; this example lists explicit
paths, not a recursive dump:

```sh
sudo stat -c '%a %U %G %h %n' /etc/swarma/issuer /etc/swarma/issuer/service.json /etc/swarma/issuer/grant.key /etc/swarma/issuer/funding.key /etc/swarma/issuer/read-route.json /etc/swarma/issuer/broadcast-route.json /etc/swarma/issuer/payment-nmc.json
sudo stat -c '%a %U %G %h %n' /etc/swarma/model /etc/swarma/model/service.json /etc/swarma/model/tls.pem /etc/swarma/model/tls.key /etc/swarma/model/api.key
sudo stat -c '%a %U %G %h %n' /etc/swarma/stations /etc/swarma/stations/service.json /etc/swarma/stations/client.pem /etc/swarma/stations/client.key /etc/swarma/stations/gateway-ca.pem
```

Repeat the issuer payment-file row for every explicitly configured coin. Require
single links, exact ownership/modes and symlink-free parents; `stat` alone does
not verify every ancestor. Infra's provisioning checks must establish those.
The scripts do not generate any custody key or approve proposed caps.

Before the first issuer start, provision0700 issuer-owned `ledger`, `issuance`,
`intake/booking` and `intake/operator` roots below `/var/lib/swarma-issuer`, plus
its root0700. Provision `presentations` as0755 (output files0644), separately
from private intake. Original outbox indexes/items must be copied by Infra's
verified append-only transport into issuer-owned0700/0600 private mirrors. Do not
share the booking user's live directory, rewrite indexes, fabricate Items or
turn a missing source into an empty one. Operator intake starts only with a
verified empty index or actual authorized records supplied by that transport.

## 3. Public host and signer host: dependencies and money authority

Install/qualify the original booking/store/relay services per SMOKE.md before
custody. Each configured payment node is an own-node dependency with separately
scoped booking `payment-observer` and signer `payment-issuer` credentials. Signer
identity reads use `w3-observer`; broadcast uses distinct `sg1-broadcaster`, same
literal loopback endpoint, with only `sendrawtransaction` authority. No node
wallet secret or general wallet RPC belongs in the deploy bundle.

The signer binary accepts S1 only at literal-loopback HTTP. This profile fixes
`http://127.0.0.1:8091`. Infra must establish and qualify an approved forwarding
route to the public store, or colocate an explicitly selected store endpoint;
this kit supplies no tunnel or a2a daemon. Similarly, confirmed signer presentations
must reach the gateway's configured directory through Infra's explicit transport.
Neither transport may export signing keys, private RPC routes or model credentials.
No unit may start while these prerequisites are undefined.

After G6 lands, compare the **installed public** gateway and ServiceV2 configs on
the public host, and repeat after either changes:

```sh
"$DEPLOY_KIT" check-coins -gateway /etc/swarma/gateway/service.json -booking /etc/swarma/booking/service.json
```

Expected output is exactly `COIN_SETS_MATCH`. The command requires versions2,
explicit nonempty closed coin sets, no duplicates and exact equality independent
of order. It never probes a coin or adds one. ServiceV2 still rejects an
unconfigured coin before a hold. Run each native/deploy config validator too:
coin equality does not validate prices, branches, template hash or consent terms.
With pre-G6 input this check must refuse; do not claim a legacy smoke pass.

Render only relevant unit templates after all placeholders and network policies
are approved. Model ingress is TLS end-to-end to its pinned native leaf; if a
reverse proxy is used, preserve that TLS endpoint with a separately qualified
L4 route. Do not substitute a terminating HTTP proxy certificate for the pinned
model certificate. Set descriptor/native model listen address together; its
port must equal the advertised HTTPS origin's port. The model unit allows only
loopback plus approved provider/station CIDRs, including any required DNS route.
Dynamic provider addresses are an Infra egress policy input, not an implicit
allow-all exception.

```sh
sudo systemd-analyze verify /etc/systemd/system/swarma-issuer.service
sudo systemd-analyze verify /etc/systemd/system/swarma-model.service
sudo systemctl daemon-reload
```

Run each verification on its host. Model config has no dry-run switch: do not
invent `-check`. After explicit activation authorization, start model; starting
it alone makes no generation request but does read the API key and opens listeners:

```sh
sudo systemctl start swarma-model.service
sudo systemctl is-active swarma-model.service
sudo stat -c '%a %U %G %n' /run/swarma-model /run/swarma-model/admin.sock
```

Require model-owned parent0750/socket0660 and both peer UID pins. RuntimeDirectory
is the only extra writable directory beyond persistent model state. A failed or
existing socket requires operator reconciliation; no automatic deletion appears
in the unit. Before starting the gateway with model config, verify its socket
access from the gateway UID using Infra's native peer-credential smoke. Rejection
from another UID and a valid authorized registration must both be demonstrated
in an isolated approved binding; filesystem metadata alone is insufficient.

**Signer start requires the owner's exact GO**, approved caps, verified native
key/policy pins and explicit confirmed inventory. An approved cap is not
permission to enroll arbitrary UTXOs. Do not run `-once` or start/restart the
signer as a harmless test. After that separate authorization:

```sh
sudo systemctl start swarma-issuer.service
sudo systemctl is-active swarma-issuer.service
```

Use only the signer's fixed result records and public transaction locators for
evidence. Preserve uncertain reservations and ledger state. No raw keys/routes,
private config or grant bodies are printed by this runbook.

## 4. Stations host: actual helper, manager and payload

Infra installs and independently qualifies the root-owned slotd helper first.
Use the pinned v1r4 wire and its reviewed root-policy schema. The table in
`templates/payload/POLICY-NEEDS.md` supplies the executable/hash/argv/bootstrap
needs; it is not a loadable policy. Fill those needs in Infra's schema, then
bind the same payload hash and label in manager and gateway. Confirm disjoint
numeric ranges. No helper install, user creation or root policy mutation is
performed by station-manager.

```sh
sudo stat -c '%a %U %G %n' /run/swarma-slotd-demo /run/swarma-slotd-demo/sock
sudo -u swarma-stations "/opt/swarma/stations/$RELEASE_VERSION/bin/station-manager" check-config --config /etc/swarma/stations/service.json
sudo systemd-analyze verify /etc/systemd/system/swarma-stations.service
```

Require root parent0750/socket0660 and correct manager group/peer admission.
`check-config` reads local mTLS files and checks public input without contacting
the helper/gateway or creating state. It does not prove the socket ACL, boot
clock or host effects. Qualify the actual helper's wrong-UID and wrong-policy
refusals using Infra's reviewed isolated fixture, alongside a valid lifecycle.
Never use somebody else's slot as a negative test.

After the public gateway manager/payload listeners and the actual helper are
qualified, and activation is authorized:

```sh
sudo systemctl daemon-reload
sudo systemctl start swarma-stations.service
sudo systemctl is-active swarma-stations.service
```

There is no `systemctl start` for payload. Infra's helper launches the fixed
executable under its per-slot user with slot-owned0600 dynamic bootstrap and root:exclusive-slot-group0640 static CA and pinned
argv. The full disposable-regtest acceptance is: explicit V2 renter terms and
consent, confirmed own-node payment, real signer issuance/publication, gateway
issued/ready, manager/helper start, payload channel delivery and model accounting
against an approved fake upstream, cap refusal without retries, expiry cleanup,
and early revoke. Model tests alone do not establish this chain. A paid real
upstream test requires separate exact approval and is not part of this runbook.

Capture signed source/release hashes, public stage results and direct process
receipts without exporting private fixture directories. A local crossbuild or
Darwin fake helper is not evidence of Linux peer credentials, actual host wipe
or production readiness. Stop at the first failing gate and name it precisely.
