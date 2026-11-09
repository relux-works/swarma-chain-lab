# Infra install and smoke plan (regtest only)

This is a plan for Infra, not evidence of a host deployment. The public host runs
linux/amd64. Nothing here authorizes a mainnet transaction, creates wallet keys,
changes custody, or bypasses host acceptance. Keep existing state and keys.
Signer, Courier and Nostr transport are pending manifest rows, not services to
guess or install from this kit.

## 1. Release workstation: build, review and sign

Use a clean reviewed commit that contains this kit, Go1.26.8 and dependencies
already downloaded and verified in the module cache. Do not build on the public host.
The commit must equal the clean checkout's HEAD. Choose a new absolute output
directory outside the source repository. From `deploy/`:

```sh
go run ./cmd/deploy-kit build -repo "$SOURCE_ROOT" -commit "$REVIEWED_COMMIT" -out "$RELEASE_DIR"
```

The program builds all three requested Linux binaries twice with separate source
trees and build caches. It emits bin/, native public config/unit templates,
README, this plan, manifest.json and SHA256SUMS, but never signs. Gateway's
regtest-preparation row explicitly records screening off. The manifest's Go version, commit,
target and every binary hash must match the approved handoff.

The release signer uses the approved signing environment/key and namespace;
replace `SIGNING_KEY` with that configured public signing-key reference:

```sh
ssh-keygen -Y sign -f "$SIGNING_KEY" -n swarma-release "$RELEASE_DIR/SHA256SUMS"
```

Do not print/copy a private key. The signature authenticates the checksum list,
which includes manifest and all shipped templates. It proves the accepted demo
signing identity, not a distinct per-lane custody boundary.

## 2. Infra: verify the unopened release before installation

With the operator-provisioned allowed-signers file and expected identity:

```sh
ssh-keygen -Y verify -f "$ALLOWED_SIGNERS" -I "$SIGNER_ID" -n swarma-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
```

Refuse any failed signature/hash, unexpected manifest commit/target/status,
or unsigned substituted file. Signed templates are intentionally incomplete;
keep the original release immutable and render host configs into a separate
staging directory. A checksum success is not evidence that a placeholder config
is deployable or that gateway grants are enforced.

## 3. Infra: prepare existing service identities and public configuration

Confirm service users `swarma-gateway`, `swarma-booking` and `swarma-store`. For the chosen release
version, install the matching binaries into:

```text
/opt/swarma/booking/VERSION/bin/rental-booking
/opt/swarma/store/VERSION/bin/grant-store
/opt/swarma/gateway/VERSION/bin/gateway
```

Directories and binaries are root-owned; binaries mode0755. Public native JSON,
profile and deploy descriptors go under `/etc/swarma/booking/` and
`/etc/swarma/store/`, root-owned0640 with the corresponding service group.
Existing `/var/lib/swarma-booking` and `/var/lib/swarma-store` remain service-owned
0700. Do not clear them to obtain a clean smoke run. Existing keys, journals and
allocated address indices are retained across restart/upgrade.

Fill every PLACEHOLDER/@VERSION@ from reviewed deployment inputs. Booking needs
the regtest public branch/hash, public identity pins, public profile bytes/hash,
canonical template hash/scope, current rate/as-of time and bounded future slots.
Zero rate/time/slot fields are invalid template sentinels, not working defaults.
`profile.bin` is an operator-provided public artifact; do not fabricate it or
silently substitute a permissive profile. Update hashes using the product's
canonical representation, not a pretty-printed JSON file hash. S1's writers are
landlord public keys only; it has no server private key.

Booking provider key remains in its existing0600
`/var/lib/swarma-booking/provider.hex`; neither validator nor smoke reads it.
Infra provisions the service-owned0400
`/var/lib/swarma-booking/rpc/namecoin.conf`, targeting only127.0.0.1:18443 with
the approved read-only rpcauth identity. Do not put credentials in unit files,
environment variables, argv, public JSON, logs or release artifacts. The pinned
native namecoin-cli reads this private file. `NodeDataDir` is the separate
service-owned client directory `/var/lib/swarma-booking/rpc/client`, not the node
datadir or any wallet. Match NodeCLI's linux/amd64 path/hash to Infra's approved
binary. The current adapter read set is getblockchaininfo, getblockhash,
getblockheader, getrawtransaction, gettxout, name_show, getrawmempool and getblock;
do not broaden it merely because another draft describes nine methods.

Validate public staged configuration on the release workstation with the kit:

```sh
go run ./cmd/deploy-kit validate -config "$STAGING/booking/deploy.json" -public "$STAGING/booking/service.json" -public "$STAGING/booking/operator-route.json"
go run ./cmd/deploy-kit validate -config "$STAGING/store/deploy.json" -public "$STAGING/store/service.json"
```

These commands never read referenced credential files. The deploy descriptor
fixes regtest, loopback endpoints and file paths; supplemental public files are
checked for duplicate keys, placeholders, inline secrets and conflicting network
markers. This is not the service's full native schema/cryptography/clock check.
Infra must keep descriptor, rendered unit and native configs consistent; native
startup performs the final checks. No validator result authorizes a mainnet run.

## 4. Infra: systemd validation before any service start

Replace @VERSION@ in the three provided `.service.in` files; gateway additionally
requires PLACEHOLDER_STATION_HOST_CIDR from the approved host network policy.
Stage the gateway, booking and store units through the reviewed Infra procedure.
Gateway allows loopback plus that station-host CIDR, with no arbitrary egress
exception. Ensure its literal listen addresses, ports and approved incoming
manager/payload routes match the rendered native config and deployment policy.

On the public host, before starting services:

```sh
systemd-analyze verify /etc/systemd/system/swarma-gateway.service /etc/systemd/system/swarma-booking.service /etc/systemd/system/swarma-store.service
systemctl daemon-reload
```

Refuse a unit verification failure, unresolved placeholder or unavailable
hardening directive. Check that systemd's IP filtering is supported on this host;
do not claim its enforcement from static template text. No local Linux VM was
available during DK1 production, so this verification is **not run** here and
remains Infra's required gate. No Lima VM is created for it.

## 5. Infra: dependency order and bounded availability probes

1. Confirm existing `namecoind-regtest` is up with its separate datadir, no P2P
   listener, and loopback18443 RPC. Never inspect or modify the adjacent mainnet
   instance. Use service status and the pinned read-only CLI only:

   ```sh
   systemctl is-active --quiet namecoind-regtest.service
   ```

   As the booking OS user, substitute the approved CLI version in these public
   arguments; none contains an RPC secret:

   ```sh
   /opt/namecoin/VERSION/bin/namecoin-cli -conf=/var/lib/swarma-booking/rpc/namecoin.conf -datadir=/var/lib/swarma-booking/rpc/client -chain=regtest -rpcclienttimeout=2 getblockchaininfo
   /opt/namecoin/VERSION/bin/namecoin-cli -conf=/var/lib/swarma-booking/rpc/namecoin.conf -datadir=/var/lib/swarma-booking/rpc/client -chain=regtest -rpcclienttimeout=2 getblockhash 0
   ```

   Require chain=regtest, not initial-block-download, and genesis
   `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`.
   Capture only these public projections/statuses, never config contents.

2. Confirm the existing bounded booking relay is listening at127.0.0.1:18818
   through its Infra-owned service/probe. `rental-relay` was surveyed as a local
   test helper but is not included in this release's three-service scope. A
   missing relay blocks booking readiness; do not silently start a test relay.

3. Start store and booking through Infra's normal service controls:

   ```sh
   systemctl start swarma-store.service
   systemctl is-active --quiet swarma-store.service
   systemctl start swarma-booking.service
   systemctl is-active --quiet swarma-booking.service
   ```

4. Run bounded probes without response bodies or credentials:

   ```sh
   curl --noproxy '*' --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}\n' http://127.0.0.1:8091/0000000000000000000000000000000000000000000000000000000000000000
   curl --noproxy '*' --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}\n' http://127.0.0.1:18819/
   ss -ltn '( sport = :8091 or sport = :18819 or sport = :18443 )'
   ```

   Require401 for unsigned S1 access and200 for booking GET/. Require127.0.0.1
   binds, no wildcard exposure. Do not call /book, /consent, grant upload or any
   payment/broadcast command just to prove availability. S1 OPTIONS204 alone is
   not the authorization-path probe. Booking GET/ does not prove watcher health.

5. Preserve public status/hash evidence and report failures. Do not dump full
   journals, RPC configs or key files into diagnostics. No automatic state reset,
   alternate credentials, permissive firewall or stub gateway fallback is allowed.

## 6. Acceptance boundary

Gateway needs separate preparation before its first start. Fill every gateway
native-config and deployment-policy placeholder; use real pinned regtest agent,
landlord/issuer/seal, booking and payload facts. Supply the 0600 agent key,
0400 observer route and TLS server key through their existing custody flow.
Provision private 0700 state directories, the read-only atomic presentation
source, server certificate/manager CA and exact leaf pins. Run both validators:

```sh
deploy-kit validate -config "$STAGING/gateway/deploy.json" -public "$STAGING/gateway/service.json"
gateway validate -config "$STAGING/gateway/service.json"
```

The native validator rejects test mode and local/stub selections. Startup also
checks private inputs and TLS pins. Match the manager's range and payload policy;
payloads need their operator-pinned gateway address, trust roots and leaf hash,
then the private v1 bootstrap for stationlink HMAC. No scripted test payload is
an approved rented-agent runtime. The manager/helper host is provisioned and
accepted separately; this kit does not install it. Verify the helper implements
the exact r4 boot_id/CLOCK_BOOTTIME freshness fence. Unknown cleanup stays
pending until the stored binding or a valid fenced absence proves it. Verify real remote start, expiry,
restart and cleanup against the host before claiming operational acceptance.

This smoke establishes installed identity/hashes, regtest read route, process
availability, loopback listener bounds and S1's unsigned-access refusal. It does
not establish full M5 rental/issuance/signing/exchange acceptance. SG1/Courier/
transport deployment is not in this kit. Infra and the lane
must finish the separate genuine regtest end-to-end acceptance before any later
mainnet decision. Ivan's exact GO and caps remain required for mainnet transactions.
