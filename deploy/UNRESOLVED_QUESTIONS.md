# DK1 scope decisions

## Gateway runtime and host inputs

GW1 resolves the original stub-wiring blocker with real v3 kernel/E1 constructors,
remote station-lifecycle gatewaybind, explicit screening off and gateway templates.
The operator still must choose/provision the real pinned payload and manager,
TLS chains/leaf pins, observer route, public presentation transfer and approved
station-host CIDR. The r4 helper binding uses persisted boot-time freshness for
uncertain Create reconciliation; legacy no-fence attempts stay pending. Real
helper compatibility still requires host acceptance. Never enable the test driver
or stub kernel/screener as a production grant enforcer.

## Linux unit validation environment

No local Linux container runtime/systemd-analyze is available, and installed Lima
has no instances. Report systemd-analyze verification as not run unless a usable
authorized environment becomes available. The maintainers explicitly prohibit
creating a Lima VM for this task. Infra must run systemd-analyze verify on the public host
before the first start; SMOKE.md records that gate.

## Deployment inputs remain operator-owned

Template keys/hashes, branch/profile pins, calendar/rate data, release version,
pinned Linux namecoin-cli, provider key,0400 RPC config and existing relay are
not guessed by this kit. Infra resolves them through the agreed custody and
installation flow. The public validator does not certify unseen native files or
credential contents. No live host or mainnet action is part of DK1 delivery.

## Optional model-proxy operator inputs

The operator must explicitly supply proxy UID, admin socket ownership/access,
HTTPS origin, leaf pin and every approved token/request/cost cap. The optional
fragment deliberately supplies no numerical allowance. Production Unix peer
qualification requires Linux; a compiled Linux binary is not acceptance evidence.

## DK2 host prerequisites

- Infra owns the unlanded slotd helper/root-policy schema and the actual per-slot
  bootstrap/argv placement. The payload requirements table is not installable
  policy and cannot establish a real Linux lifecycle/wipe.
- Infra must provision a private append-only booking/operator intake mirror on
  the signer host and confirmed presentation transport to the gateway. Native
  signer S1 access is loopback HTTP only; an explicitly qualified local forwarding
  route to the public store is required. No a2a daemon (a2ad) or network fallback is added.
- Gateway and model proxy admin socket must share one host. Approved UID/group,
  TLS, model table, prices, per-slot caps and provider/station egress CIDRs remain
  deployment inputs. Existing socket/state is preserved on refusal.
- Signer activation can process/refill funds. Exact owner approval and provisioned
  caps/keys/inventory are prerequisites; `-once` is not a harmless config probe.
- Mainnet remains refused by both kit and signer. All owner-unapproved proposal
  values remain placeholders. Full host acceptance remains external to this kit.
