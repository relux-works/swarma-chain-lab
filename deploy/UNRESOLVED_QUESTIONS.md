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
