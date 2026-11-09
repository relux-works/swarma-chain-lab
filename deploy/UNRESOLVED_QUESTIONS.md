# DK1 scope decisions

## Gateway runtime and host inputs

GW1 resolves the original stub-wiring blocker with real v3 kernel/E1 constructors,
remote station-lifecycle gatewaybind, explicit screening off and gateway templates.
The operator still must choose/provision the real pinned payload and manager,
TLS chains/leaf pins, observer route, public presentation transfer and approved
station-host CIDR. The r2 helper binding retains uncertain cleanup as pending;
newer protocol revisions need separate integration. Never enable the test driver
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
