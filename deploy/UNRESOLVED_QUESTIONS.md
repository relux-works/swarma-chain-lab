# DK1 scope decisions

## Gateway CLI is not an operational E1 service

At base5f148fb9, `cmd/gateway/serve.go` constructs a stub kernel (default live),
stub screener and local-test station driver, with no E1/booking engine wiring.
The request also forbids product code changes. A service template cannot make
this executable into a real grant-checking exchange gateway.

Resolved: package the existing binary as a non-startable reference, with manifest
status blocked on real serve wiring. Supply no gateway unit. Booking/store units
continue in DK1. Real v3 kernel/E1/station/screening wiring belongs to future GW1;
its request follows separately. Never enable the stub as a real grant enforcer.

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
