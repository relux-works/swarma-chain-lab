# DK1 scope decisions

## Gateway CLI is not an operational E1 service

At base5f148fb9, `cmd/gateway/serve.go` constructs a stub kernel (default live),
stub screener and local-test station driver, with no E1/booking engine wiring.
The request also forbids product code changes. A service template cannot make
this executable into a real grant-checking exchange gateway.

The survey recommends building it as a demo-only artifact and marking its M5
runtime/unit blocked until a separately tracked real entrypoint lands. Runnable
units can be supplied now for booking/store. The orchestrator has been asked to
confirm this scope or request a non-startable gateway reference template. Do not
silently enable the stub in a service claimed to enforce real grants.

## Linux unit validation environment

No local Linux container runtime/systemd-analyze is available, and installed Lima
has no instances. Report systemd-analyze verification as not run unless a usable
authorized environment becomes available. No VM/host provisioning is implied.
