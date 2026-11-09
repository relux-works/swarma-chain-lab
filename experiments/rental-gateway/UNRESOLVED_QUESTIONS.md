# Configured gateway integration decisions

The initial source survey is in [SERVE-SURVEY.md](SERVE-SURVEY.md); current
implementation and command evidence are described in [SERVE.md](SERVE.md).

Resolved boundaries:

- Booking uses a bounded read-only catalogue HTTP endpoint and a thin client
  for existing v1 routes. The provider key remains outside the gateway. V2 is
  not a constructor-only switch and remains separate work. Privacy must match
  the signed v1 constant.
- An operator-pinned read-only directory supplies public presentations by booking
  ID through atomic external publication. The gateway cannot issue grants.
- The remote station manager connects out to a gateway mTLS poll endpoint;
  transport authority requires verified chains and the exact manager leaf pin.
  Station payloads connect separately using server TLS with the gateway leaf
  pinned, then existing per-slot stationlink HMAC. No manager key or agent key
  is copied to a station, and no station client certificate is required.
- Host authority belongs to a root-owned slot helper and its operator policy.
  The gateway does not mirror user/home/egress/resource rules or execute the
  landed LinuxUser command planner. Executor/Track B provisioning is absent.

Remaining dependencies:

1. The integrated signed `station-lifecycle/gatewaybind` adapter uses the r4
   CLOCK_BOOTTIME/boot_id freshness fence. The real Linux helper must implement
   that exact contract; compilation/fake-helper tests do not prove host
   interoperability. Legacy r2 attempts without a fence stay conservative.
2. Host owners supply gateway/manager TLS material and pins, root-helper policy,
   executable payload, private RPC route, booking service, relay and public
   presentation transfer. No host provisioning is implied by this repository.
3. A real rented-agent payload/runtime is still an external choice. Neither the
   scripted local-test agent nor simulated manager reports are a production
   payload. Gateway templates require an explicit payload label/hash and host
   allowlist; there is no permissive default.

Genuine-Core local CLI evidence is available under explicit test mode. Linux
helper execution, systemd enforcement and deployment remain separately required
verification; passing fake-host tests cannot stand in for those observations.
