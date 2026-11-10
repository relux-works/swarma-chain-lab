# Configured gateway integration decisions

The initial source survey is in [SERVE-SURVEY.md](SERVE-SURVEY.md); current
implementation and command evidence are described in [SERVE.md](SERVE.md).

Resolved boundaries:

- Booking uses a bounded read-only catalogue HTTP endpoint and a thin client
  for typed ServiceV2 routes. The provider key remains outside the gateway.
  Explicit booking version and offered coins are provisioned alongside the
  template hash; the coin list must match ServiceV2 config because its catalogue
  does not advertise it. V1 is test-only. Privacy matches the existing signed
  constant; V2 consent keeps the established kind-8181 tag.
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

RK1 reconnect is bounded NIP01 replay, not a delivery-ack protocol. Operators
must align the gateway replay limit with the relay cap and retain enough history;
equal-timestamp overflow is counted/logged and leaves the live subscription
running. Universal recovery past retention, ingress overflow or unacknowledged
application effects needs a future cursor/ack contract. Expiry End remains
distinct from explicit closer DestroySlot completion.

DA1 adds the application reply outbox described in [DELIVERY.md](DELIVERY.md).
It does not add a third-party renter inbox/display receipt, remote model-result
lookup (DA1b), or supervisor restart/provisioning policy (Infra/DK5b). Retain
per-slot journals across restart; do not reset them to recover availability.

DA1 r1 requires an explicit `relay_max_event_bytes` deployment assertion, not
remote discovery. Match or undercut the deployed relay cap. Shared sizing covers
both NIP44 layers and full event bytes; oversized results become a durable fixed
notice. The default65536 cap therefore converts32768-byte plain results to that
notice. Chunking remains outside this change. See DELIVERY.md.
