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

1. Integrate the signed `station-lifecycle/gatewaybind` adapter with its exact
   numeric allocation-range contract. Its host helper protocol must expose
   enough immutable binding and payload evidence; unsupported claims must refuse.
2. Finish remote-mode config/listeners and deploy-kit gateway templates after
   that adapter and deploy kit are available on the integration base. Until
   then real manager startup refuses, and no deployable release is claimed.
3. Host owners supply gateway/manager TLS material and pins, root-helper policy,
   executable payload, private RPC route, booking service, relay and public
   presentation transfer. No host provisioning is implied by this repository.

Genuine-Core local CLI evidence is available under explicit test mode. Linux
helper execution, systemd enforcement and deployment remain separately required
verification; passing fake-host tests cannot stand in for those observations.
