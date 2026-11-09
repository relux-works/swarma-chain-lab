# Deployment and follow-up boundaries

- Explicit NMC-main configuration is supported; live node/custody qualification,
  funding and monitoring remain separate operator work. No local test grants
  spending authority. The hot cap measures enrolled exposure, not total wallet
  balance; out-of-band custody funding needs external monitoring.
- Remote pull/mTLS must preserve the original signed kind8182 PackageEvent.
  The local V2 exporter now emits the exact SG1 intake and companion event.
- Cross-host distribution of confirmed public presentations remains external;
  enabling the publisher on an existing custody ledger needs an explicit
  configuration-migration design. This unit never resets that binding.
- The64-record ledger/inventory/intake bounds are intentional bounded limits.
  A production retention/archival/migration design must preserve all burns,
  historical seal keys, unresolved reservations, caps and source checkpoints.
- Confirmed grant-key rotation freezes this custody configuration. There is no
  automated key migration, old-journal deletion or uncertainty release.
- S1 endpoint is loopback-only in this unit. Remote deployment and credential
  provisioning belong to the infrastructure/owner lane, not service startup.
- The service has no executor/execproxy/Track B or closer/session lifecycle scope.
