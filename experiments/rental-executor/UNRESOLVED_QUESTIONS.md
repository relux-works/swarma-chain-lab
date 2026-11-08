# M4a integration boundaries

- Independent review, hosted checks and orchestrator publication/landing remain
  required. Producer tests are not ACCEPT. M1 pin is 63087f31; review/rebase must
  preserve or explicitly update the dependency head and rerun integration.
- Deployment owns OS identities, socket proxy/mTLS, node capability configuration,
  custody provisioning and key backup. This experiment runs on isolated regtest,
  not the proposed public hosts or actual station users.
- Publish/repository.push remain documented local stubs; secret.release always
  refuses. Delivery proxy, seven-day deletion worker, final renter notifications
  and per-slot close/report orchestration remain integration work.
- Fixed fees and finite explicit budget input sets are intentional; change is
  not automatically reused. A fee below node policy fails and burns a reservation
  once attempted. Production fee estimation/input replenishment need separate
  design, not implicit wallet fallback. Unknown outcomes require reconciliation.
- Track B mint reply loss cannot remint the same slot. Audit/journal limits fail
  closed and need an operator lifecycle before production; no log rotation or
  removal of replay/closure evidence is authorized here.
- Trusted node/clock/service UID assumptions and observation-to-effect races
  remain. The tests simulate process interruption and persistence failures, not
  hardware power loss, hostile kernels or private key extraction resistance.
