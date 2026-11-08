# M4a integration boundaries

- Independent review, hosted checks and orchestrator publication/landing remain
  required. Producer tests are not ACCEPT. Integrated M1 baseline is c94b116d; review/rebase must
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
- Track B mint reply loss cannot remint the same slot. Claim windows and rolling
  audit tails are bounded; complete audit retention is deployment work. Token
  revocation and executor replay evidence are never evicted. The executor journal
  still has its 10,000-reservation capacity and needs an operator lifecycle.
- Trusted node/clock/service UID assumptions and observation-to-effect races
  remain. The tests simulate process interruption and persistence failures, not
  hardware power loss, hostile kernels or private key extraction resistance.
