# notary1 regtest rollback

Only Infra's authorized guest operation executes this procedure, in the
approved window. Confirm the target is `notary1` and these units belong to
this installation. Preserve the private receipt; never print the key/cookie.
On unknown ownership or a failed check, abort removal and escalate to Infra.

1. **Stop and disable both units.** Run `systemctl stop notary-service.service
   namecoind-regtest.service`, then `systemctl disable notary-service.service
   namecoind-regtest.service`. Check both have `ActiveState=inactive` and
   `MainPID=0`, neither is enabled, and no remaining cgroup processes/listeners
   belong to them. A failed unit may need diagnosis; a nonzero stop result is
   not success. Do not kill processes by pattern or touch unrelated services.
   The normal stop removes the runtime directories and staged cookies; check
   `/run/notary-service` and `/run/namecoind-regtest` are absent. If processes
   remain, stop here; never remove live state.

2. **Remove only this pack's two installed units.** Compare each path/hash
   against the receipt before unlinking
   `/etc/systemd/system/notary-service.service` and
   `/etc/systemd/system/namecoind-regtest.service`. Abort on unknown overrides
   or a hash mismatch. If commissioning reached the wallet-enabled phase,
   compare `/etc/systemd/system/namecoind-regtest.service.d/commissioning.conf`
   with its receipt/pack hash and unlink **only that matched file**; abort on
   unknown overrides. This also applies to failure before the positive smoke.
   Run `systemctl daemon-reload`; check both fragments, the commissioning
   override and enablement links are absent and `systemctl cat` finds no substitute unit.
   Do not remove files in shared systemd directories by wildcard.

3. **Choose retained state explicitly (default: KEEP).** Record `KEEP` in the
   private receipt. Preserve `/var/lib/namecoind-regtest`,
   `/var/lib/notary-service`, the private key, config, verified binaries and
   locked accounts. Check their owners/modes against accounts.md and record
   that services remain stopped/disabled. Keeping the files is a successful
   rollback of execution, not a key erasure claim. Keep the private-regtest
   wallet and chain/name history, protected smoke artifacts, one-shot marker
   and both recorded outcomes. If the absent-binding control failed before
   restoration, record binding state as UNKNOWN (or the privately verified
   state); do not restart a wallet/node merely to change it during rollback.
   Never export the receipt, chain values or signed responses as evidence.

4. **Optional wipe requires the owner's explicit word and exact scope.**
   Record the decision reference and exact approved paths in the receipt
   before removing anything. Node-state removal does **not** authorize key
   removal. The key at
   `/var/lib/notary-service/private/attestation.key` is removed only if that
   path is separately and explicitly authorized. Confirm services stopped,
   no open files/processes, real paths (no symlinks), receipt ownership, and
   no mount/bind-mount/shared data underneath the selected state. If the
   owner selects node-only wipe, remove only `/var/lib/namecoind-regtest`
   after those checks and verify absence; preserve the entire service state.
   Node-only wipe includes its generated throwaway wallet/control keys and
   private name history, so the decision must explicitly cover that loss.
   Do not transfer the binding or publish any name/key as a rollback step.
   For an expressly authorized key wipe, unlink exactly the key path and
   verify absence without reading it. Do not claim physical secure erasure:
   VM snapshots, filesystem journals, storage and backups require the owner's
   separate retention/erasure procedure. Abort on an unexpected path or
   inability to establish custody. Never use a broad `/var/lib` deletion.

5. **Optional artifact/account cleanup is separate.** Remove only receipt-
   matched pack configs and the version-specific notary executable if Infra
   explicitly includes them; check absence. Preserve Core if shared with any
   other role. Do not delete accounts/groups until Infra confirms no retained
   files or other S8 consumers need them. Keep the receipt private even when
   other state is wiped. Record each executed command's real status, retained
   paths and final stopped/disabled state; do not report omitted steps as run.
