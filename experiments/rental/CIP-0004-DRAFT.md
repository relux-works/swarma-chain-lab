# CIP-0004 draft: confirmed seal pool and offline plans

Status: M1 handoff draft, regtest evidence only.

A station keeps ordinary P2PKH outputs at its pinned name-owner address.
Refill makes N equal outputs (1..16, at least 100000 sat each) from explicit
legacy funding prevouts. Confirm them before issuance. A seal is referenced,
never consumed, by the issuance transaction; its confirmation height must be
strictly below the name_update anchor's height.

Issue takes the signed certificate plus M3 request/package, verifies bindings
offline, and plans exactly one name_update back to the same pinned script,
one zero-value 6a20 envelope-hash output, and change to the pinned script.
The name output remains 1000000 sat. All funding/name prevouts and values are
explicit. No hidden wallet selection, signing or network operation occurs.
An operator-supplied pool observation is not proof of current chain state.

Revoke spends exactly the selected seal to the pinned script as change.
It needs no booking state or payment lookup, so payment disappearance can
trigger immediate revocation. Kernel closure starts at mempool visibility,
not after a confirmation. Signer automation and broadcast are M4 work.

All templates reserve 200 sat/vB using the shared maximum legacy signed-size
bound, including possible uncompressed funding public keys. Reserve at least
1000 sat of change; total plan bound is 4096 signed vbytes. Reject duplicate
inputs, unexpected roles, wrong destination, insufficient funds, unsupported
scripts, unconfirmed/foreign pool claims and any issue input that spends its
referenced seal. Actual prevouts and fee policy must be rechecked by the signer.

Before returning an issue plan, lock the persistent issuer state, check both
the `(network,genesis,seal outpoint)` and booking-id journals, write/fsync the
booking reservation, then write/fsync the seal reservation. Atomic rename and
directory fsync complete each record before success. At most one certificate
uses a seal, ever; at most one emitted plan uses a booking, even with another
seal. A crash between writes can burn a booking without a usable plan. A crash
after writes but before output also burns both. No rollback or automatic
retry is permitted; reconcile with an operator and a new booking.

Private root mode 0700, owner-only single-link regular record/lock files mode
0600, no followed symlinks, and an exclusive nonblocking lock are required.
This protects against other UIDs, not hostile processes with the service UID.
State deletion/copying or selecting a fresh state directory bypasses history
and is outside the trusted operator contract; never do it for a retry.
