# M4a interfaces v1 (accepted)

## Renter request

NIP-01 signed event, dedicated lab kind **8183**, empty `content`. Exactly
five tags for non-payment requests, six for pay, each exactly two strings:

```
["action", "pay"]
["amount", "10000"]
["target", "<regtest legacy P2PKH address>"]
["slot", "<booking id: 64 lowercase hex>"]
["nonce", "<32 random bytes: 64 lowercase hex>"]
["contract", "<64 lowercase hex contract SHA-256>"]
```

Order is immaterial to semantic validation; the actual tag order is signed.
No duplicate, extra, missing, null or nested tag values. Amount is a positive
canonical decimal integer in Namecoin atoms, pay only. No signs, leading zeroes,
fractions or exponents. Closed action vocabulary: deliver, pay, publish,
repository.push, secret.release. secret.release always refuses even if scoped.
All strings are bounded printable ASCII. created_at must lie in the certificate's
half-open slot interval and not in the future at effect time. A matching nonce
is terminal across differently signed events and service restarts.

Targets: pay = regtest P2PKH address; deliver = `sha256:<64 lowercase hex>`;
publish = bounded record identifier; repository.push = HTTPS repository URL
(no credentials/fragments). The last two write local records only. There is
no execution of URL contents or network push. No target or prose parser creates
authority beyond the event fields and the verified certificate scope/budget.

Executor socket: `POST /execute`, JSON `{ "event": <signed event>,
"file_base64": "..." }`; file_base64 is empty except for deliver. Decoded
bytes must hash to the signed deliver target before reservation. Result contains
status/reason, event/slot/nonce identifiers and effect receipt, never keys or
file/message contents. Trusted configuration provides certificate, policy,
clock and own-node route; caller cannot override any of them.

Budget accounting includes pay amount plus fixed fee (conservative total debit).
Each reservation consumes that debit and its selected inputs permanently even
if broadcast/receipt completion is uncertain. A duplicate returns
already-executed with reserved/complete phase, never invokes the effect again.
Non-payment actions reserve a nonce but consume zero payment budget.

## Track B station-driver interface

Separate admin socket, Unix mode 0600, inaccessible to the rented station:
- `POST /mint`: `{ "slot": "<booking id>" }` -> one random token (returned once).
  Existing active or revoked slot refuses; no silent rotation or resurrection.
- `POST /revoke`: `{ "slot": "<booking id>" }` -> durable revoked state,
  idempotent for an already revoked slot; unknown slot refuses.
- `POST /list`: `{}` -> slot, token SHA-256, active/revoked; never raw tokens/keys.

Claim socket, intentionally no grant check:
- `POST /claim`: `{ "slot": "<booking id>", "token": "<64 lowercase hex>" }`
  -> configured per-slot throwaway regtest prize B key material on exact active
  token+slot match. Unknown/revoked/cross-slot token refuses. Repeated valid claims
  return the same key; this is a bearer-secret exposure measurement, not an
  exactly-once payout service. Actual wallet sweep is outside this module.

All admin/claim calls append time, operation, slot, token hash and outcome to a
private fsynced audit; malformed input uses empty slot/hash where unavailable.
Audit failure refuses release. Logs, receipts, list and handoffs never contain
raw tokens or private key material. Mint/revoke operations and audit are stored
atomically in one state snapshot. HTTP/socket responses set no-store.

M1 integration pin: 63087f31b62da50a6566250ef96af969e313e51b. This interface
adds no production spend authority, public deployment or target-scope semantics
beyond the explicitly local regtest experiment.
