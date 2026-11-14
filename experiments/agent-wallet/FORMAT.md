# Wallet public input formats

This file specifies the retained W1 legacy event/CLI format. The default
`agent-wallet` command uses the separate [LIP-0006 service profile](SERVICE.md).
A W1 signed event and an unsigned W2 request are not interchangeable single-use
commitments.

All signed public objects use exact compact JSON emitted by Go `json.Marshal`,
including field order below, with no trailing newline. Duplicate/unknown fields,
null arrays, aliases and noncanonical encodings refuse. Numbers are integers.
Hex is lowercase. Public files are bounded and read through W3's file loader.
This is the W1 experimental wallet-terms profile, not the booking UI's complete
rental contract. The issuing operator must bind these exact terms bytes into
the K1 grant and its corresponding consent/issuance proof; a booking contract
hash cannot be substituted for them.

## Rental terms

Field order: `version`, `recipients`, `spend_cap_sat`, `name_cap_sat`, `name_count`.
Version is 1; recipients are a sorted, unique list of at most 32 legacy regtest
P2PKH addresses. Both nonnegative caps sum to no more than the signed grant's
budget; name count is 0..3. Zero means no corresponding authority, not a default.
The file is stored as `SHA256(terms).json` in the public object directory and
must match `contract_sha256` in the signed K1 grant. No W3 seal list is embedded
in rental terms; standalone authority is a distinct format.

## Grantee-signed request

An ordinary Nostr-shaped event has ordered fields `id`, `pubkey`, `created_at`,
`kind`, `tags`, `content`, `sig`. Kind is 8184, tags is exactly `[]`, content is
canonical request JSON, pubkey is the grantee's 32-byte BIP-340 key, and sig is
64-byte BIP-340. The ID is SHA256 of compact JSON
`[0,pubkey,created_at,kind,tags,content]`. The event must be created within the
grant window and not in the future at admission. The tool does not sign it.

Content field order:

| Field | Requirement |
| --- | --- |
| `version` | 1 |
| `grant_id` | 32-byte hex stable K1 ID or standalone envelope hash |
| `action` | `pay` or `names.register`; explicitly granted |
| `nonce` | 32-byte hex, unique per grant |
| `address` | Exact approved regtest legacy P2PKH recipient |
| `amount_sat` | Positive pay amount; exactly zero for names |
| `fee_limit_sat` | 1..1,000,000 atoms; per transaction stage |
| `name` | Empty for pay; ASCII `d/` or `id/`, 3..255 bytes, no space/backslash for names |
| `value` | Empty for pay; printable ASCII at most 520 bytes for names |

Names are a deliberately narrow ASCII demo profile. Both `name` and `value`
fields remain present for pay. Unknown fields, including a request-supplied
`use_seal`, refuse. W3 commits SHA256 of the **complete canonical event bytes**,
not just content or the event ID. Re-encoding, appending a newline or changing
any signed field changes the commitment.

## Standalone single-use grant

Envelope order: `oneoff_grant`, `signature`. Signature is BIP-340 under the
landlord's key over SHA256(`swarma-wallet-oneoff-v1` || canonical inner grant).
There is no separator after the fixed ASCII domain tag. The external ID hashes
the complete canonical envelope and can change when identical content is re-signed.

Private one-off generation state uses version 2 and the domain-separated
`OneoffDigest(inner grant)` as its key, excluding the outer signature. Equivalent
valid signatures therefore share sticky key-generation closure, while their
external envelope IDs and exact request commitments stay unchanged. Legacy
`oneoff-<envelope-id>.json` generation state refuses with
`ONEOFF_STATE_MIGRATION_REQUIRED` before any new generation record is written:
the old record alone cannot recover the content identity for every signature
variant. Preserve retained history for an explicitly reviewed migration; do not
delete it to retry a grant.

Inner field order:

`version`, `network`, `genesis`, `agent_name`, `landlord_name`, `issuer_key`,
`grantee_key`, `recipient`, `amount_sat`, `fee_limit_sat`, `not_before`,
`not_after`, `seal`.

Version is 1; network/genesis are pinned to regtest. Agent/landlord names must
match operator policy. Distinct valid issuer/grantee BIP-340 keys are 32-byte
hex. The issuer must equal K1's current landlord-name key. Amount is positive,
fee maximum is 1..1,000,000 atoms, and their sum cannot exceed 21 million NMC.
Window is half-open `[not_before, not_after)`. Seal is ordered `txid`, `vout`.
The W3 P2SH 1-of-2 redeem script uses the two **even compressed keys** obtained
by prefixing each x-only key with `02`; the external fixture/operator must sign
with the corresponding normalized private scalar.

The request must be `pay`, with exactly the signed amount and recipient and no
higher fee limit. No additional terms file is accepted. A grantee seal spend
must contain exactly one minimal zero-value OP_RETURN with the full request
SHA256 and one valid SIGHASH_ALL seal signature. The funding and use transactions
must be actively confirmed, with use at a later block height. A caller-provided
use txid is a locator, not proof. An issuer-attributed spend revokes.

## Scope and lifetime limits

The standalone grant has its own domain tag; requests use Nostr kind 8184.
Neither signature may be repurposed as authority for other protocols. K1's
landlord resolver and observed-rotation limits apply. Wallet records are local,
bounded, at-most-once reservations, not distributed consensus or rollback-proof
storage. No public fixture contains a usable live signing key.
