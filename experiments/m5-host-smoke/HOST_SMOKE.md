# Additive M5C HOST_SMOKE runner delta

This document replaces only M5C HOST_SMOKE section3's missing-driver paragraph.
All original stop conditions and prerequisite gates remain. Do not change the
sealed M5C pack. Both real Linux scenarios remain unexecuted by this producer.
The runner neither installs a daemon nor supplies an Infra privilege exporter.
**Missing approved observation/action tooling is a blocker, not a positive
receipt.** Infra must prepare it before the timed scenario begins.

## Public inputs

Config JSON fields are defined by `Config` in config.go. Supply all fields:
scenario (`expiry` or `revoke`), relay and booking origins, agent_pubkey,
issuer_pubkey, agent_name, landlord_name, template_sha256, profile_sha256,
profile_id, profile_version, payload_sha256, evidence_sha256, environment_sha256, allowed,
forbidden, budget_sat, not_before and not_after. Hashes are lowercase hex.
Copy exact approved template scope/budget/pins; do not invent defaults.
not_before must be in the future with time for the operator preflight and
paced consent exchange; not_after must be exactly3600 seconds later. Each
scenario uses separately approved state/custody/config namespaces. Hash its
public namespace-selection record into environment_sha256, never a secret file.

Inventory JSON (`Inventory` in files.go) supplies:

- source and tree: exact40-hex release Git objects;
- binaries and configs: maps with exactly booking, gateway, store, relay, model,
  wallet, signer, manager, payload, each a64-hex public artifact/config hash;
- helper: exact64-hex independently qualified helper binary hash;
- hosts: exactly exec1, demo1, stations1, each with kernel and systemd version
  strings (bounded version tokens, no hostnames or arbitrary command output);
- storage_policy_sha256: hash of the reviewed sanitized cleanup policy and its
  explicit physical-erasure limitations.

Hash the exact inventory file bytes into config.evidence_sha256. Set
config.payload_sha256 to the same inventory.binaries.payload hash; inventory
intake and the running-stage receipt both enforce that equality. The client
copies that exact validated inventory into the sealed packet. Source, tree,
config and binary hashes do not by themselves prove signature validity or that
those artifacts are running: those checks are explicit Infra preflight claims.
The optional wallet is not activated; its public config still has to be valid.

## Small receipt protocol

The client writes `NN-STAGE.request.json` once. It contains version1, fresh run_id,
mode, scenario, monotone sequence, config_sha256, created_ms/deadline_ms, slot,
and the exact public contract/grant when available. `checks`, `numbers`, `hashes`
name the required observations. Each response has exactly five fields:

```json
{
  "request_sha256": "<SHA256 of exact request file bytes>",
  "observed_ms": 0,
  "checks": {},
  "numbers": {},
  "hashes": {}
}
```

Fill each requested check from the actual named observation. Every check must
be true, every number must match its expectation, and every hash must be a
64-hex evidence locator (or match the specific requested hash). Never generate
success by copying the request and setting all checks true. In numbers, request
sentinel -1 means a nonnegative observed count, -2 a positive UID/PID and -3 a
recorded boolean0/1; return the observation, never the sentinel. The caps
SeenRumorIDs count is bound into subsequent close/restart requests.

Use the client's clock domain for observed_ms (Unix milliseconds); Infra must
bind its host observation timestamps to that domain and qualify clock skew.
It cannot predate the request/previous receipt, be in the future, or exceed the
deadline. Receipt arrival also must occur before the deadline. A late file is
not accepted even if its self-reported observation time appears timely.

A shell can produce the framing without a new daemon. For Linux tooling:

```sh
umask 077
sha256sum -- "$REQUEST"       # use the hash, never change request bytes
# Obtain selected observations with the approved commands below.
date -u +%s%3N               # timestamp AFTER the corresponding observations
# Write the five-field JSON to a fresh mode0600 temporary file INSIDE PACKET
# (same filesystem), then atomically:
mv -- "$PREPARED_RECEIPT" "$PACKET/NN-STAGE.incoming.json"
```

Use the exact name/stage/sequence emitted by this run. The prepared receipt must
contain observations rather than this illustrative schema. No repeated or
renamed receipt can authorize a different stage. Unknown fields, duplicate JSON
keys, null, extra objects, oversized input, symlinks, hardlinks, broad modes,
wrong binding, missing/negative checks or wrong counters stop the run.
Accepted projections become `NN-STAGE.receipt.json`. Rejected incoming bytes
remain untrusted local inputs, excluded from SHA256SUMS and publication.

## Stage observations and operator actions

| Stage | Infra observation/action and required result |
| --- | --- |
| preflight | Original M5C sections1–2: verified release signature, actual hashes, valid public configs/check-coins, isolated regtest, selected block convergence, active units, qualified real helper, UID/permission/egress/mTLS/peer controls and neighboring positives. No overlay/fake helper. Own-node regtest genesis and agent/landlord ancestry routes. Fixture Responses policy exactly as below. Manifest hash equals approved inventory; selected_block is the common observed block hash. No existing scenario slot. |
| pregrant | No allocated gateway slot. Public foreign-consent negative preserved package/issuance and independent journal inspection confirms no hidden partial allocation. |
| unconfirmed_payment | After separate approved regtest funding authority, pay exactly contract.payment.address/amount_atoms. Before mining, payment remains unconfirmed, issuance/presentation are absent and no gateway slot exists. Preserve transaction evidence. Client independently checks public issuance absence. |
| issue | Mine/synchronize the approved depth1 payment; mirror the original immutable booking Item/index with exact hash equality. The single running native signer consumes it, uses enrolled fixture inventory, confirms its seal, then publishes the native presentation. Observe absence before seal confirmation and presence after. Record original_outbox item hash, payment_txid, selected_block and presentation byte hash. All own-node payment/seal/ancestry views agree. No fabricated Item/presentation; no concurrent `-once`. |
| running | After the client's first successful model reply: journal Starting→Started, real Linux admin Prepare/Activate, real r4 create/start, allocated slot UID/PID/cgroup, exact payload hash and matching canonical bootstrap hash/mode0600. No custody material in slot. Wrong private credential returns AUTH with no text, wrong pin fails transport; neither adds an upstream call. Neighboring valid first request succeeded. upstream_calls=1. Record actual payload_pid, slot_uid, payload_binary/bootstrap/cgroup hashes. Retain the old bearer only inside Infra's private probe boundary. |
| caps | Actual controlled upstream checked every Responses request shape;200 calls settled, requests200, input1400/output600, pending0. Client observed200 exact model replies plus two exact MODEL_CAP replies. Snapshot SeenRumorIDs count; keep private closure probe. No retry/call after cap. |
| revoke | Native version2 operator Item for exact contract/booking, reason operator, append-only atomic intake; the single running signer consumes it. Own-node exact seal gettxout changes from object to literal JSON null, synchronized views. Record real revoke_item/spend_txid/selected_block. observed_ms is the spend observation time; client starts the30s deadline there and sends the authenticated refusal probe. Empty CLI stdout is not JSON null. |
| close | By expiry not_after+25s, or revoke spend+30s: End, channel cleared, model revoked, no pending, counters unchanged, fresh old-bearer probe gives MODEL_AUTH with empty text or raw401 exact AUTH, wrong pin fails transport, SeenRumorIDs unchanged. Helper independently stopped/destroyed or safely reconciled exactly owned absence; recorded PID/cgroup gone, slot credential/network access revoked, approved storage policy completed with erasure limits recorded. gateway_destroyed records the journal flag independently (0 is not automatically failure). Expiry additionally requires reason not_after, actual UTC>=not_after and client application idle>90s. |
| restart | Separately approved restart without journal reset; durable requests/usage/pending/phase and SeenRumorIDs remain unchanged; fresh closed bearer remains refused with no text or upstream call. No uncertain reservation is discarded. |

`fixture_responses_policy` means the controlled HTTPS upstream requires exactly
/v1/responses, Bearer auth, no x-api-key, model gpt-6.1-terra,
max_output_tokens8192, stream/store/background=false, service_tier=default and
nonempty input. It returns completed `model fixture reply` with7/3/10 usage.
Approved synthetic context8192 and prices1/1 nanoUSD/token must support the
unchanged install caps; these are not provider prices. Check each request,
not only one sample. `responses_shape` attests that resulting observation.

The expiry close request is issued before the idle wait finishes so Infra's
prepared watcher can meet the deadline. Do not send extra application probes
during expiry idle. The authenticated native `slot ended` notice is permitted only at/after
not_after. After the revoke probe, exact native exchange Help or NotLive may
arrive through the non-grantee fallback; require its timestamp at/after the
probe. Record the observed fixed notice kind separately. These control replies
are not payload delivery. A restarted gateway may replay earlier inputs through
that same non-grantee fallback; exact Help/NotLive created at/after the restart
handoff are recorded separately. The client then observes a bounded two-second
interval without application messages. Other unsolicited payload replies fail;
this interval is an observation, not a promise about all future traffic. Normal WebSocket heartbeats
continue. A disconnect or replay
overflow is a failed liveness observation, not a reason to retry into success.
For revoke, capture spend time promptly; do not reset its deadline when the
receipt is copied or the operator returns to the terminal.

## Named Infra-only commands and missing tool boundaries

Read metadata only, on the relevant host, under its existing approval:

```sh
uname -r
systemctl --version
id swarma-gateway
id swarma-model
id swarma-stations
id swarma-issuer
systemctl show swarma-gateway.service -p ActiveState -p SubState -p MainPID -p ControlGroup
systemctl show swarma-model.service -p ActiveState -p SubState -p MainPID -p ControlGroup
systemctl show swarma-stations.service -p ActiveState -p SubState -p MainPID -p ControlGroup
systemctl show swarma-issuer.service -p ActiveState -p SubState -p MainPID -p ControlGroup
# Repeat relevant active-unit metadata for booking/store/relay and the reviewed helper unit.
stat -c '%a %U %G' /run/swarma-model /run/swarma-model/admin.sock
stat -c '%a %U %G' /run/swarma-slotd-demo /run/swarma-slotd-demo/sock
# For the exact helper-owned payload PID, identified by the reviewed helper:
ps -o pid=,uid=,stat= -p "$PAYLOAD_PID"
sha256sum -- "/proc/$PAYLOAD_PID/exe"
```

Expected: active/running units and qualified ownership; distinct gateway/model
UIDs; model/helper parent0750 and socket0660; exact payload executable hash and
allocated non-root slot UID. After closure the *recorded* PID/cgroup is absent,
not merely a different process or an empty arbitrary search. Do not use pattern
kills, inspect process environments, or export command lines/private config.
Inventory stores bounded version tokens; receipts store selected numeric fields
and hashes, not the raw command output.

Core read/funding/mining routes, original outbox transfer, operator intake,
private model probes, journal/registry projections, helper UID/cgroup/workspace
checks and restart require **Infra's existing approved tooling**. There is no
new privileged API or guessed root-helper executable here. Name each actual
reviewed tool and invocation in Infra's execution evidence before the run.
Expected projections are the table above. If a tool cannot produce them without
exposing secrets or resetting shared state, stop and report that missing tool.
Do not copy journal/registry/bootstrap even for convenience; project only
Started/Ended/reason/channel-cleared, counts and other named fields.

## Evidence and completion boundary

The client seals its inventory, requests, accepted receipts and final report.
Record source/tree/helper/binaries/public config hashes and retain the separately
reviewed release signature and storage-policy evidence at their pinned locations.
Keep private credentials and raw host logs in their existing custody. Stage
checks are operator assertions; hash locators alone do not authenticate them.
A reviewer must cross-check those assertions against Infra's sanitized underlying
evidence before calling the host smoke accepted.

Run checker plants locally (`go test -run TestEveryReceiptGateRejectsItsPlant`)
before acceptance; they include missing cleanup and extra upstream calls beside
valid controls. This needs no live-host damage. Any missing stage, probe, policy,
wrong count or failed signature is unverified/failure, never a skip-to-pass.
Both separate3600s expiry and full revoke scenarios are required. The producer's
Darwin PASS_SELF_TEST packet cannot substitute either. Main execution still
requires the owner's separate exact GO.
