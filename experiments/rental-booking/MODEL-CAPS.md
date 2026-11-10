# Signed rental model limits (CC1)

A model-enabled rental uses Template version2 and ContractV2. The template and
contract carry `model_caps` after the pre-existing fields, in this order:

```json
{"input_tokens":4000000,"output_tokens":300000,"requests":200,"max_tokens":8192,"cost_nano_usd":3000000000,"default_max_output_tokens":8192}
```

These are the M5 example limits, not runtime defaults. Each integer must be
positive and at most9007199254740991 so the NIP-07 browser can display and hash
it exactly. `default_max_output_tokens <= max_tokens <= output_tokens`.
`cost_nano_usd` is the total slot cost ceiling, not a per-request price.

ConfigV2.model_caps must exactly equal Template.model_caps before booking opens
state or observes a node. Both larger and smaller differences refuse. The exact
profile bytes and typed template hash remain pinned. Book copies the validated
caps into ContractV2; renter consent and provider signatures cover those bytes.
The independent rental issuer decoder authenticates and validates the extension.
Caller-owned config, returned catalogue and booking pointers cannot alter the
service's retained terms. The page discloses the same six integers alongside
canonical contract JSON; gateway exchange terms expose the same text.

The gateway checks expected caps against the pinned catalogue and each returned
contract. The exchange hands an owned copy of the validated booking contract to
registration, which checks its hash and persists `contract_b64` in the slot
journal. Before allocation/Prepare and again before Activate, gatewaybind checks
canonical contract bytes, contract hash, booking/grantee/station/window and the
presentation's bound fields. It derives proxy.Binding.Caps from that contract
and requires exact config equality. The existing kernel remains responsible for
grant signatures and current-chain admission; this adapter does not create a
second grant authority.

Revocation derives the original binding from retained contract/presentation
bytes without consulting mutable configured caps. Thus a changed valid config
refuses a new start but can still revoke the original credential after restart.
No new bootstrap credential or upstream API key is part of the public contract.

## Default output limit is disclosed, not injected

CC1 carries `default_max_output_tokens` into the signed contract and persisted
proxy binding. The current Responses profile still requires an explicit client
`max_output_tokens` and checks it against the signed max. Missing limits refuse
REQUEST; oversized limits refuse CAP, without forwarding or charging. Future
CH1-B may consume the signed default; CC1 implements no defaulting or client
compatibility workaround.

## Compatibility and upgrade boundary

Existing Templatev1 and non-model ContractV1/ContractV2 omit model_caps and retain
their canonical bytes. Templatev1 cannot carry model caps; legacy ServiceV1
cannot create a model-enabled rental. Proxy bindings from older releases retain
the omitted zero default, but a new model-enabled gateway requires all six
positive fields. Old non-model journal replay retains its original bytes.

Old model rentals with configuration-only limits have no renter-signed caps and
cannot be upgraded by inventing contract bytes or copying today's config into an
old contract. The model broker profile changes to gateway-model-contract-v3;
existing legacy model broker state is not silently relabelled. Stop new offers,
finish/revoke legacy model rentals with their original compatible release, and
retain the original state and evidence before provisioning an approved new model
profile. Booking's existing template/config fingerprint rules still apply.
Never reset a booking state directory or reuse a receiving branch with a reset
index to change templates. An operator must plan state/branch/index continuity;
this source change supplies no live-state migration or host activation.

## Public deployment preflight

Validate every native descriptor/config first. Then, from deploy/:

```sh
go run ./cmd/deploy-kit check-model-terms \
  -booking /absolute/public/booking.json \
  -profile /absolute/public/profile.bin \
  -gateway /absolute/public/gateway.json \
  -model /absolute/public/model.json \
  -payload /absolute/public/pairing.json
```

Success is exactly MODEL_TERMS_MATCH. The checker binds template/profile hashes,
all six caps in booking/template/gateway, the payload limit, selected model's
context/prices/dialect and matching pinned endpoint. These are public inputs;
it does not follow credential paths or contact hosts/providers. This cross-check
supplements full native startup checks and does not qualify custody, transport,
model entitlement or Linux lifecycle behavior. Re-run it whenever any input
changes. M5 model templates use the same signed example limits in both configs.

## Verification tools

From repository root, with the project's Go toolchain and dependency cache:

```sh
go run .scripts/cc1-guards.go -out /absolute/new-cc1-evidence
go -C experiments/m5-host-smoke test -race -count=1 ./...
```

The control runner uses Go overlays in the new evidence directory, runs a valid
baseline for each plant, and requires the named test assertion at the expected
failure. It records source/mutant hashes, command PIDs, exit codes and logs. No
production source or state is mutated. Existing module tests cover positive and
negative bindings, contract/page equality, legacy vectors and restart/revoke.
The host-smoke module is part of CC1 validation: its public config supplies
independent expected caps, all six signed limits must match in both directions,
and missing/invalid expectations refuse before operator or network effects.
The overlay controls also disable those checks and require their exact refusal
tests to detect the violation. Reflection plants must change canonical bytes.
The full M5 rehearsal uses signed model caps in Messages/Responses expiry/revoke
legs; its documented Darwin helper and registrar seams remain unchanged.
