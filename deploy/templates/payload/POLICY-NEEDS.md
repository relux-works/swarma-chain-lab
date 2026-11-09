# Scripted payload requirements for the Infra root policy

This is a requirements table, **not** an installable slotd policy fragment.
Infra owns the unlanded `cmd/swarma-slotd-demo` root-policy schema, its bootstrap
path convention and per-slot identity. No schema or placeholder expansion is
invented here. No separate payload systemd unit is supplied. This executable is
the scripted PL1 consumer, not an approved general agent runtime.

| Policy input | Required value and owner |
| --- | --- |
| Executable | Absolute `/opt/swarma/payload/@VERSION@/bin/station-payload`, root-owned, non-writable by the slot user; Infra replaces the reviewed release version. No PATH lookup or shell wrapper. |
| SHA256 | Exact `payload` artifact SHA256 in the signed release manifest; it must also equal the manager and gateway payload pins. |
| Payload label | `scripted-station-v1`, identical to manager and gateway configuration. |
| Identity | Infra's per-slot OS user; never root, issuer, gateway, model or manager user. |
| Fixed argv | `-bootstrap BOOTSTRAP_PATH -ca CA_PATH -gateway PAYLOAD_GATEWAY_ORIGIN -gateway-pin PAYLOAD_GATEWAY_LEAF_SHA256 -model APPROVED_MODEL_ID -max-tokens APPROVED_POSITIVE_INTEGER -dialect APPROVED_DIALECT -model-config PUBLIC_MODEL_CONFIG_PATH`. Each token is a separate argv entry; these capitalized names are documentation variables, not runtime expansion syntax. |
| Bootstrap path | Infra chooses an absolute, symlink-free per-slot file path in an owner0700 parent. File is slot-owned0600, single-link, bounded to the native loader. It contains only the gateway-generated canonical bootstrap, never an upstream API key. |
| CA path | Infra chooses an absolute, symlink-free per-slot CA bundle path; slot-owned0600 and single-link in an owner0700 parent. Contains approved gateway and model trust roots. |
| Gateway | Exact operator-approved HTTPS payload listener origin, separate from the manager poll endpoint; normal trust plus exact leaf pin. |
| Model arguments | Exact model ID in the model proxy's approved table and explicit max-tokens within the registered cap; no implied defaults or guessed prices. |
| Dialect and public model config | Explicit `messages` or `responses`, matching the selected model's profile. Operator provisions a canonical0600 public model config copy; referenced credential paths are never opened by the payload. Startup compares model/profile and bootstrap origin/pin before network. The copy and actual proxy config must be kept identical by provisioning. |
| Filesystem/network/resource policy | Infra's existing root policy pins allowed paths, egress, cgroups, expiry and wipe; these are not controllable through bootstrap or a station wire request. |
| Lifecycle | Manager invokes only create/start/status/stop/destroy through the reviewed r4 wire. No argv/path/policy fields travel in those requests. |

Bootstrap fields read by the executable:

| Version | Fields |
| --- | --- |
| 1 | `v`, `booking_id`, `station_name`, `channel_secret`; scripted echo/control behavior without model HTTP. |
| 2 | All v1 fields plus `model_bearer`, `model_endpoint`, `model_cert_sha256`; exact per-slot model route with ordinary TLS trust and leaf pin. |

Unknown fields/versions refuse. Bootstrap does not select a binary, OS user,
argv, environment, host policy or arbitrary shell command. Both channel secret
and bearer remain private. The standalone `payload/deploy.json` validates only
the release identity; `validate -public payload/pairing.json -public model/service.json`
additionally requires the pinned dialect/model/limit/endpoint/pin pairing. Omitted
dialect is test-only and never deployable. The pairing record must describe the
exact pinned argv above; it cannot approve the absent Infra policy or its execution.
Before host acceptance, Infra must turn this table into its reviewed real schema,
prove matching bootstrap placement/argv and demonstrate per-slot lifecycle and
cleanup. A binary double-build is not that evidence.
