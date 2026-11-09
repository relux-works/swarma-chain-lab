# Demo station lifecycle

This adapter performs the station-lifecycle role of the platform user manager
and curator-run for a bounded demo. It is replaced when those platform components
ship their station lifecycle. It is not a new platform entity, an agent runtime,
a model proxy, or a shell executor.

The independent Go module exposes Start, Stop and Status over a slot containing
its numeric helper ID, grant ID, half-open window, pinned payload label/hash and
opaque private bootstrap. No gateway, relay or a2a types enter that contract.
`gatewaybind/` is a separate module adapting the rental gateway journal/driver.
`slotd/` is the client of the separately installed `swarma-slotd-demo` helper.
Existing LinuxUser command plans are not executed or modified.

## Authority and protocol

The broker allocates canonical decimal numbers in an operator-configured
inclusive range within 0..9999. It admits at most 16 live allocations and retains
at most 64 records within a 64 KiB journal; the byte limit can bind first. Numbers
are never recycled within that retained journal. Do not delete state or rotate
ranges to evade terminal records. Independent installations require disjoint
ranges and matching operator-approved helper policy.

The manager persists starting intent before helper effects. Same-binding retries
are idempotent; conflicts and terminal starts refuse. Unknown ID-only Stop refuses;
an authenticated fully bound Stop first asks the helper to establish cleanup.
Before sending Create the manager fsyncs its exact host boot_id and
CLOCK_BOOTTIME nanoseconds. An absent status proves cleanup only if no Start was
attempted, or its probe began after that same boot's issued time + 6 s, or a
verified boot change makes the old request impossible. Early probes can still
clean a stored matching resource, but their absence cannot become proof merely
because the deadline passed while the probe was in flight. Busy always stays
pending. A restart resumes the saved fence, never generates a fresh timestamp
for the old request. Legacy r2 attempts with no recorded fence remain pending
unless the helper confirms this binding destroyed.
Failed or interrupted cleanup stays pending and retries. Closed fixed
errors do not echo helper input, keys or request bodies. Bootstrap bytes remain
private in 0600 records under existing owner-controlled 0700 directories protected
by exclusive locks; terminal records retain binding hashes and erase credentials.

The exact helper wire is v1 revision 4, document SHA256
`8c09cc17b8e0bdd9f7482f4ea2e1b553213fb94c20002bfb9d3f15ed61a7fe15`.
It is one canonical JSON line, at most 8192 bytes, per Unix connection. Requests
are only create/start/stop/status/destroy. Create adds boot_id, issued_boottime_ns, deadline and at most 4096
opaque decoded bootstrap bytes; it carries no path, user, argv, environment,
resource property, egress policy or arbitrary command. Root-owned helper policy
is the sole source of host authority. Stored-state responses bind deadline,
payload SHA256 and bootstrap SHA256. The adapter checks them before Start or
owned cleanup. A partial create with a rejected payload can be cleaned only when
its deadline and bootstrap still prove ownership. A helper `failed` state stays
pending for operator reconciliation; this adapter never automatically destroys it.

The Linux host reads `/proc/sys/kernel/random/boot_id` and CLOCK_BOOTTIME; there
is no wall-clock or per-process monotonic fallback. R4 validates freshness after
a nonblocking per-slot lock: more than 5 s old, more than 1 s ahead, or another
boot refuses stale_request. Busy means a same-slot request is executing. A fresh
request delayed by fsync or scheduling can safely refuse rather than regenerate
its timestamp after persistence. The helper must implement this exact contract.

The Linux client checks root ownership, socket 0660, parent directory 0750 and the
connected root SO_PEERCRED. The helper independently admits only its configured
caller. The adapter installs no service, socket, privileged rule or host policy.
The operator supplies the helper socket and numeric range; bootstrap is data for
the fixed helper payload, never an executable or policy override.

## Transport and expiry

The manager initiates HTTPS POST `/v1/station-manager/poll` to a literal IP.
Both ends validate certificate chains and pin the exact peer leaf DER SHA256.
The gateway handler independently requires verified manager TLS chains and its
pin, even behind a wrongly configured listener. No plaintext, redirect or proxy
fallback exists. Poll bodies are canonical, closed-schema JSON, at most 64 KiB;
responses contain at most 16 commands. Stop dominates late running reports.

The manager's own clock worker runs independently of polling, every 100 ms by
default. It reconciles helper state, cleans expired/interrupted slots and refuses
new starts after clock rollback or storage failure. Individual helper operations
have a 2 s deadline (configurable up to 5 s); cleanup can be delayed by bounded
in-flight helper calls and iteration over retained pending records. This is not
a hard real-time expiry guarantee. The helper also enforces its own deadline.
Disconnection does not suspend either local expiry mechanism. Root helper failure
cannot be represented as confirmed cleanup. Signal shutdown leaves durable state
for restart and the helper's expiry protection; it does not pretend to wipe slots.

New allocation/start requires more than 60 s remaining and at most a one-hour
window in this demo profile. Start waits are bounded to 2 s by default (at most
5 s). A timeout means not ready, never success. A saved running result cannot
satisfy a new wait after broker restart without another authenticated manager
report. Cleanup confirmation may reuse a terminal result, since numbers cannot
be revived. Gateway serve must keep these waits off its relay ACK pump.

## Gateway and payload binding

`gatewaybind.New(Config)` accepts StateDir, Journal, PayloadID, PayloadSHA256,
SlotMin/SlotMax, ManagerCertSHA256, Now and optional StartTimeout. It implements
station.Driver and station.Recoverer, and exposes Handler and Close. Use separate
state directories for gateway broker and station manager. A gateway slot ID is
its booking ID, not the helper number or grant ID. PresentationID checks framing
only; actual fresh kernel admission remains the gateway's responsibility.

The broker allocates one 32-byte channel credential and retains its exact encoded
bootstrap across retries/restart. Gatewaybind's private canonical payload document
has exactly `v`, `booking_id`, `station_name`, `channel_secret` in that order.
Version is 1; channel_secret is padded base64 of the 32 bytes. Use
`gatewaybind.DecodeBootstrap` before the payload attempts a handshake: unknown
versions, fields, duplicates, noncanonical encoding and invalid identity refuse.
The manager treats this document as opaque bytes. No manager certificate, model
API key or gateway agent key enters it.

The payload's gateway address, CA trust and server-leaf pin are separate
operator-pinned inputs. `lifecycle.DialPayload` uses server-authenticated TLS,
then the payload performs the existing stationlink HMAC challenge-response with
the decoded booking ID, station name and channel secret. No payload client
certificate is required. A real pinned rented-agent payload remains an external
input; this module does not promote the scripted test agent to one.

After gateway restart, End and Destroy resolve opaque handles through Recoverer.
No fabricated home path or copied helper policy is stored. Unknown mapping and
unconfirmed cleanup refuse; ErrCleanupPending leaves the closer operation started
for same-ID retry. End revokes gateway channel access immediately; Destroy marks
the journal destroyed only after manager-confirmed cleanup. Local driver fallback
continues to use its existing durable home/user facts.

## Tools and commands

Use Go 1.26.8 with `GOWORK=off`. From this directory:

```sh
go mod verify
go list -mod=readonly -m all
go vet ./...
go test -race -count=1 ./...
go build -trimpath -o .temp/station-manager ./cmd/station-manager
go run .scripts/guards.go -out .temp/guards
(cd gatewaybind && go mod verify && go list -mod=readonly -m all && go vet ./... && go test -race -count=1 ./...)
```

The guard driver copies modules under `.temp/`, applies one bounded violation at a
time and requires the named assertion to fail. Skips, build errors, crashes and
unapplied plants are not detections. It retains command PIDs, logs, mutation hashes
and results under the requested evidence directory, then removes its own copies.

The CLI accepts `check-config --config ABSOLUTE_PRIVATE_JSON` or
`run --config ABSOLUTE_PRIVATE_JSON`. Check-config validates local inputs without
contacting the helper, creating runtime state or connecting to the gateway.
Run uses Linux SO_PEERCRED; other platforms refuse the real socket client.
Configuration must be canonical compact JSON (optional surrounding whitespace),
with fields in this exact order:

```json
{"state_dir":"/var/lib/station-demo/manager","slotd_socket":"/run/swarma-slotd-demo/sock","slot_min":1,"slot_max":64,"payload_id":"rented-agent-v1","payload_sha256":"<64 lowercase hex>","gateway_endpoint":"https://<literal-ip>:9443/v1/station-manager/poll","gateway_cert_sha256":"<64 lowercase hex>","client_cert":"/etc/station-demo/client.pem","client_key":"/etc/station-demo/client.key","server_ca":"/etc/station-demo/gateway-ca.pem"}
```

Replace placeholders with operator inputs. All config/certificate/key/CA files
must be owner-controlled private regular files, at most 64 KiB, with no symlink
components. The state directory must already exist with mode 0700. Keep credentials
out of command arguments and logs. Process/service deployment is an operator task;
this repository supplies no installation or sudo command.

## Evidence limits

Tests exercise fake host/helper state, the actual r4 stream codec, actual loopback
TLS, durable recovery and the gateway adapter with a stub kernel. Linux cross-build
checks compile compatibility only. They do not prove Linux user/systemd/nftables
isolation, actual helper interoperability, real payload/model access or a deployed
station. Required external checks are in [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).


### Optional model-proxy registration

`gatewaybind.Config.ModelRegistrar` and `ModelCaps` opt into the independent
[model proxy](../model-proxy/README.md). Prepare freezes an inactive credential
in canonical flat bootstrap v2; Activate runs before manager Start; End/Destroy
attempt Revoke and host Stop independently and keep the closer pending if either
is uncertain. A missing registrar preserves v1. The core manager/helper stays
opaque to model credentials. Enabling v2 requires a compatible payload consumer;
existing broker profiles are not migrated implicitly. Consumer module roots
must add their own local model-proxy replacement because Go replacements are
not transitive.
