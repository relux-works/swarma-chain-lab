# DK5b typed station-payload launch profile v1

This is a pure policy/schema/argv contract for Infra's slotd implementation and
Grants' future payload integration. The existing DA1 CLI does **not** implement
`-slot-profile`; do not execute these vectors against it or install them as a
working unit. [FORMAT.md](FORMAT.md) defines the dynamic anchor/manifest and
runtime custody requirements. Caller wire v1r4 remains unchanged.

## Root profile fields, in canonical order

A standalone profile is exactly this ordered object plus one LF. All fields are
mandatory. In a manifest the identical object is nested under `profile` without
its own LF. No generic options array, environment map, command string, shell
wrapper, user override or caller-controlled executable is part of the schema.

| Field | Constraint |
| --- | --- |
| `v` | uint64, supported 1 |
| `kind` | exact `station-payload` |
| `executable` | clean absolute non-root POSIX path, at most4096 bytes; characters only ASCII letters/digits and `/._-`; outside the managed envelope and anchor namespaces |
| `executable_sha256` | 64 lowercase hex, root policy's executable digest |
| `static_release_sha256` | 64 lowercase hex, independently approved DK5 release pin |
| `gateway` | canonical literal IP:port, port1..65535; IPv6 bracketed/compressed; no hostname, zone, IPv4-mapped IPv6, unspecified or multicast address |
| `gateway_cert_sha256` | 64 lowercase hex, gateway leaf DER pin |
| `dialect` | exactly `messages` or `responses`; no legacy omission |
| `model` | 1..128 ASCII characters from letters/digits plus `._:/@+-`; exact operator model ID |
| `max_tokens` | positive uint64, rendered as unsigned decimal; no inferred budget |

The complete profile is at most4096 bytes including LF, even if an individual
path is within its own bound. `EncodeProfile`/`DecodeProfile` validate exact
canonical bytes and semantic constraints. When embedded in Infra root policy,
its parser must remain closed and preserve these constraints; never discard
unknown fields before checking them or normalize untrusted input into acceptance.
Infra owns the surrounding versioned slotd policy schema.

Executable path validation here is lexical only. Root must prove executable
custody, exact hash and location outside the actual writable home/journal before
exec. Endpoint syntax is not reachability or an egress grant. The signed model
configuration must independently permit the exact dialect/model/token budget;
this codec does not invent a model or impose a substitute quota.

## Exact argument vector

`Argv(validatedManifest)` returns exactly these **21 separate strings**, in this
order, or nil plus a fixed refusal. These are OS argv elements, not shell text:

```text
0   profile.executable
1   -slot-profile
2   dk5b-v1
3   -bootstrap
4   /var/lib/swarma-slotd-demo-payload/U/inputs/bootstrap
5   -ca
6   /var/lib/swarma-slotd-demo-payload/U/inputs/ca.pem
7   -model-config
8   /var/lib/swarma-slotd-demo-payload/U/inputs/model.json
9   -journal-dir
10  /var/lib/swarma-slotd-demo-payload/U/journal
11  -gateway
12  profile.gateway
13  -gateway-pin
14  profile.gateway_cert_sha256
15  -dialect
16  profile.dialect
17  -model
18  profile.model
19  -max-tokens
20  decimal(profile.max_tokens)
```

U is derived from the approved root policy allocation and must match actual
service UID/GID. Static release/set pins and generation are in the trusted
anchor/manifest, not inferred from arguments. There is no `-slot-anchor`
override: payload selects the fixed per-EUID `20-slot.conf` and checks argv
against its admitted manifest. There is no default journal/config/model/dialect,
no `--` suffix for arbitrary caller options, no environment substitution, no
shell, and no string interpolation by systemd. Retain `--expand-environment=no`.

The installed payload lane must require exactly this profile and argument
vector, rejecting duplicate/reordered/unknown flags and conflicting values
before credential use or state mutation. This is stricter than the old generic
flag parser; step2b must implement it. The root prestart/unit readback must also
match the intended argv, executable digest and current creation receipt.
`ValidateArgv(manifest, observedArgv)` compares all 21 elements exactly and
returns ErrBinding on missing, changed, reordered, duplicated or extra arguments.
`CheckProfile(manifest, currentTrustedProfile)` refuses policy drift separately
from receipt binding. These pure functions neither read actual process argv
nor start a process; callers must supply the actual observations. Missing custody cannot be repaired by building this vector.

The service runs as exclusive slot UID/GID, no supplementary groups. Keep
`ProtectSystem=strict`; P/inputs, P/static and both anchors are read-only. Only
P/journal is writable within P. An existing slot-owned work home may remain a
separate bind; it carries no authoritative bootstrap/journal. Infra must verify
the actual mount view and existing cgroup/BPF/NFT enforcement before payload exec.
No process-control or unit implementation is included in this step.

## Public golden vectors and paired controls

| File | Bytes | Complete-file SHA256 |
| --- | ---: | --- |
| [testdata/profile-v1.json](testdata/profile-v1.json) | 441 | `ad3ab71c7fbbc02f0c94bb4462e3d65e13ba03d3dd33c2bb21fde8c3a2a448bd` |
| [testdata/argv-v1.json](testdata/argv-v1.json) | 527 | `11d5932acb358280a85f299c0deba9e3bdda67f34e0e749f3a43282e6552d78c` |

The argv fixture serializes the 21 strings as a compact JSON array plus LF for
interoperability inspection. It is not another runtime input format. The vectors
use an inert executable/endpoint/model and placeholder hashes. Do not launch them.

Tests pair missing/default/unknown values, unsafe or ambiguous executable/model
strings, malformed IP/port, unsupported versions and foreign paths with valid
IPv4/IPv6, messages/Responses and explicit-budget neighbors. Manifest and anchor
controls cover exact byte hashes, actual identity and persisted receipt binding.
They do not claim OS custody or real unit enforcement.

## Tools

Use Go1.26.8 after creating the repository-required isolated absolute HOME, cwd,
caches and temp directories under owned scratch. From `experiments/single-use`:

```sh
gofmt -l payloadlaunch/*.go
go test -race -count=1 -v ./payloadlaunch
go vet ./payloadlaunch
go test -run '^$' -fuzz '^FuzzGoldenAnchor$' -fuzztime=10s -parallel=2 ./payloadlaunch
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /absolute/task-scratch/payloadlaunch-linux.test ./payloadlaunch
```

Logs, coverage and cross-built binaries belong under `.temp/`. Cross-compilation
is not a Linux execution test. Qualification of actual path metadata, readonly
mounts, unit flags, journal lifecycle, crash boundaries and cross-slot denial is
pending Infra/step2b work at accepted composed heads.
