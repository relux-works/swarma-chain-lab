# M5 external host smoke client

This client drives the native relay/booking/ConsentV2/issued-grant/model flow of
already-installed services. It generates a fresh renter key in memory; it never
reads custody keys, RPC configuration, the model registry or bootstrap. It runs
no host command, installation, payment, mining, signing, restart or cleanup.
Those operations remain with Infra through explicit operator handoffs.

A successful host result is **CLIENT_PASS_OPERATOR_ATTESTED**: direct client
observations passed and all required operator receipts were supplied. It is not
independent verification of those receipts, permission to spend, a Linux review
verdict, or authorization for main. The orchestrator must assess both separate
expiry and revoke packets and their underlying Infra evidence.

[HOST_SMOKE.md](HOST_SMOKE.md) supplies the additive M5C runbook delta. Keep the
original sealed install pack read-only. Its blockers, exact Linux release,
helper qualification, authorization and isolated regtest prerequisites still
apply. This runner cannot resolve those prerequisites by producing JSON.

## Tools and artifacts

Go 1.26.8, sibling modules and a populated module cache are required:

```sh
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
GOWORK=off go build -trimpath -o .temp/m5-host-smoke ./cmd/m5-host-smoke
```

On the approved client workstation, after Infra has prepared the installed
services, reviewed public config, sanitized inventory and receipt producers:

```sh
umask 077
.temp/m5-host-smoke -config /absolute/expiry-public.json \
  -inventory /absolute/expiry-inventory.json -out /absolute/new-expiry-packet
# Use separate approved state and a new public config/inventory for revoke.
.temp/m5-host-smoke -config /absolute/revoke-public.json \
  -inventory /absolute/revoke-inventory.json -out /absolute/new-revoke-packet
```

The CLI fixes PoW16, demo-60, 1000 USD cents, 3600 seconds, depth1, 200 requests,
25-second expiry and 30-second revoke closure limits. There is no acceleration,
credential-file, arbitrary command or insecure-TLS option. Pre-grant messages
are paced at ten seconds to respect the installed exchange rate limit. Relay
uses normal TLS trust and optional challenge authentication with the ephemeral
renter key; plain transport is restricted to literal loopback addresses for
approved forwarding. Booking redirects and credential-bearing URLs are refused.
The booking origin must expose the native read-only catalogue/booking routes.
A lost client process cannot resume its in-memory renter: preserve the failed
packet and existing slot state; do not reset or automatically rebook.

Output is a new mode0700 directory. Public config/inventory inputs and incoming
receipts must be regular, single-link, owner-only files owned by the caller.
Requests and accepted receipts are mode0600. SHA256SUMS covers selected public
evidence only; it is an integrity seal, not a release signature. Incoming files
are untrusted work items and are excluded from the seal; do not publish them.
No raw response, exception body, command output, registry or journal is copied.
Stop/timeout produces a FAIL report with a fixed reason and seals completed
observations. Failure to seal is separately fatal. No retries-to-green occur.

## Runner self-test

`RunSelfTest` is a library entry point used only by
`../m5-rehearsal/host_runner_test.go`. It uses the existing genuine isolated Core,
native CLIs and actual relay/booking/model flow, with the declared Darwin helper
and registrar seams. It is always **PASS_SELF_TEST**, with the short-window,
two-request fixture, one node/shared outbox and fixture-only signer cycles.
Linux peer credentials, UID/cgroup isolation, remote mirrors, installed running
signer and storage erasure are not exercised or accepted by this lane.

Follow the existing m5-rehearsal pinned Core/release prerequisites and choose
fresh short run roots. Execute each scenario separately from a signed clean head:

```sh
IT1_REGTEST=1 IT1_PRODUCT_HEAD=<exact-signed-clean-head> \
 IT1_CORE_DAEMON=<pinned-namecoind> IT1_CORE_CLI=<pinned-namecoin-cli> \
 IT2_RELEASE_DIR=<matching-normal-release> \
 IT1_RUN_ROOT=<new-short-absolute-root> IT2_SCENARIO=expiry \
 go -C ../m5-rehearsal test -race -count=1 -timeout 10m \
 -run '^TestHostRunnerComposition$' -v
# Repeat with a different root and IT2_SCENARIO=revoke.
```

The ordinary Go test command skips this opt-in integration. A skipped test is
not successful composition evidence. Unit plants calibrate every receipt
assertion, exact counters, bindings, time bounds, JSON/file intake and native
terms/contract checks. They show checker rejection of known violations, not the
truth of a supplied operator claim. Public results and process cleanup evidence
are in the rehearsal run root's `public/` directory; private fixture state stays
there and must not be published.
