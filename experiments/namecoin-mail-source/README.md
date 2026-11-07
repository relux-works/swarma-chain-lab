# Closed-world Namecoin mail: source prerequisite candidate

This packet prepares a disposable regtest experiment. It does not run mail, create
wallets or keys, submit transactions, or qualify a production service. Fresh
independent exact-head review precedes any separately admitted runtime phase.
Ordinary-client SPV/Electrum qualification remains a separate experiment.

The proposed result is **route-only**: `bob@bob.bit` stays the same while Bob
spends his current name output to change MX and TLSA to an independently keyed
provider. Existing mailbox contents, already accepted queues, and other users'
submission settings remain with their original authorities. A mailbox export or
in-flight handoff is outside this phase and unnecessary for the route result.

Read [SOURCE_PLAN.md](SOURCE_PLAN.md) for boundaries, trust limits, timings,
controls and runtime prerequisites. [pins/components.json](pins/components.json)
and the unmodified upstream Go lockfiles fix acquisition inputs. Public parser
fixtures in `fixtures/` are small, deterministic and contain synthetic TLSA
association bytes, not keys or usable mail credentials. Their exact expected DNS
RRsets are adjacent `.rr` files.

## Source observations that affect the design

* The pinned ncdns parser supports direct `mx: [[priority, absolute-hostname]]`.
  Its `tls` field accepts `[usage,selector,matching-type,base64-data]`; it emits
  hexadecimal TLSA data. Put `tls` under `_25._tcp.<MX-host>` using nested `map`.
* IFA-0001 requires MX synthesis from port-25 `_smtp._tcp` `srv` records and
  disallows direct MX in that specification. This ncdns snapshot instead emits
  the SRV only and accepts its direct `mx` extension. The parser probes exercise
  both layouts. The older six-field `service` layout yields no records here.
  This is an implementation/spec discrepancy, not evidence of compliance.
* ncdns's LRU caches raw name JSON without a time-based expiry. Zero maximum
  entries means unlimited in its groupcache dependency. Neither setting zero nor
  waiting the DNS TTL establishes a fresh name read. Restart/invalidation and a
  fail-closed freshness gate are runtime prerequisites, not implemented here.
* NameQuery consumes `name_show`'s value without checking expiry, height or a
  proof. Configure the walletless validating backend with `allowexpired=0`;
  independently verify actual errors and invalidate every cache for expiry and
  reorg cases. No DNSSEC signature certifies a global chain tip.
* Postfix `dane-only` rejects missing/insecure/unusable TLSA instead of selecting
  opportunistic TLS. Postfix trusts the validating resolver's result; it does not
  itself validate DNSSEC. Protect that resolver path and anchor `.bit` explicitly.
  The shared template also sets `tls_required_enable = no`; otherwise the pinned
  default allows a `TLS-Required: no` message header to weaken mandatory DANE.

## Offline source checks

`checks/parser_probe.go` runs inside an exact ncdns source copy with its locked
modules, in a clear-environment, network-unshared sandbox. It checks actual parser
output against independent expected RRsets, including the absence of synthesized
MX. `checks/verify_modules.py` independently computes Go canonical h1 hashes from
proxy zips and go.mod bytes and compares upstream locks and canonical HTTPS lookup
records. It makes no independent transparency-log inclusion-proof claim.

Use `checks/offline_checks.sh` with the staged canonical acquisitions and the
sandbox contract it describes. No network fallback, `go mod tidy`, `@latest`, or
dependency upgrades are permitted. C build/config probes use a private prefix;
never install host packages. The export report states actual failures and limits.

`checks/check_tls_required.py --upstream /path/to/verified/postfix-3.11.7
--postconf /path/to/pinned/postconf --out /evidence/header-check` runs in that
same offline sandbox. Supply an extracted, hash-verified pinned archive and its
checker binary. It queries effective settings and service overrides for A, B and
Bprime without service startup, and compiles the exact upstream state macro and
policy prefix with minimal test types. Its no-header, header and ESMTP REQUIRETLS
controls check policy selection before DANE initialization; they do not qualify
SMTP delivery. Wrong-key and no-STARTTLS header cases remain planned runtime
negatives requiring DEFER without message data.
