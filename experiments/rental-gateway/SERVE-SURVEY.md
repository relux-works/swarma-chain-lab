# Real gateway serve: landed constructor and deployment survey

Baseline: `30c35534d484ea3c82ee02f511e97af5ef828069`, including P1 and CG1.
This preserves the initial source survey and proposed wiring contract. See
[SERVE.md](SERVE.md) for the later implementation and remaining dependencies.
The existing command builds with Go1.26.8 on darwin/arm64. No service, Linux user,
VM, wallet, node or host configuration was started or changed for this survey.

## Landed construction chain

1. Strict public config validation must precede keys, sockets, state or commands.
   Only regtest is supported; real mode must reject every stub/local-test option.
2. `gateway.LoadAgentKey` reads the gateway's private messaging key. A separate
   private RPC route file can supply `single-use.Route` to `single-use.NewRPC`:
   literal loopback IP, bounded port, exact username `w3-observer`, no fallback.
   Public config pins the route endpoint; private credential values are never
   accepted inline, logged or passed as process arguments.
3. `kernelbind.New(node, stateDir, agentName, landlordName, issuerPubkey)` builds
   the real v3 adapter. It fixes regtest/genesis and derives the seal script from
   the issuer key. Explicit network/genesis/seal-script config pins must match
   those derived values; they cannot override them. Pass the same adapter as both
   `gateway.Config.Kernel` and `.Presenter` to retain fresh inline/cache checks.
4. `bookingbind.Adapter` accepts its **in-process** `Service` interface plus
   agent/landlord names, agent public key and the owned clock. It implements
   E1's Catalogue, Book, Consent and Status. `bookingbind.Grants` separately
   adapts `PresentationSource.Presentation(ctx, bookingID)` and checks proof
   signatures and booking/name/window binding. It never issues or funds grants.
5. `exchange.New` takes that backend/source, isolated state, names, PoW and bounded
   queue/rate/replay/time settings. `gateway.New` binds the exchange to the agent
   key, relay and gateway registration/current-time-check hooks. Issuance and
   ready notices do not start a station; the next fresh live message does.
6. `station.LinuxUserDriver` takes `LinuxUserConfig`, a real `station.Executor`
   and a non-nil `TrackBAdminClient` for deployment. Nil token administration
   falls back to test-only random tokens and must be rejected in real mode.
7. Screening off needs an explicit implementation of `screen.Screener` that
   permits content only after the gateway's unchanged kernel admission. It must
   be selected only by explicit `screening: "off"`, recorded at startup/release,
   and named as disabled screening. A model adapter can later occupy that same
   interface. `screen.Stub` is not that implementation.
8. Open the journal, real relay and station listener with bounded cancellation;
   close relay/exchange/listener on shutdown and stop the tick goroutine. The
   current CLI has an uncancelled tick loop and unconditionally removes the Unix
   path; the new wiring must not delete an unrelated existing socket/file.

The parent gateway module currently has no kernelbind dependency. Wiring the
command requires the nested module and its in-tree replacement closure (rental,
booking, payment-chain, single-use and sealwatch), plus corresponding CI/build
coverage. This is module glue; it does not require changing kernelbind's API.

## Booking boundary: missing transport, not a constructor option

`kernelbind/bookingbind.Service` requires `Catalogue(int64,int)`, `Book`,
`AcceptConsent` and `Get` returning v1 types. The landed booking HTTP handler
exposes only GET `/`, POST `/book`, POST `/consent` and GET `/booking?id=...`.
It has **no catalogue JSON endpoint** and no Go HTTP client. The HTML homepage
does not carry the full template/profile/hash catalogue and is not a substitute.

A thin bounded HTTP client can reuse the three existing v1 booking routes, but
cannot implement the real dynamic Catalogue without another boundary. The clean
separate-service option is one explicit read-only catalogue endpoint wrapping
the existing method, plus client glue. That is a booking API extension, which
the current request excludes, so it requires a scope decision before coding.
The other clean option is an embedded booking service, which changes deployment
ownership by placing its provider signing key/state/watcher in the gateway;
that is not silently selected. Reading the booking's private state or scraping
HTML is not an acceptable substitute.

ServiceV2 is **not a one-file constructor switch**: it has `CatalogueV2`,
`BookInputV2`, `BookingV2`, `ContractV2` and per-coin quote/payment policy; the
adapter encodes v1 contracts/consent and NMC-only selection, and the landed CLI
and HTTP handler remain v1. Keep the v1 adapter until a separately scoped v2
adapter/transport contract is approved.

The privacy notice is a signed v1 constant: `Contract.Validate` requires its
exact hash. A config may pin that exact notice and template/profile hashes;
arbitrary replacement privacy text would require a signed-wire policy change.
The terms reply is structured E1 catalogue output, not an arbitrary prose field.

## Issued presentation handoff

There is a `PresentationSource` interface, but no deployed client or file source.
The existing Core lifecycle uses a private in-memory test source populated by
the independent issuer. Gateway must not gain issuer keys or issuance methods.
A possible minimal production adapter reads bounded canonical public
presentations from an operator-pinned directory, with booking-ID-only names,
no symlinks/traversal, absent-file meaning not-yet-issued and binding verified by
`bookingbind.Grants`. The separate issuer's atomic publication contract and
custody/permissions need agreement; this survey does not fabricate that service.

## Linux station boundary

`LinuxUserDriver` is a command planner, not a remote manager client. No real
`station.Executor` implementation is shipped; tests inject `FakeExec`.
Create executes useradd/install/chown/chmod/id/nft; start invokes systemd-run;
teardown invokes systemctl/nft and UID-scoped cleanup/userdel. Those need local
host authority. A gateway running as its own unprivileged service user on one
host cannot thereby create stations on a different host.

The deployment plan separates gateway and station hosts. Either a documented
existing privileged manager bridge must implement the Executor boundary, or
deployment placement/authority must change. Adding sudo, running the public
gateway as root, or inventing a remote admin protocol would be a separate
architecture/security decision, not minimum wiring. No such action is taken.

LinuxUserConfig requires gateway, executor-proxy and model API literal IP:port
allowlist entries, optional package proxy, home root and an agent command.
Screening off does not remove the station's separate model API requirement.
Track B uses a private Unix admin socket; its host placement must also match.
The station link accepts a supplied net.Listener but has no TLS provisioning
implementation. Deployment comments require TCP+mTLS; command-level TLS listener
wiring can use pinned certificate/key/client-CA files, but per-station client
certificate provisioning and the actual station agent launcher remain external
runtime inputs. The existing station stub supports only the local test path.

macOS can validate config, constructor selection and command plans, and run a
real Core/relay/CLI test with LocalTestDriver under explicit mode=test. It cannot
establish actual Linux user creation, nftables enforcement, systemd lifecycle or
the remote manager path. These must remain reported as not run locally.

## Proposed public config groups

One strict, bounded JSON file; secret material only through protected file refs:

| Group | Proposed keys and meaning |
| --- | --- |
| Identity | version, mode=regtest/test, agent_key_file, agent_pubkey |
| Kernel | network, genesis, agent_name, landlord_name, issuer_pubkey, seal_script, state_dir, rpc_host, rpc_port, rpc_route_file |
| Runtime | journal_dir, relay_url, station listener/endpoint, TLS cert/key/client_ca refs, tick interval |
| Exchange | state_dir, booking endpoint, exact privacy/template/profile pins, presentation source, PoW/rate/queue/replay/time limits |
| Station | driver=linux-user/local-test, manager boundary, Track B admin socket, four allowlist endpoints, home_root, agent_command |
| Screening | screening=off; explicit startup and manifest disclosure |
| Tests only | stub kernel/verdict, stub screener, local driver/station stub; all rejected outside mode=test |

The transport/manager decisions above determine the final config, so these keys
are a proposal, not a committed compatibility promise. Deploy gateway templates
and manifest readiness must wait for DK1 plus the resolved real runtime chain.
No gateway unit should claim operational readiness while required boundaries
are missing.

## Source anchors

- `cmd/gateway/serve.go`, `gateway/gateway.go`, `gateway/exchange.go`.
- `kernelbind/kernelbind.go`, `kernelbind/bookingbind/bookingbind.go`.
- `../rental-booking/http.go`, `catalogue.go`, `service.go`, `service_v2.go`,
  `catalogue_v2.go`, `contract.go`, `cmd/rental-booking/main.go`.
- `exchange/types.go`, `exchange/engine.go`, `screen/screen.go`.
- `station/linuxuser.go`, `station/station.go`, `station/trackbadmin.go`.
- `stationlink/stationlink.go`, `kernelbind/exchange_core_test.go`.

Decisions needed before dependent implementation are in
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).
