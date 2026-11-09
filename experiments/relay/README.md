# Bounded rental Nostr relay

`swarma-relay` is a standalone Go relay for signed regular events 1059 (gift wrap),
8181 (consent) and 8182 (package). It reuses the reviewed gateway `nostr` event and
BIP-340 implementation and `exchange.CheckWork`; it neither decrypts messages nor
knows whether a renter has a live grant. The existing package-only booking relay
is unchanged. No go-nostr, NIP-29, wallet, model API or public admin API is used.

## Wire and admission

The [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) subset accepts
EVENT, REQ and CLOSE and emits OK, EVENT, EOSE, CLOSED and fixed-code NOTICE.
Filters support exact 64-character lowercase ids/authors/#p/#e, kinds,
inclusive since/until, and limit. Fields combine with AND; filters combine with
OR. Empty lists match nothing. Backlog is newest-first, ties by ascending ID,
bounded by each filter's limit and the global `backlog` cap. Limit zero returns
EOSE and retains live subscription matching. A rejected replacement removes the
old subscription. Unknown fields, duplicate keys, nulls and trailing input refuse.

[NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) AUTH uses a fresh
random challenge per connection, the exact configured public URL, a signed 22242
event within 600 seconds and exactly one relay/challenge tag. Up to eight keys
can authenticate on a connection. AUTH is never stored or broadcast. Write/read
auth can be required independently. `restrict_gift_wrap_reads` requires AUTH for
queries that could include 1059 and filters both backlog and live delivery to
the authenticated recipient. Each stored 1059 must have exactly one valid p tag.
When any AUTH-dependent policy is enabled the challenge is sent on connection.
Otherwise it follows the first command response, preserving the booking
publisher's first-response OK contract without changing that client.

[NIP-13](https://github.com/nostr-protocol/nips/blob/master/13.md) outer-event work
can be required for unknown publishers; only explicit `known_pubkeys` exempt an
authenticated identity (or the signed event author without AUTH). Publishing
never creates reputation. This is distinct from E1's work inside the encrypted
kind14 rumor. [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)
kind13 is the encrypted seal, not a standalone first-contact event. The deploy
profile leaves outer PoW and AUTH restrictions OFF until the gateway client
implements AUTH. See [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).

## Durability and bounds

The state root is a canonical owner directory (0700), with a single-writer flock.
Snapshot/lock files are regular, owner-only, single-link files; aliases refuse.
Acceptance writes an atomic bounded snapshot with file fsync, rename and directory
fsync before OK=true and before fanout. A valid event already in durable memory
gets OK=true with `duplicate:` and is not broadcast again. A persistence error
poisons the running store until restart, including when the durability result is
uncertain; no subsequent ACK claims success. Snapshot recovery revalidates event
signatures, supported kinds, duplicate IDs and bounds.

Created-at retention and future skew apply before publication and query delivery.
Expired events are pruned on new writes, restart and a one-minute maintenance
tick, including idle periods. Live events are never evicted to admit another
event. Config bounds cap stored bytes/count, event size, connections, retained IP
buckets, frames per minute, subscriptions, filters, backlog and outbound queues.
Fixed windows count malformed messages and control-frame pings/pongs too.
Disconnect retains the IP budget until its window ends; full IP tables refuse
new addresses instead of growing. A full outbound queue disconnects only that
slow consumer; network writes never run under the shared relay mutex. Storage
fsync remains serialized and may delay admission during slow local disk I/O.

The HTTP CLI listens only on IPv4 loopback. `trusted_proxy_ip` selects one exact
peer whose single `X-Real-IP` header is accepted; other forwarding headers are
ignored. No header on a trusted local connection means direct loopback service
traffic, sharing the loopback budget. The proxy must overwrite client headers,
as the Caddy template does. No public exposure bypassing that proxy is intended.
GET `/` upgrades to WebSocket; other routes refuse. Message bodies, AUTH events,
private content and peer addresses are not logged by the relay.

## Tools and artifacts

Use Go1.26.8, with installed dependencies and `GOTOOLCHAIN=local GOWORK=off`.
For offline validation also set `GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly`.

```sh
go mod verify
go vet ./...
go test -race -count=1 ./...
go run .scripts/guards.go -out .temp/guards
go build -trimpath -o .temp/swarma-relay ./cmd/swarma-relay
.temp/swarma-relay -config /absolute/public-service.json -check
.temp/swarma-relay -config /absolute/public-service.json -listen 127.0.0.1:18818
```

Start from `deploy/templates/relay/service.json`, fill the public URL and provision
the 0700 state parent before starting. `-check` creates no state or listener.
The deploy kit includes the relay in its independent double Linux build and
ships a systemd unit plus Caddy fragment; it performs no installation itself.
Guard outputs belong under `.temp/`; persistent relay events belong only in the
configured state root. Tests use synthetic keys and loopback fixtures. Hosted
Linux execution and real deployment remain separate evidence.
