# IT2: payload startup can precede gateway admission readiness

**Historical evidence on G6.** SR1 (`2b37db7c`) resolved this product gap;
RK1 (`14e35bbc`) resolved the later relay-idle expiry failure. The text below
describes the original failed runs and the original expected-defect witness,
preserved in their sealed packets. The current witness instead checks SR1
admission with a wrong-credential negative control; its control restores the old
gate. See README for current commands. Full composition outcomes remain bound
to each resumed run, not inferred from these fixes.

The full NMC rehearsal remains blocked. Two genuine-Core runs at signed harness
head `ab358652dd334ea3ecd69a119eadc095b3af2ac7`, on product G6
`d2fb89c10bd5c901de2afa8ecac415825fe472b5`, reached native SG1 confirmed
presentation and relay `issued`/`ready`, but failed their first model reply.
The actual payload process exited with the fixed `PAYLOAD_CHANNEL` error.

Both private-state summaries show one accepted delivery in the gateway journal,
`started=true`, an active model registration with zero requests, and no completed
closure. The earlier `revoke-03` run reached two real MP1/fake-upstream requests
and both cap refusals, so the start failure is timing-sensitive rather than an
unconditional bootstrap or TLS incompatibility. That earlier run did not prove
revocation completion: its seal assertion used the CLI string adapter, which
cannot preserve JSON-RPC null semantics. The successor uses native read-only
JSON-RPC with an unspent-before/null-after check, but was blocked before revoke.

## Reachable ordering

1. `gateway.startStation` registers the channel secret, then calls the driver's
   `StartSession`; it calls `Journal.MarkStarted` only after that method returns.
2. `gatewaybind.Driver.StartSession` activates the real model binding and asks
   the broker/manager to start. The manager starts the payload process before
   acknowledging the running state back to the gateway.
3. That process may connect and send stationlink Hello before `MarkStarted`.
   `gateway.stationHello` refuses it with `session not started`.
4. PL1 `Client.Run` treats the non-System Hello as terminal `ErrChannel` and
   exits. A later manager running acknowledgment can leave the gateway started
   with an accepted delivery but no live payload consumer.

The full process logs intentionally do not expose individual handshake frames.
They establish the fixed failure and durable states above; attributing those
particular failures to this ordering is supported by the following independent
witness, not a claim that their logs recorded the exact Hello response.

## Deterministic witness and controls

`TestStartupOrderingWitness` calls the real gateway `StartSlot`, using explicit
kernel/driver/publisher stubs to isolate scheduling. During the driver's still-
running `StartSession` callback it proves all of the following over actual TLS:

- The channel credential is already registered but the journal is not Started.
- Real stationlink Hello returns exactly `session not started`.
- Real PL1 `Client.Run` returns exactly `PAYLOAD_CHANNEL`.
- After the callback returns, an identical credential successfully authenticates
  and receives a System frame from the same gateway.

It passes without sleeps, retries, a modified product or a weakened gate. It
proves this reachable ordering and neighboring successful handshake; it is not
an additional Core or native-CLI test. The full runs supply those separate facts.
A bounded overlay control removes only the `!slot.Started` Hello refusal and
makes the witness fail at `pre-start Hello was not refused at the exact gate`.
The control fails at the intended assertion, not compilation or setup.

```sh
go test -race -run '^TestStartupOrderingWitness$' -count=1 -v -timeout 30s
go run .scripts/plant-startup-gate.go /absolute/repo /absolute/new-gate-control
go test -overlay /absolute/new-gate-control/overlay.json -race \
  -run '^TestStartupOrderingWitness$' -count=1 -v -timeout 30s
# The final command must exit 1 at the exact gate assertion above.
```

## Next product unit

A separately reviewed product change must resolve startup readiness while
preserving pre-grant/pre-start admission, credential/HMAC checks, bounded failure
and cleanup. The rehearsal must not hide the race with a launch sleep, fabricated
running state or silent payload reconnect. The appropriate readiness/handshake
contract belongs to the product fix; IT2 changes no product code.

After the fix lands, rerun both full variants on the exact signed successor.
Verify first delivery, accounting, cap/no-retry, native SG1 seal-spend refusal,
expiry, model credential revocation and manager/helper cleanup. Neither full
variant currently passes, and Linux isolation/physical wipe remain separate.
