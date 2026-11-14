# Guard-removal controls

The script uses `go test -overlay` to remove one named semantic guard per run,
without writing to checker/kernel source. It records original/mutant hashes,
command, PID, real exit, named test actions, intended assertion witness and bound.
Every intended test failure must exit 1; compile/setup errors, skips and unrelated
failures are invalid. No published source or test is replaced by the script.

| Mutant | Named failing subtest | Narrowed bound |
| --- | --- | --- |
| `no-envelope` | `NoEnvelope` | Early missing-envelope classification; signature checks remain |
| `bad-signature` | `BadSignature` | Signature math with other bindings retained |
| `wrong-key` | `WrongKey` | Verified key cannot be replaced by a proof-claimed key |
| `wrong-executor` | `WrongExecutor` | Protected terms executor pin |
| `unknown-issuer` | `UnknownIssuer` | Early issuer pin before metadata/reads; deeper K1 pin remains |
| `before-window` | `BeforeWindow` | Early not-before routing; final CG1 clock defence remains |
| `after-window` | `AfterWindow` | Early expiry before reads; late expiry defences remain |
| `stale-ibd` | `StaleNode-ibd` | Bench sync routing; K1 IBD defence remains |
| `stale-height` | `StaleNode-height` | Protected minimum height before K1 chain binding |
| `stale-headers` | `StaleNode-headers` | Conservative catch-up refusal |
| `replay` | `Replay` | Per-instance accepted-nonce memory |
| `matrix-sender` | `MatrixSender` | No id-to-claimed-key normalization |
| `owner-dm` | `OwnerDM` | No admission or replay work for protected owner route |
| `text-authority` | `TextAuthority` | No prose-based early live return |
| `seal-mempool` | `SealMempool` | `gettxout(..., true)` includes mempool spends |
| `seal-confirmed` | `SealConfirmed` | Null UTXO is spent |

Some kills observe changed refusal routing or new reads rather than a live
admission. Those bounds are explicit above: they do not prove that removing a
single early guard defeats the stack's independent deeper defences.
