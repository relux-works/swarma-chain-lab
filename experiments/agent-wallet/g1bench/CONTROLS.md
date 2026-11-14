# Guard-removal controls

The script uses `go test -overlay` to remove one named semantic guard per run,
without writing to checker/kernel source. The missing-co-signature plant removes
both presence and verification as one semantic bypass. It records original/mutant hashes,
command, PID, real exit, named test actions, intended assertion witness and bound.
Every intended test failure must exit 1; compile/setup errors, skips and unrelated
failures are invalid. No published source or test is replaced by the script.

| Mutant | Named failing subtest | Narrowed bound |
| --- | --- | --- |
| `no-envelope` | `NoEnvelope` | Early missing-envelope classification; signature checks remain |
| `bad-signature` | `BadSignature` | Signature math with other bindings retained |
| `wrong-key` | `WrongKey` | Verified co-signer cannot be replaced by a proof-claimed key |
| `wrong-executor` | `WrongExecutor` | Protected terms executor pin |
| `unknown-issuer` | `UnknownIssuer` | Early issuer pin before metadata/reads; deeper K1 pin remains |
| `before-window` | `BeforeWindow` | Early not-before routing; final CG1 clock defence remains |
| `after-window` | `AfterWindow` | Early expiry before reads; late expiry defences remain |
| `stale-ibd` | `StaleNode-ibd` | Bench sync routing; K1 IBD defence remains |
| `stale-height` | `StaleNode-height` | Protected minimum height before K1 chain binding |
| `stale-headers` | `StaleNode-headers` | Conservative catch-up refusal |
| `replay` | `Replay` | Per-instance accepted-envelope memory |
| `matrix-sender` | `MatrixSender` | No id-to-claimed-key normalization |
| `owner-dm` | `OwnerDM` | No admission or replay work for protected owner route |
| `text-authority` | `TextAuthority` | No prose-based early live return |
| `seal-mempool` | `SealMempool` | `gettxout(..., true)` includes mempool spends |
| `seal-confirmed` | `SealConfirmed` | Null UTXO is spent |
| `signed-text-removal` | `DeliveryBinding/text` | Signed hash binds text despite equal outer carriage |
| `warm-live-authority` | `SealConfirmed` | Earlier live admission on the same Gate cannot replace a post-spend grant check; signature, replay and fresh sync checks remain |
| `gate-drops-issuer-refusal` | `UnknownIssuer` | Gate preserves issuer refusal even when verified signer equals the real grantee |
| `accept-without-cosignature` | `CosignatureMissing` | Valid Ed25519 envelope alone cannot supply the grant key; the mutant deliberately removes both co-signature presence and verification checks |
| `ed25519-author-as-sender` | `TwoIdentities` | A valid Track A pair requires the verified BIP-340 co-signer as sender, never its Ed25519 author |
| `cosignature-replay-key` | `CosignatureIndependentReplay` | Independent valid co-signatures on identical bytes remain one accepted envelope |

Some kills observe changed refusal routing or new reads rather than a live
admission. Those bounds are explicit above: they do not prove that removing a
single early guard defeats the stack's independent deeper defences.

The 22 plants retain all 19 existing controls and add the three Track A controls.
`SealConfirmed` can run alone: it warms a Gate and its exact checker
cache before creating and confirming the spend. In a complete run the same Gate
is retained from `SealMempool` through confirmation, with cold-Gate neighbours
at both stages. The signed-text plant removes only the hash comparison, keeping
room, `to`, outer carriage, signature, nonce and lifetime checks intact.
