# Remaining integration decisions

- M1 is regtest-only. Mainnet runtime admission, deployment, real keys, signer
  caps, payment sweeping, revocation broadcast and production availability are
  M4/M5 work; no source build or passing test authorizes them.
- M4 owns structured renter requests, scope/target/budget enforcement,
  anti-replay, prize-outpoint exclusion and effects. Kernel scope output alone
  is never authority for an effect.
- Gateway/issuer must keep persistent state off hostile station UIDs. Backup,
  restore and disaster recovery must preserve burned reservations/closures.
- Current relevant transaction decoding is legacy-only and bounded. A booking
  payment with witness inputs fails closed. Broader payment support needs an
  explicit decoder/profile extension and its own controls; unrelated witness
  traffic is already tolerated.
- A first kernel observation cannot prove previously unobserved name history.
  A deployment needing universal historical closure must provide a trusted
  persistent observer or a separately specified history-reconstruction rule.
- M3 hold bounds are signed; late arrival refuses for operator/refund review.
  v1 does not accept a watcher receipt as proof of earlier payment observation.
- The CIP drafts here require independent review and transfer to the public
  swarma-link-spec repository by its owner. M1 producer does not publish it.
