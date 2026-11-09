# Remaining integration decisions

- The gateway RelayClient supports NIP-42 and repeats authentication after
  reconnect. The compatible deploy profile still permits unauthenticated
  reads/writes and leaves recipient restriction OFF; gift-wrap ciphertext and
  recipient metadata can therefore be read by other subscribers. Enable
  `restrict_gift_wrap_reads` only after every intended reader authenticates.
- Outer-event PoW is OFF; E1's encrypted-rumor PoW stays gateway-owned. Operators
  may configure outer work separately but must account for ephemeral wrapper
  keys and sender compatibility. No live-grantee inference is implemented here.
- The actual client-facing proxy must overwrite X-Real-IP and preserve the
  configured trust boundary. If another proxy is introduced, specify and test
  its address chain instead of accepting arbitrary forwarded headers.
- Local CLI/native tests and cross-builds do not certify systemd/cgroup or host
  isolation. Host unit validation, certificates, DNS and deployment are external.
- Full issuance/presentation composition is exercised separately. The Darwin fake slotd
  proves codec/manager behavior only; no real payload or OS wipe claim follows.
- RK1 uses standard NIP01 timestamp pagination within configured replay and
  retention bounds. Equal-timestamp page exhaustion is explicitly counted as
  REPLAY_OVERFLOW. A universal acknowledged cursor/delivery protocol remains a
  future design item; no silent completeness guarantee is made here.
