# Remaining integration decisions

- The landed gateway RelayClient does not speak NIP-42. Its AUTH adapter is a
  separate follow-up. The compatible deploy profile permits unauthenticated
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
- Full issuance/presentation composition depends on BG1. The Darwin fake slotd
  proves codec/manager behavior only; no real payload or OS wipe claim follows.
