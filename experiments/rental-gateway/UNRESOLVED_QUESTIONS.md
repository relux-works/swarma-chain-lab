# Real serve integration decisions

The source evidence and viable boundaries are documented in
[SERVE-SURVEY.md](SERVE-SURVEY.md). No runtime implementation is claimed yet.

1. **Booking transport:** may this unit add a bounded read-only catalogue HTTP
   endpoint around the existing v1 Catalogue method and a thin client for the
   existing v1 routes? Current scope prohibits booking API changes, while no
   landed client/catalogue route exists. Alternative: explicitly choose embedded
   booking and account for its provider-key/state custody change. Keep v1; v2
   is not a constructor-only switch. Config privacy text must match the signed
   v1 constant, rather than silently alter it.
2. **Station placement and authority:** identify the existing sanctioned remote
   manager/Executor contract, or decide where LinuxUser executes and which
   service has authority for user/nftables/systemd operations. The planned
   unprivileged gateway on a different host cannot directly execute them.
   Confirm the Track B admin socket, TLS/client-certificate provisioning and
   station agent launcher boundary with that placement. No privilege changes,
   root gateway or ad hoc remote admin protocol are implied.
3. **Issued presentation source:** approve an operator-pinned read-only public
   presentation directory keyed by booking ID with atomic issuer publication,
   or identify an existing issuer read API. The gateway must never own issuer
   keys or sign/broadcast/fund grants to fill this gap.

After these decisions, complete real constructor wiring, strict config refusal
controls, actual Core/relay/CLI test mode and independent review. Linux execution
and final host deployment remain separate verification obligations. Gateway
deploy templates follow DK1 landing and the resolved runtime boundary.
