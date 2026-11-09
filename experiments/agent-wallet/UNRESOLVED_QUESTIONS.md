# Deployment decisions and limits

- Curator must pin actual wallet directory, memory-zone directory, installed
  executable and private operator config paths. This package is a draft skill;
  it neither installs nor proves enforcement of those restrictions.
- Operator issuance must explicitly produce this wallet-terms profile and the
  matching K1 consent/issuance proof. The complete booking-UI contract is not
  implicitly convertible into wallet terms; a shared future contract profile
  requires its own reviewed change.
- Automated reconciliation, refunds/reclaim of incomplete name commitments,
  journal garbage collection, safe backup restoration and anti-rollback storage
  are outside this bounded demo. Reserved uncertain effects never retry.
- W2 supplies the separate service-user boundary and templates, but local
  macOS socket fixtures run under one UID. Actual Linux different-UID denied
  reads/socket isolation and systemd enforcement remain Infra qualification;
  no local users/services were created. W1 legacy remains unsandboxed.
- W2 v1 rejects name registration/update. W2b requires explicit commit/reveal
  continuation semantics; terminal duplicate replay must not be weakened.
- Receipt keys, peer UIDs/groups, private roots and client action keys require
  operator provisioning. There is no automatic key/journal migration or rotation.
- Observed key rotation is sticky; an unobserved rotate-away-and-back is not
  reconstructed by the current K1 resolver. A complete historical name walk
  would require a separate bounded design and evidence.
