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
- The shared-user unsandboxed model cannot prevent an agent from bypassing the
  CLI. Hardware custody, a separate signing service or OS confinement would be
  separate architecture decisions, not properties supplied by this skill.
- Observed key rotation is sticky; an unobserved rotate-away-and-back is not
  reconstructed by the current K1 resolver. A complete historical name walk
  would require a separate bounded design and evidence.
