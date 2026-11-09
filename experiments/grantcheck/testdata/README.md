# Recorded verdict vectors v1

`verdicts-v1.json` records 21 outputs from `TestCoreVectors` using the actual
public checker API, pinned Namecoin Core regtest, and grants created by
`rental.IssueGrant`. It includes public presentations, verified sender inputs,
verifier time, setup description, expected routing/metadata, and node binary
SHA-256 pins. Malformed and oversized input rows are intentionally invalid.

Run `go test -run '^TestRecordedVectors$' -v .` without a node. This checks the
closed consumer routing matrix and live rows' cryptographic metadata bindings.
It does not replay the node, prove current liveness, or permit production to
use a recorded verdict. The production constructor always builds kernelbind.

`CG1_REGTEST=1` generates a new `vectors.json` in the fresh `CG1_RUN_ROOT` only
after all actual results match their independently specified expectations.
Transactions and keys vary by run; compare decisions and contract fields, not
byte equality of independent generated ledgers. The committed recording is
stable. Public issuer receipts and presentations accompany each run. All nested
state directories, RPC credentials and wallet files must stay out of delivery
evidence. The root-level `node.pid` is retained to verify owned-process cleanup.
