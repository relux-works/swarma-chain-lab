# Frozen C0 input provenance

Upstream: `relux-works/swarma-credential-broker`, main
`7a730950fb0965fdfc34081b7d390f02e8c9a3bd`, after C0 PR #79.

| Local input | Upstream source | SHA-256 / transformation |
| --- | --- | --- |
| surfaces.json | contracts/lab-v0/surfaces.json | 8d819e57121a3993023e33fe085340269ff34e58676dafda5e55f03d39e458b7 |
| wire-fixtures.json | contracts/lab-v0/wire-fixtures.json | 6b0196268f5e920abf0cdfe10b2f94fb6ebccbb9dc330d3f218217b01f91423f |
| fixtures.json | contracts/lab-v0/fixtures.json | Seven relevant surface cases, selected without changing decoded case data; reserialized for the test fixture. Not an alternative C0 wire encoding. |

The two embedded inputs are byte-for-byte copies, including their lack of a
terminal newline. The frozen contract-index SHA-256 is
`4f9a81562d391153764b5ae75d7914cf83f03c1bb3d956461211d8eb36f6e7d8`.
`TestLabFrozenContentPins` checks these seals and a changed-byte negative.

The tagged test helper `lab_operators_linux_test.go` copies C0's literal,
separator, hexadecimal, scalar, wrong-kind and canonical-time operators from
`internal/labcontractv0/generated_test.go` and `catalogue_test.go`. `TestLabFrozenRecordCatalogue` applies them
through the actual runtime parser, visiting nested structures and array items;
`TestLabHeaderCatalogue` applies the ASCII field-name operators. Fixture scalars
are public synthetic data. The fake broker uses only
`PUBLIC-SYNTHETIC-ONLY-NOT-A-VENDOR-KEY`, never a vendor credential, and the worker
marker is `ssh-placeholder`. No test calls a vendor or installs native services.

The records are independent grammar fixtures, not a joined authorized
installation. Test helpers explicitly join public contexts, hashes, deadlines
and the current test process peer; they do not claim qualified time, approvals,
native three-account isolation or durable broker restart behavior.
