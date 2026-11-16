# Pinned trust-contract vectors

Both files are copied VERBATIM from swarma-link-spec commit
`bd3bc80e5543d8a563343ec05abd1a5f3f67284c` (v0.1.51):

| Local file | Upstream path | SHA-256 |
| --- | --- | --- |
| `trust-vectors.json` | `vectors/LIP-0013/trust-vectors.json` | `9c29cddd739d56c5d15f4663c3cc923c6ea016730fc62634bff4b4214bf27ff8` |
| `contract-vectors.json` | `vectors/LIP-0014/contract-vectors.json` | `563d49574f3c2bd913316cd0b0a295987648f5c281d28a68b065bf96ef180f14` |

The files fit the repository's existing fixture practice (the notary corpus is
larger). Each has a `.sha256` record and an executable hash/count pin. Run from
this directory: `sha256sum -c trust-vectors.json.sha256 contract-vectors.json.sha256`.

LIP-0013 tests judge all 4 valid contracts, 32 invalid contracts, 15 binding
vectors and the 3 envelope-section grants. The 26 kind-8185 envelope admission
vectors are preserved but NOT JUDGED: this module checks grants, not envelopes.
The public-hygiene check allows the RFC 2606 `.example` hosts used in this file.

LIP-0014 tests judge all 151 contract vectors with their exact expected first
refusal or acceptance and their published derived values. The reader supports
both member sets, including /1 vectors. D12 is retained: hypothetical delegable
spend is not enabled. The 39 section-8 parent/child pairs are enumerated and both
documents are run through the parser. Their pair-level verdicts are NOT JUDGED:
this copy implements section 3.1, not section 8; G1.0 refuses all /2 children.
Six pairs describe the hypothetical spend profile with D12 lifted, which is not
this reader's profile. This is an explicit coverage gap, not conformance proof
for delegation. No vector expectation has been changed to hide the gap.

Run document and binding vectors from the module:
`go test -count=1 -v -run 'TestVectorFilePinned|TestLIP0013|TestLIP0014|TestV2|TestNotary' ./internal/trustcontract`.
The keys are published BIP-340 test keys, never custody material.
