# Frozen rental wire fixture v1

Public deterministic fixture for independently implemented M1/M3 parsers.
The renter/provider/agent use public test scalars 3/2/4. Payment txid, block and
tip are synthetic repeated hex digits. This is **not** proof of a real payment,
a valid grant or live-chain admission. No production keys are included.

The five JSON files are canonical compact JSON with no trailing newline.
The provider package includes hold_created_at and hold_expires_at. SHA256SUMS
pins the frozen files. From the module directory, regenerate to a NEW path:

```sh
M3_FIXTURE_OUT=/absolute/new/output go test -run '^TestFrozenPublicFixture$' -count=1
```

Without M3_FIXTURE_OUT the test compares all five bytestrings against fresh
deterministic generation and validates the package signatures.
