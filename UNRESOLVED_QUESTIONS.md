# Unresolved questions

Should detached v2 retain its existing observer-local first-admitted seal/ID
binding, or migrate to a versioned per-certificate chain issuance commitment?

V2 has no issuance locator or per-certificate commitment. Two valid signatures
over identical content can each be admitted first by different fresh observers;
one observer refuses the second ID after admitting the first. V1 and v3 bind
exact signed IDs to confirmed commitments. The [identifier audit](docs/signature-identities.md)
and `TestCoreDetachedSecondSignatureSealBinding` retain this distinction.
