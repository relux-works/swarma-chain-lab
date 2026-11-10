# Pure public model configuration validation

`ValidatePublicModelConfig(b []byte, want TypedProfile) error` composes the
existing public FileConfig decode with payload model pairing. `TypedProfile`
contains exactly `Dialect`, `Model`, `MaxTokens`, `Endpoint`, and `CertSHA256`.
It never opens the inert path strings in the public config, reads environment or
time, accesses a key, starts a proxy, or mutates the supplied bytes.

`DecodeFileConfig` owns the sole FileConfig schema. It preserves the existing
loader's 65536-byte input bound, surrounding-whitespace trimming, canonical JSON
field order/encoding and duplicate/escaped-key refusal, returning `CONFIG_FILE`.
`CheckModelPair` checks the selected model, nonzero/context-bounded token count,
endpoint/cert pin and Messages/Responses profile pairing, returning
`PAYLOAD_CONFIG`. Model-proxy's loader keeps its DK5 installed-file custody check and then calls
`ParseConfig`, which delegates to this decoder; payload pairing delegates to the
shared checker. Empty or oversized installed files retain `DK5_FILE_SIZE`; the
pure parser returns `CONFIG_FILE` for the same byte lengths.
Their public compatibility types are aliases, not second independently maintained
schemas. Request-body JSON validation in the proxy retains its separate contract.

These are the payload's existing public checks, not full proxy service-startup
validation. In particular, pairing intentionally does not impose every stricter
`CONFIG_PROFILE` rule (the golden table pins the uppercase upstream-host
asymmetry), validate prices, establish trusted provisioning or admit a slot.
Callers still need the appropriate custody/manifest/receipt checks.

Run `go test -race ./modelprofile/...` from single-use in owned scratch. The same
literal `testdata/golden.json` is read by actual proxy-loader and payload consumer
tests. Valid neighbours, exact refusal codes and nonmutation are checked. The
repository `.scripts/dk5b-api-guards.go` calibrates the shared checks and real
consumer delegation; its output is public text evidence under the chosen scratch.
