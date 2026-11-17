# Captured broker frames

Upstream: `relux-works/swarma-credential-broker` at
`698d9e40f57058addd80a82d56c356009239dea6`.

- `broker-frame.hex`: captured by calling `internal/wire/frame.go:Write` on
  the exact `{"ok":true}` control from `internal/wire/wire_test.go`,
  `TestFrameBounds`.
- `broker-service-hello-request.hex` and `broker-service-hello-response.hex`:
  actual socket bytes captured with `io.MultiWriter` / `io.TeeReader` while
  repeating `internal/server/services_linux_test.go`,
  `TestServiceSocketStandardHello`, using its landed `newSocketService`,
  `testutil.New`, `start` and `dial` helpers. The request ID and versions-only
  params are unchanged. The response's numeric UID is a fixture observation,
  not an installation/account pin.

Hex files include the original four-byte big-endian length prefix. They carry
no material. Lease-material replies are deliberately not persisted. Capture
commands and the small capture harness are retained in the private handoff.
The fake broker uses the closed service schemas in `internal/wire/service.go`
and the response envelopes in `internal/server/services.go` at that commit;
`harness` is `claude_code`, not a provider display name.
