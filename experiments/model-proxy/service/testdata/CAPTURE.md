# Reproducing the nonmaterial captures

Use a disposable checkout of `relux-works/swarma-credential-broker` at
`698d9e40f57058addd80a82d56c356009239dea6`, Go 1.26.8 and a private absolute
HOME/cache/temp environment. No provider, real credential or lease method is
involved. These instructions reuse the broker's existing test helpers.

Add `internal/server/capture_linux_test.go` in that disposable checkout:

```go
//go:build linux

package server

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "io"
    "os"
    "path/filepath"
    "testing"

    "github.com/relux-works/swarma-credential-broker/internal/lease"
    "github.com/relux-works/swarma-credential-broker/internal/testutil"
    "github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: capture only the existing standard hello request and its real reply.
func TestCaptureStandardHello(t *testing.T) {
    e := testutil.New(t, lease.Options{})
    broker, _ := newSocketService(t)
    path := start(t, e, func(s *Server) { s.Services = broker })
    c := dial(t, path)
    var sent, received bytes.Buffer
    req := wire.Request{Method: "hello", ID: "standard", Params: json.RawMessage(`{"versions":[1]}`)}
    if wire.Write(io.MultiWriter(c, &sent), req) != nil {
        t.Fatal("hello write failed")
    }
    if _, err := wire.Read(io.TeeReader(c, &received)); err != nil {
        t.Fatal("hello read failed")
    }
    for name, data := range map[string][]byte{
        "broker-service-hello-request.hex": sent.Bytes(),
        "broker-service-hello-response.hex": received.Bytes(),
    } {
        if os.WriteFile(filepath.Join(os.Getenv("CAPTURE_DIR"), name), []byte(hex.EncodeToString(data)+"\n"), 0600) != nil {
            t.Fatal("capture write failed")
        }
    }
}
```

Create a new absolute output directory, export it as `CAPTURE_DIR`, then run
`go test -count=1 -run '^TestCaptureStandardHello$' ./internal/server`.
The response UID is the capturing process's effective UID, so a capture from a
different UID has different bytes. The committed fixture records UID 1001; it
is a test observation, never an installation identity pin.

For `broker-frame.hex`, use a temporary command under that same broker checkout
so it can import `internal/wire`. Call `wire.Write(&buffer,
map[string]any{"ok": true})`, then write `hex.EncodeToString(buffer.Bytes())`
plus one newline to the output file. This is the upstream `TestFrameBounds`
positive control. Both recipes retain the four-byte big-endian frame header.
