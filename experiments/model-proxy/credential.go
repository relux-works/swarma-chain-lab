package modelproxy

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"sync"
)

const (
	ModeDevelopment   = "development"
	ModeManaged       = "managed"
	SchemeAPIKey      = "api-key"
	SchemeOAuthBearer = "oauth-bearer"
	// MaxCredentialVersions bounds the values the tripwire remembers in one
	// process. A source that exceeds it is refused rather than forgotten.
	MaxCredentialVersions = 256
)

// UpstreamCredential is one provider credential obtained from the source per
// use. Value never prints or encodes; Version is an opaque identifier that a
// renewal request names. The agent never holds this credential.
type UpstreamCredential struct {
	Scheme  string
	Value   UpstreamKey
	Version string
}

func (UpstreamCredential) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private upstream credential]")
}
func (UpstreamCredential) String() string   { return "[private upstream credential]" }
func (UpstreamCredential) GoString() string { return "[private upstream credential]" }
func (UpstreamCredential) MarshalJSON() ([]byte, error) {
	return []byte(`"[private upstream credential]"`), nil
}
func (UpstreamCredential) MarshalText() ([]byte, error) {
	return []byte("[private upstream credential]"), nil
}
func (c UpstreamCredential) valid() bool {
	return (c.Scheme == SchemeAPIKey || c.Scheme == SchemeOAuthBearer) && printable(c.Value.Reveal(), 4096) && printable(Secret(c.Version), 128)
}

// printable admits the existing key alphabet: 1..max bytes of visible ASCII.
func printable(s Secret, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for _, v := range []byte(s) {
		if v < 33 || v > 126 {
			return false
		}
	}
	return true
}

// CredentialSource supplies the upstream credential per use. The source, not
// the proxy, is the only refresher: after an upstream 401 the proxy calls Renew
// naming the rejected Version and uses whatever current credential comes back.
// A source that cannot supply a credential returns an error; the proxy then
// refuses with CREDENTIAL_UNAVAILABLE and makes no upstream request. The broker
// adapter implements this interface in a later slice.
type CredentialSource interface {
	Credential(ctx context.Context) (UpstreamCredential, error)
	Renew(ctx context.Context, rejected string) (UpstreamCredential, error)
}

// brokerSource is the allow-list for managed mode. The marker method is
// unexported, so only a type declared in this package can implement it: no
// wrapper, file-reading source or static key qualifies from outside. The broker
// adapter implements it when it lands; until then managed mode refuses to
// construct with CONFIG_MODE_NO_BROKER, and tests reach it only through an
// unexported double.
type brokerSource interface {
	CredentialSource
	brokerCredentialSource()
}

// staticSource wraps the existing Config.APIKey as a single-version source.
type staticSource struct{ value UpstreamKey }

func (s *staticSource) Credential(context.Context) (UpstreamCredential, error) {
	return UpstreamCredential{Scheme: SchemeAPIKey, Value: s.value, Version: "static"}, nil
}
func (s *staticSource) Renew(ctx context.Context, _ string) (UpstreamCredential, error) {
	return s.Credential(ctx)
}

// FileSource reads an api-key credential from a private 0400 file on every use
// and on every renewal. It exists for development and tests only; managed mode
// refuses it at New. The version advances whenever the file content changes.
type FileSource struct {
	path    string
	mu      sync.Mutex
	current UpstreamKey
	serial  uint64
}

func NewFileSource(path string) *FileSource { return &FileSource{path: path} }

func (*FileSource) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[file credential source]") }
func (*FileSource) String() string             { return "[file credential source]" }
func (*FileSource) GoString() string           { return "[file credential source]" }

// read holds f.mu. It never returns bytes from a file that fails the private
// file contract, and never keeps more than the current value.
func (f *FileSource) read() (UpstreamCredential, error) {
	raw, e := ReadPrivateFile(f.path, 0400, 4096)
	if e != nil || !printable(Secret(raw), 4096) {
		return UpstreamCredential{}, fail("CREDENTIAL_UNAVAILABLE")
	}
	if subtle.ConstantTimeCompare(raw, []byte(f.current.Reveal())) != 1 {
		f.current = NewAPIKey(Secret(raw))
		f.serial++
	}
	return UpstreamCredential{Scheme: SchemeAPIKey, Value: f.current, Version: fmt.Sprintf("file-%d", f.serial)}, nil
}
func (f *FileSource) Credential(context.Context) (UpstreamCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.read()
}

// Renew re-reads the file. The same version as the rejected one means no
// renewal is available; a version already superseded returns the current one.
func (f *FileSource) Renew(_ context.Context, rejected string) (UpstreamCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, e := f.read()
	if e != nil {
		return UpstreamCredential{}, e
	}
	if c.Version == rejected {
		return UpstreamCredential{}, fail("CREDENTIAL_REJECTED")
	}
	return c, nil
}

// upstreamCredential obtains the credential for one use. Nothing here touches
// the upstream; a refusal leaves no reservation and no provider call.
func (s *Service) upstreamCredential(ctx context.Context) (UpstreamCredential, error) {
	c, e := s.source.Credential(ctx)
	return s.issued(c, e)
}

// renewCredential names the rejected version to the source. Only exchange
// calls it, and only after an explicit upstream 401.
func (s *Service) renewCredential(ctx context.Context, rejected string) (UpstreamCredential, error) {
	c, e := s.source.Renew(ctx, rejected)
	return s.issued(c, e)
}

// issued admits a credential from the source and registers its value with the
// tripwire, so every version issued in this process is matched from then on.
func (s *Service) issued(c UpstreamCredential, e error) (UpstreamCredential, error) {
	if e != nil || !c.valid() || !s.tripwire.add(c.Value.Reveal()) {
		return UpstreamCredential{}, fail("CREDENTIAL_UNAVAILABLE")
	}
	return c, nil
}

// authenticate is the single place an upstream credential becomes request
// headers. Both known authentication headers are cleared first, so a renewed
// credential or a different scheme never leaves a stale value behind. The
// api-key scheme keeps each dialect's own header; oauth-bearer sends
// Authorization: Bearer for every dialect, Messages included.
func authenticate(h http.Header, d Dialect, c UpstreamCredential) {
	h.Del("x-api-key")
	h.Del("Authorization")
	d.Headers(h, c.Value)
	if c.Scheme == SchemeOAuthBearer {
		h.Del("x-api-key")
		h.Set("Authorization", "Bearer "+string(c.Value.Reveal()))
	}
}
