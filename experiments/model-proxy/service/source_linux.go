//go:build linux

package service

import (
	"context"
	"fmt"
	"sync"
)

// Source binds one protected caller mapping to a broker connection. It
// structurally implements the gateway's managed credential seam without an
// import of that gateway. It never accepts caller identity from HTTP input.
type Source struct {
	*sourceState
}

type sourceState struct {
	mu     sync.Mutex
	client *Client
	caller Caller
	lease  *Lease
	serial uint64
	closed bool
}

func (*Source) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("<broker-source>")) }

func NewSource(client *Client, caller Caller) (*Source, error) {
	if client == nil || !valid(caller.Account) || !valid(caller.Generation) || !valid(caller.LaunchID) {
		return nil, ErrInput
	}
	return &Source{sourceState: &sourceState{client: client, caller: caller}}, nil
}

func (s *Source) version() string { return fmt.Sprintf("lease-%d", s.serial) }

func (s *Source) current(ctx context.Context) (string, []byte, string, error) {
	if e := s.client.Check(ctx, s.lease); e != nil {
		return "", nil, "", sanitized(e)
	}
	s.lease.mu.Lock()
	defer s.lease.mu.Unlock()
	if !s.lease.live() || s.lease.kind != "claude-oauth-token" || s.lease.harness != "claude_code" {
		return "", nil, "", ErrInactive
	}
	return "oauth-bearer", append([]byte(nil), s.lease.value...), s.version(), nil
}

func (s *Source) CredentialValue(ctx context.Context) (string, []byte, string, error) {
	if s == nil || s.sourceState == nil || ctx == nil {
		return "", nil, "", ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", nil, "", ErrInactive
	}
	if s.lease == nil {
		op, e := OperationID()
		if e != nil {
			return "", nil, "", e
		}
		s.lease, e = s.client.Request(ctx, op, s.caller)
		if e != nil {
			return "", nil, "", sanitized(e)
		}
		s.serial++
	}
	return s.current(ctx)
}

func (s *Source) RenewValue(ctx context.Context, rejected string) (string, []byte, string, error) {
	if s == nil || s.sourceState == nil || ctx == nil {
		return "", nil, "", ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.lease == nil || rejected == "" {
		return "", nil, "", ErrInactive
	}
	if rejected == s.version() {
		op, e := OperationID()
		if e != nil {
			return "", nil, "", e
		}
		if e = s.client.Renew(ctx, op, s.lease); e != nil {
			return "", nil, "", sanitized(e)
		}
		s.serial++
	}
	return s.current(ctx)
}

// Close releases this source's lease. Closing the connection remains the
// holder's duty; a released source cannot silently reacquire authority.
func (s *Source) Close(ctx context.Context) error {
	if s == nil || s.sourceState == nil || ctx == nil {
		return ErrInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lease == nil {
		return nil
	}
	return s.client.Release(ctx, s.lease)
}
