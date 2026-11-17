//go:build linux

// Package service is the gateway's inactive broker/1 service client. Its
// credential handles stay within the trusted gateway process.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

const LeaseCeiling = 900 * time.Second

// Code is a closed diagnostic; remote messages/details and OS errors never escape.
type Code string

func (c Code) Error() string { return string(c) }

const (
	ErrTransport   Code = "broker_unavailable"
	ErrFrame       Code = "broker_frame_invalid"
	ErrIdentity    Code = "server_identity_mismatch"
	ErrRole        Code = "role_not_permitted"
	ErrInactive    Code = "lease_not_active"
	ErrRevoked     Code = "lease_revoked"
	ErrUnavailable Code = "revocation_state_unavailable"
	ErrInput       Code = "request_malformed"
	ErrUnknown     Code = "operation_outcome_unknown"
)

// Caller comes from protected launch evidence, never an HTTP header.
type Caller struct {
	Account    string `json:"account"`
	UID        uint32 `json:"agent_uid"`
	Generation string `json:"agent_generation"`
	LaunchID   string `json:"launch_id"`
}

type Config struct {
	Socket     string
	BrokerUID  uint32
	ServiceUID uint32
	Generation string
	// MaxLifetime may shorten the ceiling; a larger value is refused, not clamped.
	MaxLifetime time.Duration
}

type helloResult struct {
	Version   int `json:"version"`
	Principal struct {
		Name       string `json:"service_name"`
		UID        uint32 `json:"uid"`
		Generation string `json:"service_generation"`
	} `json:"principal"`
}

type Client struct {
	cfg     Config
	gate    chan struct{}
	conn    *net.UnixConn
	mu      sync.Mutex
	leases  map[*Lease]bool
	blocked map[string]bool
	epoch   uint64
	failed  bool
}

func (*Client) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("<broker-client>")) }

// Lease exposes metadata only. It cannot be JSON-encoded or formatted as material.
// Go's allocator may retain immutable decoder copies; this is not secure erasure.
type Lease struct {
	*leaseState
}

// The unexported indirection also protects formatting/JSON of a copied Lease
// value, where pointer-receiver redaction methods would not be selected.
type leaseState struct {
	mu                sync.Mutex
	owner             *Client
	caller            Caller
	id, kind, harness string
	until             time.Time
	localUntil        time.Time
	tokenExpiry       *time.Time
	value             []byte
	closed            bool
}

func (*Lease) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("<service-lease>")) }
func (*Lease) MarshalJSON() ([]byte, error)  { return []byte(`"<service-lease>"`), nil }
func (l *Lease) close() {
	if l == nil || l.leaseState == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.value)
	l.value = nil
	l.closed = true
}
func (l *Lease) live() bool {
	now := time.Now()
	return !l.closed && now.Before(l.until) && now.Before(l.localUntil) && (l.tokenExpiry == nil || now.Before(*l.tokenExpiry))
}
func (l *Lease) AuthorizedUntil() time.Time {
	if l == nil || l.leaseState == nil {
		return time.Time{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.until
}
func (l *Lease) Kind() string {
	if l == nil || l.leaseState == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.kind
}

func OperationID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(b[:]), nil
}
func valid(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// Matches internal/service/broker.go validCaller at the pinned broker revision.
// Account labels are wire identifiers, including slash, rather than path parts.
func validCaller(c Caller) bool {
	return wire.ASCII(c.Account, 128) && wire.ASCII(c.Generation, 128) && wire.ASCII(c.LaunchID, 128)
}

// Dial checks SO_PEERCRED before even sending hello. net's Unix descriptors are
// close-on-exec; this package neither starts children nor passes descriptors.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if ctx == nil || cfg.ServiceUID != uint32(os.Geteuid()) || !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || !wire.ASCII(cfg.Generation, 128) || cfg.MaxLifetime <= 0 || cfg.MaxLifetime > LeaseCeiling {
		return nil, ErrInput
	}
	raw, e := (&net.Dialer{}).DialContext(ctx, "unix", cfg.Socket)
	if e != nil {
		return nil, ErrTransport
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		raw.Close()
		return nil, ErrTransport
	}
	uid, e := peerUID(conn)
	if e != nil || uid != cfg.BrokerUID {
		conn.Close()
		return nil, ErrIdentity
	}
	c := &Client{cfg: cfg, conn: conn, gate: make(chan struct{}, 1), leases: make(map[*Lease]bool), blocked: make(map[string]bool)}
	c.gate <- struct{}{}
	var h helloResult
	if e = c.call(ctx, "hello", map[string]any{"versions": []int{1}}, &h); e != nil {
		c.Close()
		return nil, e
	}
	if h.Version != 1 || h.Principal.Name != "credential-gateway" || h.Principal.UID != cfg.ServiceUID || h.Principal.Generation != cfg.Generation {
		c.Close()
		return nil, ErrRole
	}
	return c, nil
}
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return 0, ErrIdentity
	}
	var cred *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil || inner != nil || cred == nil {
		return 0, ErrIdentity
	}
	return cred.Uid, nil
}
func (c *Client) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	for l := range c.leases {
		l.close()
	}
}
func (c *Client) Close() error {
	c.mu.Lock()
	c.failed = true
	c.mu.Unlock()
	c.invalidate()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	return nil
}
func refusal(code string) error {
	switch code {
	case "role_not_permitted", "lease_not_owner", "lease_not_active", "service_binding_unknown", "service_binding_mismatch", "principal_ledger_mismatch", "account_hold_active", "account_hold_unknown", "hold_reason_unknown", "service_operation_conflict", "lease_unbound", "lease_grant_revoked", "lease_caller_revoked", "lease_not_authorised", "lease_account_unknown", "lease_harness_mismatch", "lease_account_revoked", "lease_reauth_required", "lease_owner_unavailable", "revocation_state_unavailable", "request_malformed", "request_deadline_exceeded", "renew_timeout":
		return Code(code)
	}
	return ErrUnavailable
}

// Interface implementations cannot turn an opaque error into an outward
// material channel. Only this module's closed codes cross the seam.
func sanitized(err error) error {
	code, ok := err.(Code)
	if !ok {
		return ErrUnavailable
	}
	switch code {
	case ErrTransport, ErrFrame, ErrIdentity, ErrRole, ErrInactive, ErrRevoked, ErrUnavailable, ErrInput, ErrUnknown:
		return code
	default:
		return refusal(string(code))
	}
}

func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	if ctx == nil {
		return ErrInput
	}
	budget := 2 * time.Second
	switch method {
	case "service.lease.request":
		budget = 30 * time.Second
	case "service.lease.renew":
		budget = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	select {
	case <-ctx.Done():
		return ErrTransport
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()
	deadline, _ := ctx.Deadline()
	if c.conn.SetDeadline(deadline) != nil {
		_ = c.Close()
		return ErrTransport
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Now()); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	id, e := OperationID()
	if e != nil {
		return e
	}
	raw, e := wire.Encode(params)
	if e != nil {
		return ErrInput
	}
	defer clear(raw)
	e = wire.Write(c.conn, map[string]any{"method": method, "params": json.RawMessage(raw), "request_id": id})
	if e != nil {
		_ = c.Close()
		return ErrUnknown
	}
	frame, e := wire.Read(c.conn)
	if e != nil {
		_ = c.Close()
		return ErrUnknown
	}
	defer clear(frame)
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		_ = c.Close()
		return ErrUnknown
	}
	var envelope map[string]json.RawMessage
	defer func() { clear(envelope["result"]) }()
	if json.Unmarshal(frame, &envelope) != nil || len(envelope) != 2 {
		return c.badFrame()
	}
	var got string
	if json.Unmarshal(envelope["request_id"], &got) != nil || got != id {
		return c.badFrame()
	}
	if raw, ok := envelope["error"]; ok {
		var r struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		}
		if wire.Decode(raw, &r) != nil {
			return c.badFrame()
		}
		err := refusal(r.Code)
		// Ordinary method refusals have no connection-wide effect. Only loss
		// of this principal's authority or revocation availability closes it.
		if err == ErrRole || err == Code("principal_ledger_mismatch") || err == ErrUnavailable {
			_ = c.Close()
		}
		return err
	}
	raw, ok := envelope["result"]
	if !ok || wire.Decode(raw, out) != nil {
		return c.badFrame()
	}
	return nil
}
func (c *Client) badFrame() error { _ = c.Close(); return ErrFrame }

type leaseResult struct {
	ID      string `json:"service_lease_id"`
	Account string `json:"account"`
	Harness string `json:"harness"`
	Kind    string `json:"kind"`
	Payload struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"payload"`
	TokenExpiry *time.Time `json:"token_expires_at"`
	Until       string     `json:"authorized_until"`
	Renewable   bool       `json:"renewable"`
}

func (c *Client) accept(r *leaseResult, caller Caller, started time.Time, epoch uint64) (*Lease, error) {
	defer func() { r.Payload.Value = "" }()
	until, e := time.Parse(time.RFC3339Nano, r.Until)
	// Reject replies above the ceiling at receipt, then conservatively shorten
	// local use to the request-start ceiling. No network delay widens local use.
	if e != nil || !time.Now().Before(until) || until.After(time.Now().Add(c.cfg.MaxLifetime)) || !wire.ASCII(r.ID, 128) || r.Account != caller.Account || r.Kind != "claude-oauth-token" || r.Harness != "claude_code" || r.Kind != r.Payload.Kind || r.Payload.Value == "" || !r.Renewable || (r.TokenExpiry != nil && (!time.Now().Before(*r.TokenExpiry) || until.After(*r.TokenExpiry))) {
		return nil, ErrInactive
	}
	if bound := started.Add(c.cfg.MaxLifetime); until.After(bound) {
		until = bound
	}
	// Retain a monotonic local deadline as well as the broker's wall timestamp:
	// a later wall-clock correction cannot extend already accepted local use.
	now := time.Now()
	l := &Lease{leaseState: &leaseState{owner: c, caller: caller, id: r.ID, kind: r.Kind, harness: r.Harness, until: until, localUntil: now.Add(until.Sub(now)), tokenExpiry: r.TokenExpiry, value: []byte(r.Payload.Value)}}
	if !l.live() {
		l.close()
		return nil, ErrInactive
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || c.epoch != epoch || c.blocked[caller.Account] {
		l.close()
		return nil, ErrInactive
	}
	c.leases[l] = true
	return l, nil
}
func (c *Client) Request(ctx context.Context, op string, caller Caller) (*Lease, error) {
	if !wire.ASCII(op, 128) || !validCaller(caller) {
		return nil, ErrInput
	}
	c.mu.Lock()
	epoch := c.epoch
	blocked := c.failed || c.blocked[caller.Account]
	c.mu.Unlock()
	if blocked {
		return nil, ErrInactive
	}
	started := time.Now()
	var r leaseResult
	p := struct {
		Operation  string `json:"operation_id"`
		Account    string `json:"account"`
		UID        uint32 `json:"agent_uid"`
		Generation string `json:"agent_generation"`
		Launch     string `json:"launch_id"`
	}{op, caller.Account, caller.UID, caller.Generation, caller.LaunchID}
	if e := c.call(ctx, "service.lease.request", p, &r); e != nil {
		if holdRefusal(e) {
			c.blockAccount(caller.Account)
		}
		return nil, e
	}
	return c.accept(&r, caller, started, epoch)
}
func (c *Client) Renew(ctx context.Context, op string, l *Lease) error {
	if l == nil || !c.owns(l) || !wire.ASCII(op, 128) {
		return ErrInput
	}
	l.mu.Lock()
	live := l.live()
	id, caller, kind, harness := l.id, l.caller, l.kind, l.harness
	l.mu.Unlock()
	if !live {
		l.close()
		return ErrInactive
	}
	c.mu.Lock()
	epoch := c.epoch
	c.mu.Unlock()
	started := time.Now()
	var r leaseResult
	if e := c.call(ctx, "service.lease.renew", map[string]any{"operation_id": op, "service_lease_id": id}, &r); e != nil {
		l.close()
		if holdRefusal(e) {
			c.blockAccount(caller.Account)
		}
		return e
	}
	next, e := c.accept(&r, caller, started, epoch)
	if e != nil {
		l.close()
		return e
	}
	defer func() { next.close(); c.mu.Lock(); delete(c.leases, next); c.mu.Unlock() }()
	if next.id != id || next.kind != kind || next.harness != harness {
		l.close()
		return ErrFrame
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || c.epoch != epoch || c.blocked[caller.Account] {
		l.close()
		return ErrInactive
	}
	next.mu.Lock()
	value := append([]byte(nil), next.value...)
	next.mu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		clear(value)
		return ErrInactive
	}
	clear(l.value)
	l.value = value
	l.until = next.until
	l.localUntil = next.localUntil
	l.tokenExpiry = next.tokenExpiry
	return nil
}
func (c *Client) Check(ctx context.Context, l *Lease) error {
	if l == nil || !c.owns(l) {
		return ErrInput
	}
	l.mu.Lock()
	live, id := l.live(), l.id
	l.mu.Unlock()
	if !live {
		l.close()
		return ErrInactive
	}
	var r struct {
		Verdict  string          `json:"verdict"`
		Sequence json.RawMessage `json:"revocation_sequence"`
	}
	if e := c.call(ctx, "service.revocation.check", map[string]any{"service_lease_id": id}, &r); e != nil {
		l.close()
		return e
	}
	switch r.Verdict {
	case "not_revoked":
		l.mu.Lock()
		live = l.live()
		l.mu.Unlock()
		if live {
			return nil
		}
		l.close()
		return ErrInactive
	case "revoked":
		l.close()
		return ErrRevoked
	default:
		l.close()
		return ErrUnavailable
	}
}

// Poll stops on any lost authority. A later not_revoked result never reopens l.
// It does not claim the inherited system-wide revocation propagation bound.
func (c *Client) Poll(ctx context.Context, l *Lease, interval time.Duration) error {
	if interval <= 0 {
		return ErrInput
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if e := c.Check(ctx, l); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			l.close()
			return ErrInactive
		case <-tick.C:
		}
	}
}

// owns permits nonmaterial hold reconciliation on a fresh connection only for
// the identical kernel service generation and broker endpoint. Closed handles
// retain no material and cannot be renewed into activity.
func (c *Client) owns(l *Lease) bool {
	return l != nil && l.leaseState != nil && l.owner != nil && l.owner.cfg.Socket == c.cfg.Socket && l.owner.cfg.BrokerUID == c.cfg.BrokerUID && l.owner.cfg.ServiceUID == c.cfg.ServiceUID && l.owner.cfg.Generation == c.cfg.Generation
}

func holdRefusal(err error) bool {
	return err == Code("account_hold_active") || err == Code("account_hold_unknown")
}

func (c *Client) blockAccount(account string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blocked[account] = true
	for l := range c.leases {
		if l.caller.Account == account {
			l.close()
		}
	}
}

func (c *Client) Hold(ctx context.Context, op string, l *Lease) error {
	if l == nil || !c.owns(l) || !wire.ASCII(op, 128) {
		return ErrInput
	}
	c.blockAccount(l.caller.Account)
	l.close()
	var r struct {
		ID      string    `json:"hold_id"`
		Account string    `json:"account"`
		Reason  string    `json:"reason_code"`
		State   string    `json:"state"`
		At      time.Time `json:"placed_at"`
	}
	if e := c.call(ctx, "account.hold", map[string]any{"operation_id": op, "service_lease_id": l.id, "account": l.caller.Account, "reason_code": "leak_match"}, &r); e != nil {
		return ErrUnknown
	}
	if !wire.ASCII(r.ID, 128) || r.Account != l.caller.Account || r.Reason != "leak_match" || r.State != "active" || r.At.IsZero() {
		return ErrUnknown
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for other := range c.leases {
		if other.caller.Account == l.caller.Account {
			other.close()
		}
	}
	return nil
}
func (c *Client) Release(ctx context.Context, l *Lease) error {
	if l == nil || !c.owns(l) {
		return ErrInput
	}
	l.close()
	var r struct {
		ID    string `json:"service_lease_id"`
		State string `json:"state"`
	}
	if e := c.call(ctx, "service.lease.release", map[string]any{"service_lease_id": l.id}, &r); e != nil {
		return e
	}
	if r.ID != l.id || r.State != "released" {
		return ErrFrame
	}
	return nil
}
