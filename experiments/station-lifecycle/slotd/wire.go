// Package slotd binds the Infra-owned demo helper's v1 r2 wire. It executes no
// OS command and carries no user/path/argv/egress or unit property in requests.
package slotd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

const MaxWire = 8192

// ProtocolSHA256 pins the reviewed input document; wire v remains1 in r2.
const ProtocolSHA256 = "9bbccabe81782cfd9a9ac869715646adfb6b0d955d14d75fd1756ddd513554d4"

type Request struct {
	V         int     `json:"v"`
	Op        string  `json:"op"`
	Slot      string  `json:"slot"`
	NotAfter  *string `json:"not_after,omitempty"`
	Bootstrap *string `json:"bootstrap,omitempty"`
}
type Response struct {
	V               int    `json:"v"`
	OK              bool   `json:"ok"`
	Slot            string `json:"slot,omitempty"`
	State           string `json:"state,omitempty"`
	Error           string `json:"error,omitempty"`
	NotAfter        string `json:"not_after,omitempty"`
	PayloadSHA256   string `json:"payload_sha256,omitempty"`
	BootstrapSHA256 string `json:"bootstrap_sha256,omitempty"`
}
type Caller interface {
	Call(context.Context, Request) (Response, error)
}
type Client struct {
	dial    func(context.Context) (net.Conn, error)
	timeout time.Duration
}

func failure(code string) error { return errors.New(code) }
func sum(b []byte) string       { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func validSlot(s string) bool {
	n, e := strconv.Atoi(s)
	return e == nil && n >= 0 && n <= 9999 && strconv.Itoa(n) == s
}
func canonical(v any) []byte { b, _ := json.Marshal(v); return b }
func ValidRequest(r Request) bool {
	if r.V != 1 || !validSlot(r.Slot) {
		return false
	}
	switch r.Op {
	case "create":
		if r.NotAfter == nil || r.Bootstrap == nil {
			return false
		}
		t, e := time.Parse(time.RFC3339, *r.NotAfter)
		if e != nil || t.Nanosecond() != 0 {
			return false
		}
		b, e := base64.StdEncoding.DecodeString(*r.Bootstrap)
		return e == nil && len(b) <= 4096 && base64.StdEncoding.EncodeToString(b) == *r.Bootstrap
	case "start", "stop", "status", "destroy":
		return r.NotAfter == nil && r.Bootstrap == nil
	default:
		return false
	}
}
func decodeResponse(raw []byte, slot string) (Response, error) {
	var r Response
	if len(raw) < 2 || len(raw) > MaxWire || raw[len(raw)-1] != '\n' {
		return r, failure("SLOTD_RESPONSE")
	}
	raw = raw[:len(raw)-1]
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || !bytes.Equal(raw, canonical(r)) || r.V != 1 || r.Slot != slot {
		return Response{}, failure("SLOTD_RESPONSE")
	}
	if r.OK {
		if r.Error != "" {
			return Response{}, failure("SLOTD_RESPONSE")
		}
		switch r.State {
		case "absent", "created", "running", "stopped", "destroyed", "failed":
		default:
			return Response{}, failure("SLOTD_RESPONSE")
		}
		if r.State == "absent" {
			if r.NotAfter != "" || r.PayloadSHA256 != "" || r.BootstrapSHA256 != "" {
				return Response{}, failure("SLOTD_RESPONSE")
			}
		} else {
			if !validBinding(r) {
				return Response{}, failure("SLOTD_BINDING")
			}
		}
	} else {
		if r.State != "" {
			return Response{}, failure("SLOTD_RESPONSE")
		}
		switch r.Error {
		case "bad_request", "forbidden_peer", "invalid_slot", "invalid_not_after", "invalid_bootstrap", "conflict", "invalid_state", "expired", "unit_active", "busy", "internal":
		default:
			return Response{}, failure("SLOTD_RESPONSE")
		}
		if r.NotAfter != "" || r.PayloadSHA256 != "" || r.BootstrapSHA256 != "" {
			if !validBinding(r) {
				return Response{}, failure("SLOTD_BINDING")
			}
		}
	}
	return r, nil
}
func validBinding(r Response) bool {
	t, e := time.Parse(time.RFC3339, r.NotAfter)
	return e == nil && t.UTC().Format(time.RFC3339) == r.NotAfter && digest(r.PayloadSHA256) && digest(r.BootstrapSHA256)
}
func (c *Client) Call(ctx context.Context, r Request) (Response, error) {
	if !ValidRequest(r) {
		return Response{}, failure("SLOTD_REQUEST")
	}
	raw := append(canonical(r), '\n')
	if len(raw) > MaxWire {
		return Response{}, failure("SLOTD_REQUEST")
	}
	timeout := c.timeout
	if timeout <= 0 || timeout > 5*time.Second {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, e := c.dial(ctx)
	if e != nil {
		return Response{}, failure("SLOTD_UNAVAILABLE")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return Response{}, failure("SLOTD_UNAVAILABLE")
	}
	// Context cancellation interrupts an already connected Unix stream as well.
	stopped := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopped()
	if _, e = io.Copy(conn, bytes.NewReader(raw)); e != nil {
		return Response{}, failure("SLOTD_UNAVAILABLE")
	}
	raw, e = io.ReadAll(io.LimitReader(conn, MaxWire+1))
	if e != nil {
		return Response{}, failure("SLOTD_UNAVAILABLE")
	}
	return decodeResponse(raw, r.Slot)
}
