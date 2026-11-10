// Package stationlink is the station-initiated channel protocol
// between a station (agent host) and the gateway. Stations initiate
// every connection (separate VM; the gateway never dials in): they
// pull deliveries and push replies over one long-lived connection.
// Frames are length-prefixed JSON over any net.Conn: a unix socket
// in local tests, TCP+mTLS in deployment. The agent Nostr key never
// crosses this channel; the gateway signs all outbound DMs itself.
package stationlink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"io"
	"net"
)

// ChannelSecretBytes is the per-slot channel credential length.
const ChannelSecretBytes = 32

// ComputeResponse returns hex(HMAC-SHA256(secret,
// nonceBytes || slotID || stationName)) for a challenge nonce (hex).
func ComputeResponse(secret []byte, nonceHex, slotID, stationName string) (string, error) {
	if len(secret) != ChannelSecretBytes {
		return "", fmt.Errorf("stationlink: secret want %d bytes", ChannelSecretBytes)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 32 {
		return "", fmt.Errorf("stationlink: nonce want 64 hex")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	mac.Write([]byte(slotID))
	mac.Write([]byte(stationName))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyResponse compares a response in constant time.
func VerifyResponse(secret []byte, nonceHex, slotID, stationName, responseHex string) bool {
	want, err := ComputeResponse(secret, nonceHex, slotID, stationName)
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(responseHex)
	if err != nil {
		return false
	}
	wantBytes, _ := hex.DecodeString(want)
	return hmac.Equal(got, wantBytes)
}

// Message types. Station -> gateway requests each get exactly one
// gateway response frame.
const (
	TypeHello    = "hello"     // station -> gateway: request auth challenge for a slot
	TypeAuth     = "auth"      // station -> gateway: HMAC response to the challenge
	TypePull     = "pull"      // station -> gateway: next delivery please
	TypeReceived = "received"  // station -> gateway: input durably recorded
	TypeReply    = "reply"     // station -> gateway: agent reply content
	TypeEndEarly = "end_early" // station -> gateway: agent asks to end
	TypeExtend   = "extend"    // station -> gateway: always refused

	TypeChallenge = "challenge" // gateway -> station: hello answer carrying the nonce
	TypeSystem    = "system"    // gateway -> station: auth response (session info)
	TypeDeliver   = "deliver"   // gateway -> station: pull response with a message
	TypeNotice    = "notice"    // gateway -> station: screening refusal notice
	TypeNone      = "none"      // gateway -> station: pull timed out, nothing queued
	TypeAck       = "ack"       // gateway -> station: reply accepted
	TypeEnd       = "end"       // gateway -> station: slot over
	TypeError     = "error"     // gateway -> station: request refused
)

// Frame is one protocol message. Only fields relevant to Type are set.
type Frame struct {
	RelayMaxEventBytes int    `json:"relay_max_event_bytes,omitempty"`
	Type               string `json:"type"`
	SlotID             string `json:"slot_id,omitempty"`
	StationName        string `json:"station_name,omitempty"`
	RenterPubKey       string `json:"renter_pubkey,omitempty"`
	ContractSHA256     string `json:"contract_sha256,omitempty"`
	NotAfter           int64  `json:"not_after,omitempty"`
	DeliveryID         string `json:"delivery_id,omitempty"`
	Content            string `json:"content,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Nonce              string `json:"nonce,omitempty"`    // challenge: 64 lower hex (32 bytes)
	Response           string `json:"response,omitempty"` // auth: 64 lower hex HMAC-SHA256
}

// MaxFrameBytes bounds one frame (DM rumor content is <= 64 KiB by
// NIP-44; 1 MiB leaves room without allowing memory abuse).
const MaxFrameBytes = 1 << 20

// WriteFrame writes one length-prefixed JSON frame.
func WriteFrame(w io.Writer, f *Frame) error {
	body, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(body) > MaxFrameBytes {
		return fmt.Errorf("stationlink: frame too large (%d)", len(body))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadFrame reads one frame; oversized or malformed frames are errors.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameBytes {
		return nil, fmt.Errorf("stationlink: frame length %d invalid", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var f Frame
	if err := su.StrictInput(body, &f); err != nil {
		return nil, fmt.Errorf("stationlink: frame json: %w", err)
	}
	if f.Type == "" {
		return nil, fmt.Errorf("stationlink: frame without type")
	}
	return &f, nil
}

// Client is the station side of the protocol over one connection.
type Client struct {
	conn net.Conn
}

// NewClient wraps a station-initiated connection (unix or TCP+mTLS).
func NewClient(conn net.Conn) *Client { return &Client{conn: conn} }

// Hello authenticates and binds the connection to a slot:
// hello -> challenge(nonce) -> auth(HMAC response) -> system frame
// (renter key, contract hash, end time) or a refusal frame. The
// secret itself never crosses the wire.
func (c *Client) Hello(slotID, stationName string, secret []byte) (*Frame, error) {
	ch, err := c.roundTrip(&Frame{Type: TypeHello, SlotID: slotID, StationName: stationName})
	if err != nil {
		return nil, err
	}
	if ch.Type != TypeChallenge {
		return ch, nil // refusal/end frame: caller inspects Type
	}
	resp, err := ComputeResponse(secret, ch.Nonce, slotID, stationName)
	if err != nil {
		return nil, err
	}
	return c.roundTrip(&Frame{Type: TypeAuth, SlotID: slotID, StationName: stationName, Response: resp})
}

// Pull asks for the next queued delivery/notice/end (long-poll).
func (c *Client) Pull() (*Frame, error) {
	return c.roundTrip(&Frame{Type: TypePull})
}

// Received acknowledges only a durably recorded input.
func (c *Client) Received(deliveryID string) (*Frame, error) {
	return c.roundTrip(&Frame{Type: TypeReceived, DeliveryID: deliveryID})
}

// Reply binds one immutable agent reply to its durable input.
func (c *Client) Reply(deliveryID, content string) (*Frame, error) {
	return c.roundTrip(&Frame{Type: TypeReply, DeliveryID: deliveryID, Content: content})
}

// EndEarly asks the gateway to end the slot now.
func (c *Client) EndEarly() (*Frame, error) {
	return c.roundTrip(&Frame{Type: TypeEndEarly})
}

// Extend attempts to extend the slot (the gateway must always refuse).
func (c *Client) Extend() (*Frame, error) {
	return c.roundTrip(&Frame{Type: TypeExtend})
}

func (c *Client) roundTrip(req *Frame) (*Frame, error) {
	if err := WriteFrame(c.conn, req); err != nil {
		return nil, err
	}
	return ReadFrame(c.conn)
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }
