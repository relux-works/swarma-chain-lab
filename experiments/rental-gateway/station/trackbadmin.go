package station

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"io"
	"net"
	"net/http"
	"time"
)

// TrackBAdminClient speaks the M4a Track B driver admin contract
// over its private Unix socket: POST /mint {"slot":"<64 lower hex
// booking id>"} -> {"token":"<64 lower hex>","status":"ok"};
// POST /revoke same slot, idempotent. The raw token is returned
// once by Mint and never logged here.
type TrackBAdminClient struct {
	SocketPath string
}

func (c *TrackBAdminClient) httpClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", c.SocketPath)
			},
		},
	}
}

func (c *TrackBAdminClient) post(ctx context.Context, path, bookingID string, out *trackBMintReply) error {
	body, _ := json.Marshal(map[string]string{"slot": bookingID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://trackb"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trackb admin %s: status %d", path, resp.StatusCode)
	}
	if out != nil {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
		if err != nil || len(raw) > 4096 || decodeTrackBMintReply(raw, out) != nil {
			return fmt.Errorf("trackb admin: invalid reply")
		}
		return nil
	}
	return nil
}

// Mint implements TokenAdmin.
func (c *TrackBAdminClient) Mint(ctx context.Context, bookingID string) (TrackBToken, error) {
	var out trackBMintReply
	if err := c.post(ctx, "/mint", bookingID, &out); err != nil {
		return TrackBToken{}, err
	}
	if out.Status != "ok" || len(out.Token.Reveal()) != 64 {
		return TrackBToken{}, fmt.Errorf("trackb admin mint: malformed reply")
	}
	return out.Token, nil
}

// Decode the private admin reply directly into opaque storage. Generic output
// of this carrier is redacted; only the dedicated private server encoder emits it.
type trackBMintReply struct {
	Token  TrackBToken `json:"token"`
	Status string      `json:"status"`
}

func decodeTrackBMintReply(raw []byte, out *trackBMintReply) error {
	*out = trackBMintReply{}
	// The existing strict schema is checked against its original private DTO;
	// StrictInput deliberately does not trust arbitrary custom unmarshallers.
	var wire struct {
		Token  string `json:"token"`
		Status string `json:"status"`
	}
	if err := su.StrictInput(raw, &wire); err != nil {
		return err
	}
	*out = trackBMintReply{Token: NewTrackBToken(wire.Token), Status: wire.Status}
	return nil
}

// Revoke implements TokenAdmin (idempotent at the endpoint).
func (c *TrackBAdminClient) Revoke(ctx context.Context, bookingID string) error {
	return c.post(ctx, "/revoke", bookingID, nil)
}
