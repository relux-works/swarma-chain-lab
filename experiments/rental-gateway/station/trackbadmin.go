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

func (c *TrackBAdminClient) post(ctx context.Context, path, bookingID string, out any) error {
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
		if err != nil || len(raw) > 4096 || su.StrictInput(raw, out) != nil {
			return fmt.Errorf("trackb admin: invalid reply")
		}
		return nil
	}
	return nil
}

// Mint implements TokenAdmin.
func (c *TrackBAdminClient) Mint(ctx context.Context, bookingID string) (string, error) {
	var out struct {
		Token  string `json:"token"`
		Status string `json:"status"`
	}
	if err := c.post(ctx, "/mint", bookingID, &out); err != nil {
		return "", err
	}
	if out.Status != "ok" || len(out.Token) != 64 {
		return "", fmt.Errorf("trackb admin mint: malformed reply")
	}
	return out.Token, nil
}

// Revoke implements TokenAdmin (idempotent at the endpoint).
func (c *TrackBAdminClient) Revoke(ctx context.Context, bookingID string) error {
	return c.post(ctx, "/revoke", bookingID, nil)
}
