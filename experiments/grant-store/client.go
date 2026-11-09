package grantstore

// Blossom request/hash-verification pattern adapted from
// relux-works/a2a-transport-nostr/blossom/client.go (MIT; see NOTICE).
// This client adds signed GET, reader tags, single-use nonce, bounded reads,
// strict descriptors and redirect refusal. No credentials appear in errors.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"strings"
	"time"
)

type Client struct {
	HTTP     *http.Client
	Signer   *nostr.PrivKey
	Now      func() time.Time
	MaxBytes int64
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
func (c *Client) limit() int64 {
	if c.MaxBytes > 0 && c.MaxBytes <= 64<<20 {
		return c.MaxBytes
	}
	return 1 << 20
}
func (c *Client) request(ctx context.Context, server, method, path, action, hash string, data []byte, readers []string) ([]byte, int, error) {
	u, e := serverURL(server)
	if e != nil {
		return nil, 0, errors.New("invalid server URL")
	}
	auth, e := AuthHeader(c.Signer, action, hash, u.Hostname(), readers, c.now())
	if e != nil {
		return nil, 0, e
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(u.String(), "/")+path, bytes.NewReader(data))
	if e != nil {
		return nil, 0, errors.New("invalid request")
	}
	req.Header.Set("Authorization", auth)
	if method == "PUT" {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-SHA-256", hash)
	}
	client := http.Client{Timeout: 30 * time.Second}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Do(req)
	if e != nil {
		return nil, 0, errors.New("request failed")
	}
	defer resp.Body.Close()
	limit := int64(65536)
	if action == "get" {
		limit = c.limit()
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, resp.StatusCode, errors.New("invalid response size")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("store status %d", resp.StatusCode)
	}
	return raw, resp.StatusCode, nil
}
func (c *Client) Put(ctx context.Context, server string, data []byte, readers []string) (Descriptor, error) {
	var d Descriptor
	if int64(len(data)) > c.limit() {
		return d, errors.New("blob too large")
	}
	hash := Hash(data)
	raw, status, e := c.request(ctx, server, "PUT", "/upload", "upload", hash, data, readers)
	if e != nil {
		return d, e
	}
	if (status != 200 && status != 201) || json.Unmarshal(raw, &d) != nil || d.SHA256 != hash || d.Size != int64(len(data)) || d.Type != "application/octet-stream" || d.Uploaded < 0 {
		return Descriptor{}, errors.New("invalid upload descriptor")
	}
	u, e := serverURL(server)
	if e != nil || d.URL != strings.TrimSuffix(u.String(), "/")+"/"+hash+".bin" {
		return Descriptor{}, errors.New("invalid descriptor URL")
	}
	return d, nil
}
func (c *Client) Get(ctx context.Context, server, hash string) ([]byte, error) {
	if !digest(hash) {
		return nil, errors.New("invalid hash")
	}
	raw, status, e := c.request(ctx, server, "GET", "/"+hash, "get", hash, nil, nil)
	if e != nil {
		return nil, e
	}
	if status != 200 || Hash(raw) != hash {
		return nil, errors.New("download hash mismatch")
	}
	return raw, nil
}
func (c *Client) Delete(ctx context.Context, server, hash string) error {
	if !digest(hash) {
		return errors.New("invalid hash")
	}
	_, status, e := c.request(ctx, server, "DELETE", "/"+hash, "delete", hash, nil, nil)
	if e == nil && status != 204 && status != 200 {
		return errors.New("invalid delete status")
	}
	return e
}
func (c *Client) List(ctx context.Context, server string) ([]Descriptor, error) {
	if c.Signer == nil {
		return nil, errAuth
	}
	raw, _, e := c.request(ctx, server, "GET", "/list/"+c.Signer.PubKeyHex(), "list", "", nil, nil)
	if e != nil {
		return nil, e
	}
	var list []Descriptor
	if json.Unmarshal(raw, &list) != nil || list == nil {
		return nil, errors.New("invalid list response")
	}
	return list, nil
}
