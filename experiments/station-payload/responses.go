package payload

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

// A Responses delivery is one stateless user string. The original client body
// never contains the service/storage settings inserted by the trusted proxy.
func (c *Client) generateResponses(ctx context.Context, text string) (string, error) {
	q := struct {
		Model  string `json:"model"`
		Input  string `json:"input"`
		Stream bool   `json:"stream"`
		Max    uint64 `json:"max_output_tokens"`
	}{Model: c.model, Input: text, Max: c.maxTokens}
	raw, _ := json.Marshal(q)
	prepared, err := (proxy.Responses{}).Parse(raw)
	if err != nil {
		return "", ErrRequest
	}
	url := c.bootstrap.ModelEndpoint + "/slots/" + c.bootstrap.BookingID + "/v1/responses"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return "", ErrRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(c.bootstrap.ModelBearer.Reveal()))
	res, err := c.http.Do(req)
	if err != nil {
		return "", ErrTransport
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Encoding") != "" {
		return "", ErrResponse
	}
	limit := int64(proxy.MaxResponse)
	if res.StatusCode != http.StatusOK {
		limit = 256
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return "", ErrResponse
	}
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == 400 && string(body) == `{"error":"PROFILE"}` {
			return "", Code("MODEL_PROFILE")
		}
		return "", refusal(res.StatusCode, body)
	}
	typ, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return "", ErrResponse
	}
	if _, err = (proxy.Responses{}).Complete(body, prepared); err != nil {
		return "", ErrResponse
	}
	var response struct {
		Output []struct{ Content []struct{ Type, Text string } }
	}
	if json.Unmarshal(body, &response) != nil {
		return "", ErrResponse
	}
	if len(response.Output) == 0 {
		return "", ErrResponse
	}
	var out strings.Builder
	for _, item := range response.Output {
		for _, part := range item.Content {
			if part.Type == "refusal" {
				return "", Code("MODEL_REFUSAL")
			}
			if out.Len()+len(part.Text) > MaxText {
				return "", ErrResponse
			}
			out.WriteString(part.Text)
		}
	}
	return out.String(), nil
}
