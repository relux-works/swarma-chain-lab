//go:build linux && gateway_lab

package service

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type labAttemptUsage struct {
	source                           io.Reader
	attempt                          *labAttempt
	line, event, data                []byte
	started, delta, stopped, invalid bool
	usage                            map[string]any
	requestID                        string
}

func newLabAttemptUsage(body io.Reader, response *http.Response, attempt *labAttempt) *labAttemptUsage {
	usage := &labAttemptUsage{source: body, attempt: attempt, requestID: response.Header.Get("Request-Id")}
	if response.StatusCode != 200 || len(response.Header.Values("Request-Id")) != 1 || labValue(usage.requestID, "id") != nil || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		usage.invalid = true
	}
	return usage
}
func (usage *labAttemptUsage) Read(buffer []byte) (int, error) {
	count, err := usage.source.Read(buffer)
	for _, value := range buffer[:count] {
		if len(usage.line) > 262144 || len(usage.data) > 262144 {
			usage.invalid = true
			usage.attempt.cancel()
			return 0, ErrUnknown
		}
		if value == '\n' {
			line := bytes.TrimSuffix(usage.line, []byte{'\r'})
			if len(line) == 0 {
				usage.consume()
				clear(usage.data)
				usage.data = nil
				usage.event = nil
			} else if bytes.HasPrefix(line, []byte("event:")) {
				usage.event = append(usage.event, bytes.TrimSpace(line[6:])...)
			} else if bytes.HasPrefix(line, []byte("data:")) {
				if len(usage.data) > 0 {
					usage.data = append(usage.data, '\n')
				}
				usage.data = append(usage.data, bytes.TrimPrefix(line[5:], []byte{' '})...)
			} else if line[0] != ':' {
				usage.invalid = true
			}
			clear(usage.line)
			usage.line = nil
		} else {
			usage.line = append(usage.line, value)
		}
	}
	if usage.attempt.ctx.Err() != nil {
		return count, ErrUnknown
	}
	if err == io.EOF && (len(usage.line) != 0 || len(usage.data) != 0 || !usage.stopped) {
		usage.invalid = true
	}
	return count, err
}
func (usage *labAttemptUsage) consume() {
	if len(usage.data) == 0 {
		return
	}
	value, err := labJSON(usage.data)
	object, objectOK := value.(map[string]any)
	if err != nil || !objectOK {
		usage.invalid = true
		return
	}
	kind, ok := object["type"].(string)
	if !ok || string(usage.event) != kind || usage.stopped {
		usage.invalid = true
		return
	}
	switch kind {
	case "ping":
	case "message_start":
		message, ok := object["message"].(map[string]any)
		if !ok || usage.started || message["model"] != "claude-opus-5-5" {
			usage.invalid = true
			return
		}
		counters, ok := message["usage"].(map[string]any)
		if !ok {
			usage.invalid = true
			return
		}
		tier := message["service_tier"]
		flat := counters
		if cache, exists := counters["cache_creation"]; exists {
			parts, ok := cache.(map[string]any)
			if !ok || len(parts) != 2 || len(counters) != 6 || counters["service_tier"] != "standard" || tier != nil && tier != "standard" {
				usage.invalid = true
				return
			}
			flat = map[string]any{"input_tokens": counters["input_tokens"], "output_tokens": counters["output_tokens"], "cache_creation_input_tokens": counters["cache_creation_input_tokens"], "cache_read_input_tokens": counters["cache_read_input_tokens"], "cache_creation_5m_input_tokens": parts["ephemeral_5m_input_tokens"], "cache_creation_1h_input_tokens": parts["ephemeral_1h_input_tokens"]}
		} else if tier != "standard" || len(counters) != 6 {
			usage.invalid = true
			return
		}
		projected := map[string]any{}
		for name := range labUsageZero() {
			value, ok := labUsageInteger(flat[name])
			if !ok {
				usage.invalid = true
				return
			}
			projected[name] = value
		}
		if _, err := labPriceCharge(usage.attempt.gate.admission.price, projected); err != nil {
			usage.invalid = true
			return
		}
		usage.usage = projected
		usage.started = true
	case "message_delta":
		if !usage.started {
			usage.invalid = true
			return
		}
		counters, ok := object["usage"].(map[string]any)
		if !ok || len(counters) != 1 {
			usage.invalid = true
			return
		}
		output, ok := labUsageInteger(counters["output_tokens"])
		if !ok || output < usage.usage["output_tokens"].(int64) || output > usage.attempt.gate.admission.plan["max_output_tokens_per_invocation"].(int64) {
			usage.invalid = true
			usage.attempt.cancel()
			return
		}
		usage.usage["output_tokens"] = output
		usage.delta = true
		if output == usage.attempt.gate.admission.plan["max_output_tokens_per_invocation"] {
			usage.invalid = true
			usage.attempt.cancel()
		}
	case "message_stop":
		if !usage.started || !usage.delta {
			usage.invalid = true
			return
		}
		usage.stopped = true
	case "content_block_start", "content_block_delta", "content_block_stop":
		if !usage.started {
			usage.invalid = true
		}
	default:
		usage.invalid = true
	}
}
func labUsageInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	text := number.String()
	var parsed int64
	if text == "0" {
		return 0, true
	}
	if len(text) == 0 || text[0] < '1' || text[0] > '9' {
		return 0, false
	}
	for _, digit := range text {
		if digit < '0' || digit > '9' {
			return 0, false
		}
		if parsed > (labSafeInteger-int64(digit-'0'))/10 {
			return 0, false
		}
		parsed = parsed*10 + int64(digit-'0')
	}
	return parsed, true
}
func (usage *labAttemptUsage) finish(clean bool) error {
	defer clear(usage.line)
	defer clear(usage.data)
	return usage.attempt.finish(usage.usage, usage.requestID, clean && !usage.invalid && usage.started && usage.delta && usage.stopped)
}
