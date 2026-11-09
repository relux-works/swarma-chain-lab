package modelproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

// Kept separate from the MP1 handler: its framing, terminal timing and profile
// are an existing wire contract. The registry and accounting are shared.
func (s *Service) serveResponses(w http.ResponseWriter, r *http.Request) {
	id := ""
	reject := func(status int, code string) { refusal(w, status, code); s.audit(id, status, code, Usage{}) }
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" {
		reject(400, "REQUEST")
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "slots" || parts[3] != "v1" || parts[4] != "responses" || !digest(parts[2]) {
		reject(404, "ROUTE")
		return
	}
	id = parts[2]
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
		reject(401, "AUTH")
		return
	}
	bearer := Secret(strings.TrimPrefix(auth[0], "Bearer "))
	s.mu.Lock()
	_, e := s.authorize(id, bearer)
	s.mu.Unlock()
	if e != nil {
		reject(401, "AUTH")
		return
	}
	if r.Header.Get("Content-Encoding") != "" || r.ContentLength > MaxResponsesBody {
		reject(413, "BODY")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, MaxResponsesBody+1))
	if e != nil || len(raw) > MaxResponsesBody {
		reject(413, "BODY")
		return
	}
	dialect := Responses{}
	p, e := dialect.Parse(raw)
	if e != nil {
		reject(400, "REQUEST")
		return
	}
	profile, ok := s.cfg.ModelProfiles[p.Model]
	if !ok || profile.Profile != OpenAIResponsesProfile {
		reject(400, "PROFILE")
		return
	}
	call, cancel, e := s.reserve(r.Context(), id, bearer, p)
	if e != nil {
		code := e.Error()
		if code != "CAP" && code != "MODEL" && code != "BUSY" {
			code = "AUTH"
		}
		reject(403, code)
		return
	}
	defer cancel()
	settled := false
	defer func() {
		if !settled {
			_ = s.settle(id, nil)
		}
	}()
	done := make(chan struct{})
	defer close(done)
	go func() {
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-call.Done():
				return
			case <-tick.C:
				if !s.alive(id) {
					cancel()
					return
				}
			}
		}
	}()
	if call.Err() != nil || !s.alive(id) {
		reject(403, "AUTH")
		return
	}
	req, e := http.NewRequestWithContext(call, "POST", profile.Upstream, bytes.NewReader(p.Body))
	if e != nil {
		reject(502, "UPSTREAM")
		return
	}
	dialect.Headers(req.Header, s.cfg.APIKey)
	if p.Stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	transport := s.cfg.Transport
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		t.DisableCompression = true
		transport = t
		defer t.CloseIdleConnections()
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("REDIRECT") }}
	resp, e := client.Do(req)
	if e != nil {
		reject(502, "UPSTREAM")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		reject(502, "UPSTREAM")
		return
	}
	if !p.Stream {
		body, e := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
		if e != nil || len(body) > MaxResponse || call.Err() != nil || !s.alive(id) {
			reject(502, "UPSTREAM")
			return
		}
		u, e := dialect.Complete(body, p)
		if e != nil {
			reject(502, "USAGE")
			return
		}
		e = s.settle(id, &u)
		settled = true
		if e != nil {
			reject(502, "USAGE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
		s.audit(id, 200, "OK", u)
		return
	}
	media, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || media != "text/event-stream" {
		reject(502, "STREAM")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	streamError := func() {
		_, _ = io.WriteString(w, "event: error\ndata: {\"type\":\"error\",\"code\":\"proxy_stream\"}\n\n")
		s.audit(id, 502, "STREAM", Usage{})
	}
	reader := bufio.NewReaderSize(resp.Body, MaxResponsesEvent+1)
	decoder := dialect.Stream(p)
	total := 0
	var terminal []byte
	var usage *Usage
	for {
		frame, name, data, err := readResponsesFrame(reader)
		if err == io.EOF && terminal != nil && call.Err() == nil && s.alive(id) {
			e = s.settle(id, usage)
			settled = true
			if e != nil {
				streamError()
				return
			}
			_, _ = w.Write(terminal)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			s.audit(id, 200, "OK", *usage)
			return
		}
		total += len(frame)
		if err != nil || terminal != nil || total > MaxResponse || call.Err() != nil || !s.alive(id) {
			streamError()
			return
		}
		u, final, e := decoder.Event(name, data)
		if e != nil {
			streamError()
			return
		}
		if final {
			// Detect a reported overrun before waiting for EOF; settlement freezes
			// the slot and leaves its original worst-case reservation charged.
			if !s.responsesUsageWithin(id, *u) {
				_ = s.settle(id, u)
				settled = true
				streamError()
				return
			}
			terminal, usage = frame, u
			continue
		}
		if _, e = w.Write(frame); e != nil {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (s *Service) responsesUsageWithin(id string, u Usage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.state.Records[id].Pending
	if p == nil {
		return false
	}
	cost, ok := price(s.cfg.Models[p.Model], u)
	return ok && u.Input <= p.Usage.Input && u.Output <= p.Usage.Output && cost <= p.Cost
}

func readResponsesFrame(r *bufio.Reader) ([]byte, string, []byte, error) {
	var frame, data []byte
	name := ""
	for {
		line, e := r.ReadSlice('\n')
		if e == io.EOF && len(line) == 0 && len(frame) == 0 {
			return nil, "", nil, io.EOF
		}
		if e != nil || len(frame)+len(line) > MaxResponsesEvent {
			return nil, "", nil, fail("STREAM")
		}
		frame = append(frame, line...)
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		if len(line) == 0 {
			if len(data) == 0 {
				return nil, "", nil, fail("STREAM")
			}
			data = bytes.TrimSuffix(data, []byte("\n"))
			if name == "" {
				var m map[string]json.RawMessage
				if json.Unmarshal(data, &m) != nil {
					return nil, "", nil, fail("STREAM")
				}
				name, _ = str(m["type"])
			}
			return frame, name, data, nil
		}
		if bytes.HasPrefix(line, []byte(":")) {
			continue
		}
		key, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			return nil, "", nil, fail("STREAM")
		}
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(key) {
		case "event":
			if name != "" {
				return nil, "", nil, fail("STREAM")
			}
			name = string(value)
		case "data":
			data = append(data, value...)
			data = append(data, '\n')
		default:
			return nil, "", nil, fail("STREAM")
		}
	}
}
