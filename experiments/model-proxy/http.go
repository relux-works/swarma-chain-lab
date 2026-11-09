package modelproxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"
)

func refusal(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(canonical(struct {
		Error string `json:"error"`
	}{code}))
}
func (s *Service) audit(id string, status int, code string, u Usage) {
	if s.cfg.Audit != nil {
		s.cfg.Audit(Audit{id, code, status, u})
	}
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := ""
	reject := func(status int, code string) { refusal(w, status, code); s.audit(id, status, code, Usage{}) }
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.Fragment != "" {
		reject(400, "REQUEST")
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "slots" || parts[3] != "v1" || parts[4] != "messages" || !digest(parts[2]) {
		reject(404, "ROUTE")
		return
	}
	id = parts[2]
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
		reject(401, "AUTH")
		return
	}
	bearer := Secret(strings.TrimPrefix(headers[0], "Bearer "))
	s.mu.Lock()
	_, e := s.authorize(id, bearer)
	s.mu.Unlock()
	if e != nil {
		reject(401, "AUTH")
		return
	}
	if r.Header.Get("Content-Encoding") != "" || r.ContentLength > MaxBody {
		reject(413, "BODY")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if e != nil || len(raw) > MaxBody {
		reject(413, "BODY")
		return
	}
	p, e := s.cfg.Dialect.Parse(raw)
	if e != nil {
		reject(400, "REQUEST")
		return
	}
	call, cancel, e := s.reserve(r.Context(), id, bearer, p)
	if e != nil {
		code := e.Error()
		if code != "BUSY" && code != "MODEL" && code != "CAP" {
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
	// Poll the own clock while I/O is blocked; deadline/revoke cancellation does
	// not refund exposure, because the provider may already have accepted work.
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
	req, e := http.NewRequestWithContext(call, "POST", s.cfg.Upstream, bytes.NewReader(p.Body))
	if e != nil {
		reject(502, "UPSTREAM")
		return
	}
	s.cfg.Dialect.Headers(req.Header, s.cfg.APIKey)
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
		u, e := s.cfg.Dialect.Complete(body, p)
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
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		reject(502, "STREAM")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	decoder := s.cfg.Dialect.Stream(p)
	reader := bufio.NewReaderSize(resp.Body, MaxEvent+1)
	total := 0
	streamError := func() {
		_, _ = io.WriteString(w, "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"proxy_error\",\"message\":\"STREAM\"}}\n\n")
		s.audit(id, 502, "STREAM", Usage{})
	}
	for {
		frame, name, data, e := readFrame(reader)
		total += len(frame)
		if e != nil || total > MaxResponse || call.Err() != nil || !s.alive(id) {
			streamError()
			return
		}
		u, final, e := decoder.Event(name, data)
		if e != nil {
			streamError()
			return
		}
		if final {
			e = s.settle(id, u)
			settled = true
			if e != nil {
				streamError()
				return
			}
		}
		if _, e = w.Write(frame); e != nil {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if final {
			s.audit(id, 200, "OK", *u)
			return
		}
	}
}
func readFrame(r *bufio.Reader) ([]byte, string, []byte, error) {
	var frame, data []byte
	name := ""
	for {
		line, e := r.ReadSlice('\n')
		if e != nil || len(frame)+len(line) > MaxEvent {
			return nil, "", nil, fail("STREAM")
		}
		frame = append(frame, line...)
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			if name == "" || len(data) == 0 {
				return nil, "", nil, fail("STREAM")
			}
			return frame, name, bytes.TrimSuffix(data, []byte("\n")), nil
		}
		if bytes.HasPrefix(line, []byte(":")) {
			continue
		}
		if bytes.HasPrefix(line, []byte("event: ")) {
			if name != "" {
				return nil, "", nil, fail("STREAM")
			}
			name = string(line[7:])
			continue
		}
		if bytes.HasPrefix(line, []byte("data: ")) {
			data = append(data, line[6:]...)
			data = append(data, '\n')
			continue
		}
		return nil, "", nil, fail("STREAM")
	}
}

var _ http.Handler = (*Service)(nil)
