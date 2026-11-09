package grantstore

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func serverURL(value string) (*url.URL, error) {
	u, e := url.Parse(value)
	if e != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errAuth
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errAuth
		}
	}
	u.Host = strings.ToLower(u.Host)
	return u, nil
}
func blobPath(path string) string {
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	v := strings.TrimPrefix(path, "/")
	if len(v) < 64 || !digest(v[:64]) {
		return ""
	}
	if len(v) > 64 {
		if v[64] != '.' || len(v) > 81 || len(v) == 65 {
			return ""
		}
		for _, c := range v[65:] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return ""
			}
		}
	}
	return v[:64]
}
func deny(w http.ResponseWriter, r *http.Request, status int) {
	msg := "request refused"
	if status == 401 {
		msg = "authorization required"
	}
	if status == 403 {
		msg = "access denied"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Reason", msg)
	w.WriteHeader(status)
	if r.Method != "HEAD" {
		_, _ = io.WriteString(w, msg+"\n")
	}
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, *")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, DELETE")
		w.WriteHeader(204)
		return
	}
	// Serialize authorization reservations and bounded effects with ownership
	// checks so concurrent puts cannot replace the winner's ACL or putter.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		deny(w, r, 503)
		return
	}
	action, hash := "", ""
	var data []byte
	switch {
	case r.URL.Path == "/upload" && r.Method == "PUT":
		action = "upload"
		if r.ContentLength > s.cfg.MaxBlobBytes {
			deny(w, r, 413)
			return
		}
		var e error
		data, e = io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBlobBytes+1))
		if e != nil {
			deny(w, r, 400)
			return
		}
		if int64(len(data)) > s.cfg.MaxBlobBytes {
			deny(w, r, 413)
			return
		}
		hash = Hash(data)
		if got := r.Header.Get("X-SHA-256"); got != "" && got != hash {
			deny(w, r, 409)
			return
		}
	case strings.HasPrefix(r.URL.Path, "/list/") && r.Method == "GET":
		action = "list"
	case r.Method == "GET" || r.Method == "HEAD":
		action = "get"
		hash = blobPath(r.URL.Path)
	case r.Method == "DELETE":
		action = "delete"
		hash = blobPath(r.URL.Path)
	default:
		deny(w, r, 405)
		return
	}
	if (action != "list" && hash == "") || r.URL.RawPath != "" {
		deny(w, r, 400)
		return
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		deny(w, r, 401)
		return
	}
	now := s.now().Unix()
	a, e := parseAuth(headers[0], action, hash, s.hostname, now, s.cfg.SkewSeconds)
	if e != nil {
		deny(w, r, 401)
		return
	}
	if !s.authorized(a, action, hash, r.URL.Path) {
		deny(w, r, 403)
		return
	}
	if status, e := s.reserve(a, now); e != nil {
		deny(w, r, status)
		return
	}
	switch action {
	case "upload":
		d, status, e := s.put(a, data, now)
		if e != nil {
			deny(w, r, status)
			return
		}
		jsonResponse(w, status, d)
	case "list":
		owner := strings.TrimPrefix(r.URL.Path, "/list/")
		limit := 100
		query, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil {
			deny(w, r, 400)
			return
		}
		for k, v := range query {
			if (k != "limit" && k != "cursor") || len(v) != 1 {
				deny(w, r, 400)
				return
			}
		}
		if v := query.Get("limit"); v != "" {
			limit, e = strconv.Atoi(v)
			if e != nil || limit < 1 || limit > 100 {
				deny(w, r, 400)
				return
			}
		}
		cursor := query.Get("cursor")
		if cursor != "" && !digest(cursor) {
			deny(w, r, 400)
			return
		}
		list := []Descriptor{}
		for _, m := range s.blobs {
			if m.Owner == owner {
				list = append(list, m.Descriptor)
			}
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Uploaded == list[j].Uploaded {
				return list[i].SHA256 < list[j].SHA256
			}
			return list[i].Uploaded > list[j].Uploaded
		})
		start := 0
		if cursor != "" {
			found := false
			for i, d := range list {
				if d.SHA256 == cursor {
					start = i + 1
					found = true
					break
				}
			}
			if !found {
				deny(w, r, 400)
				return
			}
		}
		end := start + limit
		if end > len(list) {
			end = len(list)
		}
		jsonResponse(w, 200, list[start:end])
	case "get", "delete":
		m := s.blobs[hash]
		if action == "delete" {
			if e := s.remove(hash); e != nil {
				deny(w, r, 503)
				return
			}
			w.WriteHeader(204)
			return
		}
		b, e := privateRead(s.cfg.Root+"/"+hash+"/blob", s.cfg.MaxBlobBytes)
		if e != nil || int64(len(b)) != m.Descriptor.Size || Hash(b) != hash {
			s.failed = true
			deny(w, r, 503)
			return
		}
		w.Header().Set("Content-Type", m.Descriptor.Type)
		http.ServeContent(w, r, hash+".bin", time.Unix(m.Descriptor.Uploaded, 0), bytes.NewReader(b))
	}
}

// authorized runs under the same mutex as reservation and effects. Refusals
// never spend a replay slot, including missing blobs and another owner's list.
func (s *Server) authorized(a authorization, action, hash, path string) bool {
	switch action {
	case "upload":
		allowed := false
		for _, writer := range s.cfg.Writers {
			allowed = allowed || writer == a.Event.PubKey
		}
		return allowed
	case "list":
		owner := strings.TrimPrefix(path, "/list/")
		if owner != a.Event.PubKey || !key(owner) {
			return false
		}
		// A self-signed empty namespace is not putter authority: otherwise
		// anyone could mint fresh keys and fill the journal through list.
		for _, m := range s.blobs {
			if m.Owner == owner {
				return true
			}
		}
		return false
	case "get", "delete":
		m, ok := s.blobs[hash]
		allowed := false
		if ok {
			if action == "delete" {
				allowed = m.Owner == a.Event.PubKey
			} else {
				for _, reader := range m.Readers {
					allowed = allowed || reader == a.Event.PubKey
				}
			}
		}
		return allowed
	}
	return false
}
