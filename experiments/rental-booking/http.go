package booking

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const browserScript = `const out=document.getElementById('out');let current;
async function post(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const v=await r.json();if(!r.ok)throw Error(v.error);return v;}
document.getElementById('book').onclick=async()=>{try{if(!document.getElementById('privacy').checked)throw Error('Acknowledge the privacy notice first.');if(!window.nostr)throw Error('A NIP-07 signer is required.');const pubkey=await window.nostr.getPublicKey();current=await post('/book',{slot_id:document.getElementById('slot').value,renter_pubkey:pubkey,renter_name:document.getElementById('name').value,privacy_acknowledged:true});out.textContent=JSON.stringify(current,null,2);document.getElementById('sign').disabled=false;}catch(e){out.textContent=e.message;}};
document.getElementById('sign').onclick=async()=>{try{if(!current)throw Error('Book first.');const b=current.booking;const event={created_at:Math.floor(Date.now()/1000),kind:8181,tags:[['t','swarma-rental-consent-v1'],['contract',current.contract_sha256],['booking',b.contract.booking_id],['privacy',b.contract.privacy_sha256]],content:''};const signed=await window.nostr.signEvent(event);out.textContent=JSON.stringify(await post('/consent',{booking_id:b.contract.booking_id,event:signed}),null,2);}catch(e){out.textContent=e.message;}};`
const pageHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Rental booking regtest</title><h1>Rental booking — regtest</h1><p>Local experiment. Payments use disposable regtest coins.</p><p>Start-now bookings require at least {{.StartWindow}} seconds remaining. Payment and rental activation confirmations may delay the start; the signed end time stays fixed.</p><p>{{.Privacy}}</p>{{if .ModelTerms}}<p id="model-terms">{{.ModelTerms}}</p>{{end}}<label><input id="privacy" type="checkbox">I acknowledge this permanent public linkage.</label><p><label>Slot <select id="slot">{{range .Slots}}<option value="{{.ID}}">{{.StationName}} · {{.NotBefore}}–{{.NotAfter}} · {{.PaymentPolicy}}</option>{{end}}</select></label></p><p>Price: {{.Price}} USD cents. The booking response fixes the exact NMC amount and rate.</p><p><label>Optional Namecoin name <input id="name" placeholder="id/example"></label></p><button id="book">Create hold and show contract</button><button id="sign" disabled>Sign the displayed contract</button><pre id="out" aria-live="polite"></pre><script>{{.Script}}</script></html>`

type HTTPHandler struct {
	s      *Service
	v2     *ServiceV2
	script string
	origin string
	page   *template.Template
	csp    string
}

func NewHTTPHandler(s *Service, origin string) (*HTTPHandler, error) {
	return newHTTPHandler(s, nil, origin)
}

// NewHTTPHandlerV2 exposes the same bounded routes with independently typed v2
// contracts. It does not reinterpret v1 exchange requests or choose a coin.
func NewHTTPHandlerV2(s *ServiceV2, origin string) (*HTTPHandler, error) {
	return newHTTPHandler(nil, s, origin)
}
func newHTTPHandler(s *Service, v2 *ServiceV2, origin string) (*HTTPHandler, error) {
	u, e := url.Parse(origin)
	if (s == nil && v2 == nil) || e != nil || u.Scheme != "http" || !LoopbackAddress(u.Host) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, refuse("HTTP_ORIGIN")
	}
	html, script := pageHTML, browserScript
	if v2 != nil {
		if network, _ := v2.cfg.NetworkPins(); network == "main" {
			html = strings.ReplaceAll(html, "Rental booking regtest", "Rental booking — Namecoin mainnet")
			html = strings.ReplaceAll(html, "Rental booking — regtest", "Rental booking — Namecoin mainnet")
			html = strings.Replace(html, "Local experiment. Payments use disposable regtest coins.", "M5 test rental. Payments use real NMC on Namecoin mainnet.", 1)
		}
		html = strings.Replace(html, "exact NMC amount", "exact amount in the selected coin", 1)
		html = strings.Replace(html, `<button id="book">`, `<p><label>Payment coin <select id="coin">{{range .Coins}}<option value="{{.}}">{{.}}</option>{{end}}</select></label></p><button id="book">`, 1)
		script = strings.Replace(script, "slot_id:document", "coin:document.getElementById('coin').value,slot_id:document", 1)
	}
	t, e := template.New("booking").Parse(html)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256([]byte(script))
	csp := "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	return &HTTPHandler{s: s, v2: v2, origin: origin, page: t, csp: csp, script: script}, nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func httpFail(w http.ResponseWriter, status int, code string) {
	respond(w, status, map[string]string{"error": code})
}
func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return refuse("CONTENT_TYPE")
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		return refuse("BODY_BOUND")
	}
	return Strict(raw, v)
}
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", h.csp)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if "http://"+r.Host != h.origin {
		httpFail(w, 403, "HOST_REFUSED")
		return
	}
	if r.Method == "POST" && r.Header.Get("Origin") != h.origin {
		httpFail(w, 403, "ORIGIN_REFUSED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5e9)
	defer cancel()
	switch {
	case r.Method == "GET" && r.URL.Path == "/catalogue":
		if len(r.URL.RawQuery) > 128 {
			httpFail(w, 400, "CATALOGUE_BOUNDS")
			return
		}
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) != 2 || len(q["until"]) != 1 || len(q["limit"]) != 1 {
			httpFail(w, 400, "CATALOGUE_BOUNDS")
			return
		}
		until, e1 := strconv.ParseInt(q.Get("until"), 10, 64)
		limit, e2 := strconv.Atoi(q.Get("limit"))
		if e1 != nil || e2 != nil {
			httpFail(w, 400, "CATALOGUE_BOUNDS")
			return
		}
		var c any
		if h.v2 != nil {
			c, e = h.v2.Catalogue(until, limit)
		} else {
			c, e = h.s.Catalogue(until, limit)
		}
		if e != nil {
			httpFail(w, 400, "CATALOGUE_BOUNDS")
			return
		}
		respond(w, 200, c)
	case r.Method == "GET" && r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := struct {
			Privacy     string
			ModelTerms  string
			Slots       []Slot
			Price       int64
			StartWindow int64
			Coins       []string
			Script      template.JS
		}{Privacy: PrivacyNotice, Script: template.JS(h.script)}
		if h.v2 != nil {
			if caps := h.v2.cfg.Template.ModelCaps; caps != nil {
				data.ModelTerms = caps.Text()
			}
			data.Slots = h.v2.cfg.Slots
			data.Price = h.v2.cfg.PriceUSDCents
			data.StartWindow = h.v2.cfg.MinStartNowRemainingSeconds
			for coin := range h.v2.cfg.Coins {
				data.Coins = append(data.Coins, coin)
			}
			sort.Strings(data.Coins)
		} else {
			data.Slots = h.s.cfg.Slots
			data.Price = h.s.cfg.PriceUSDCents
			data.StartWindow = h.s.cfg.MinStartNowRemainingSeconds
		}
		_ = h.page.Execute(w, data)
	case r.Method == "POST" && r.URL.Path == "/book":
		if h.v2 != nil {
			var in BookInputV2
			if e := decodeBody(w, r, &in); e != nil {
				httpFail(w, 400, e.Error())
				return
			}
			b, e := h.v2.Book(ctx, in)
			if e != nil {
				httpFail(w, 409, e.Error())
				return
			}
			respond(w, 201, map[string]any{"booking": b, "contract_sha256": b.Contract.Hash()})
			return
		}
		var in BookInput
		if e := decodeBody(w, r, &in); e != nil {
			httpFail(w, 400, e.Error())
			return
		}
		b, e := h.s.Book(ctx, in)
		if e != nil {
			httpFail(w, 409, e.Error())
			return
		}
		respond(w, 201, map[string]any{"booking": b, "contract_sha256": b.Contract.Hash()})
	case r.Method == "POST" && r.URL.Path == "/consent":
		var in struct {
			BookingID string `json:"booking_id"`
			Event     Event  `json:"event"`
		}
		if e := decodeBody(w, r, &in); e != nil {
			httpFail(w, 400, e.Error())
			return
		}
		var b any
		var e error
		if h.v2 != nil {
			b, e = h.v2.AcceptConsent(ctx, in.BookingID, in.Event)
		} else {
			b, e = h.s.AcceptConsent(ctx, in.BookingID, in.Event)
		}
		if e != nil {
			httpFail(w, 409, e.Error())
			return
		}
		respond(w, 200, b)
	case r.Method == "GET" && r.URL.Path == "/booking":
		id := r.URL.Query().Get("id")
		if !hexSize(id, 32) {
			httpFail(w, 400, "BOOKING_ID")
			return
		}
		var b any
		var e error
		if h.v2 != nil {
			b, e = h.v2.Get(id)
		} else {
			b, e = h.s.Get(id)
		}
		if e != nil {
			httpFail(w, 404, e.Error())
			return
		}
		respond(w, 200, b)
	default:
		httpFail(w, 404, "NOT_FOUND")
	}
}
