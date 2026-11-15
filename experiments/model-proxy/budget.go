package modelproxy

import (
	"net/http"
	"time"
)

// Budget is secret-free conservative exposure: committed includes full pending
// and uncertain reservations, replaced by actual cost only on verified settlement.
type Budget struct {
	UTCDay           string `json:"utc_day"`
	CeilingNanoUSD   uint64 `json:"ceiling_nano_usd"`
	CommittedNanoUSD uint64 `json:"committed_nano_usd"`
	RemainingNanoUSD uint64 `json:"remaining_nano_usd"`
}

func accountingCode(code string) bool {
	return code == "DAILY_ACCOUNTING_MISSING" || code == "DAILY_ACCOUNTING_CORRUPT"
}

// DailyBudget rolls forward with the same durable clock and mutex as admission.
func (s *Service) DailyBudget() (Budget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.clock()
	if e != nil {
		return Budget{}, e
	}
	spent := s.state.Daily.Committed
	return Budget{time.Unix(now, 0).UTC().Format("2006-01-02"), s.cfg.DailyCostCeilingNanoUSD, spent, s.cfg.DailyCostCeilingNanoUSD - spent}, nil
}

// budgetHandler is reached only after the existing pinned Unix peer check.
func (s *Service) budgetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		refusal(w, 400, "ADMIN")
		return
	}
	b, e := s.DailyBudget()
	if e != nil {
		code := e.Error()
		if !accountingCode(code) {
			code = "UNAVAILABLE"
		}
		refusal(w, 503, code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(privateCanonical(b))
}
