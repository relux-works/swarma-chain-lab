package smoke

import (
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"time"
)

type contractEnvelope struct {
	ID       string `json:"booking_id"`
	Hash     string `json:"contract_sha256"`
	Contract string `json:"contract_base64"`
	Expires  int64  `json:"hold_expires_at"`
}
type paymentEnvelope struct {
	BookingID string `json:"booking_id"`
	Expires   int64  `json:"hold_expires_at"`
	Address   string `json:"address"`
	Amount    int64  `json:"amount_atomic"`
	Coin      string `json:"coin"`
	Min       int64  `json:"min_confirmations"`
}

func checkPaymentEnvelope(pay paymentEnvelope, c booking.ContractV2, expires, depth, now int64) error {
	if pay.BookingID != c.BookingID || pay.Expires != expires || expires <= now || pay.Address != c.Payment.Address || pay.Amount != c.Payment.AmountAtoms || pay.Coin != "nmc" || pay.Min != depth {
		return refuse("PAYMENT_BOUND")
	}
	return nil
}
func checkClosure(scenario string, notAfter, observedMS int64, idle time.Duration, now time.Time) error {
	if scenario == "expiry" && (observedMS < notAfter*1000 || now.Unix() < notAfter || idle <= 90*time.Second) {
		return refuse("EXPIRY_TIME")
	}
	return nil
}
