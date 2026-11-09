package wallet

import (
	"context"
	"encoding/json"
	"strings"

	sw "relux.works/swarma-chain-lab/experiments/sealwatch"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type Balance struct {
	Confirmed   int64 `json:"confirmed_sat"`
	Unconfirmed int64 `json:"unconfirmed_sat"`
	Immature    int64 `json:"immature_sat"`
}

func (w *Wallet) Balance(ctx context.Context) (Balance, error) {
	var b Balance
	raw, e := w.wallet.Call(ctx, "getbalances")
	if e != nil {
		return b, e
	}
	var mine json.RawMessage
	if sw.ProjectJSON(raw, map[string]any{"mine": &mine}, nil) != nil {
		return b, fail("BALANCE_RESPONSE")
	}
	var trusted, pending, immature json.Number
	if sw.ProjectJSON(mine, map[string]any{"trusted": &trusted, "untrusted_pending": &pending, "immature": &immature}, nil) != nil {
		return b, fail("BALANCE_RESPONSE")
	}
	if b.Confirmed, e = su.ParseCoins(trusted.String()); e != nil {
		return b, fail("BALANCE_AMOUNT")
	}
	if b.Unconfirmed, e = su.ParseCoins(pending.String()); e != nil {
		return b, fail("BALANCE_AMOUNT")
	}
	if b.Immature, e = su.ParseCoins(immature.String()); e != nil {
		return b, fail("BALANCE_AMOUNT")
	}
	return b, nil
}
func (w *Wallet) Receive(ctx context.Context) (string, error) {
	var a string
	if e := call(ctx, w.wallet, "getnewaddress", &a, "", "legacy"); e != nil {
		return "", e
	}
	if _, e := addressScript(a); e != nil {
		return "", e
	}
	return a, nil
}

type HistoryItem struct {
	TxID          string `json:"txid"`
	Category      string `json:"category"`
	Amount        int64  `json:"amount_sat"`
	Fee           int64  `json:"fee_sat"`
	Confirmations int64  `json:"confirmations"`
	Time          int64  `json:"time"`
}

func signedAtoms(n json.Number) (int64, error) {
	s := n.String()
	negative := strings.HasPrefix(s, "-")
	if negative {
		s = s[1:]
	}
	v, e := su.ParseCoins(s)
	if negative {
		v = -v
	}
	return v, e
}
func (w *Wallet) History(ctx context.Context) ([]HistoryItem, error) {
	var raw []json.RawMessage
	if e := call(ctx, w.wallet, "listtransactions", &raw, "*", 50, 0, false); e != nil {
		return nil, e
	}
	if raw == nil || len(raw) > 50 {
		return nil, fail("HISTORY_BOUND")
	}
	rows := make([]HistoryItem, 0, len(raw))
	for _, item := range raw {
		var r HistoryItem
		var amount, fee json.Number
		if sw.ProjectJSON(item, map[string]any{"txid": &r.TxID, "category": &r.Category, "amount": &amount, "confirmations": &r.Confirmations, "time": &r.Time}, map[string]any{"fee": &fee}) != nil || !hexN(r.TxID, 32) || !ascii(r.Category, 32) {
			return nil, fail("HISTORY_RESPONSE")
		}
		var e error
		if r.Amount, e = signedAtoms(amount); e != nil {
			return nil, fail("HISTORY_AMOUNT")
		}
		if fee != "" {
			if r.Fee, e = signedAtoms(fee); e != nil {
				return nil, fail("HISTORY_AMOUNT")
			}
		}
		rows = append(rows, r)
	}
	return rows, nil
}
