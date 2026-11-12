package wallet

// PX1 stream S1 seam bodies (owner S1). STUBS until S1 lands.

// PX1Journal returns the wallet-layer journal v2, or nil under W2.
func (w *Wallet) PX1Journal() JournalV2 { return nil }

// PX1Ledger folds the wallet-layer journal for the cap checker.
func (w *Wallet) PX1Ledger() (LedgerView, error) { return nil, ErrNotImplemented }
