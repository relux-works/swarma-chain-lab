package wallet

import (
	"context"
	"encoding/hex"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// Bounded laboratory journals stop admitting before their receipt reserve is
// exhausted. No automatic pruning/reset can restore already consumed authority.
const maxServiceEntries = 32
const maxServiceReceipt = 16384

type serviceEntry struct {
	Request ActionRequest        `json:"request"`
	Hash    string               `json:"request_hash"`
	Phase   string               `json:"phase"`
	Peer    PeerIdentity         `json:"peer"`
	Plan    *Record              `json:"plan,omitempty"`
	Receipt *SignedActionReceipt `json:"receipt,omitempty"`
}
type serviceState struct {
	Version int            `json:"version"`
	Binding string         `json:"binding"`
	Entries []serviceEntry `json:"entries"`
}
type ActionService struct {
	mu       sync.Mutex
	config   ServiceConfig
	wallet   *Wallet
	key      *btcec.PrivateKey
	pub      string
	store    *durable.Store
	state    serviceState
	clock    func() int64
	poisoned bool
	hook     func(string) // Unexported crash/race fixture seam; never configured by CLI.
}

func OpenActionService(c ServiceConfig) (*ActionService, error) {
	if e := validServiceConfig(c); e != nil {
		return nil, e
	}
	wc, e := LoadInstalledWalletConfig(c.WalletConfig)
	if e != nil {
		return nil, e
	}
	if e := wc.validateNetwork(); e != nil {
		return nil, e
	}
	network, genesis := serviceNetworkPins(c.Network, c.Genesis)
	if wc.Network != network || wc.Genesis != genesis {
		return nil, fail("SERVICE_WALLET_NETWORK")
	}
	if c.StateDir == wc.StateDir || c.StateDir == wc.Policy.StateDir || c.StateDir == wc.ObjectsDir || c.StateDir == wc.WalletDir || c.StateDir == wc.MemoryZone {
		return nil, fail("SERVICE_PATH")
	}
	i, e := os.Lstat(wc.ObjectsDir)
	if e != nil || !i.IsDir() || i.Mode().Perm()&0022 != 0 {
		return nil, fail("SERVICE_OBJECTS")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return nil, fail("SERVICE_OBJECTS")
	}
	key, e := loadReceiptKey(c.ReceiptKeyFile)
	if e != nil {
		return nil, e
	}
	if hex.EncodeToString(schnorr.SerializePubKey(key.PubKey())) == c.Grantee {
		return nil, fail("SERVICE_KEY_SEPARATION")
	}
	w, e := px1OpenServiceWallet(wc, c, key)
	if e != nil {
		return nil, e
	}
	s, e := openActionService(c, w, key)
	if e != nil {
		w.Close()
		return nil, e
	}
	return s, nil
}
func openActionService(c ServiceConfig, w *Wallet, key *btcec.PrivateKey) (*ActionService, error) {
	store, e := durable.Open(c.StateDir, "service.lock")
	if e != nil {
		return nil, e
	}
	pub := hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	s := &ActionService{config: c, wallet: w, key: key, pub: pub, store: store, clock: func() int64 { return time.Now().Unix() }}
	binding := Hash(canonical(struct {
		Config ServiceConfig `json:"config"`
		Key    string        `json:"key"`
		Wallet string        `json:"wallet_binding"`
	}{c, pub, w.state.Binding}))
	s.state = serviceState{1, binding, []serviceEntry{}}
	b, e := store.Read("service.json", 65536)
	if e == nil && b != nil {
		e = strict(b, &s.state)
		if e == nil && (s.state.Version != 1 || s.state.Binding != binding || s.state.Entries == nil || len(s.state.Entries) > maxServiceEntries) {
			e = fail("SERVICE_JOURNAL_BINDING")
		}
		seen := map[string]bool{}
		if e == nil {
			for index, entry := range s.state.Entries {
				_, fieldErr := actionFieldsForNetwork(entry.Request, c.Service, w.config.Network, w.config.Genesis)
				if fieldErr != nil || entry.Request.Grantee != c.Grantee || entry.Hash != Hash(canonical(entry.Request)) || seen[entry.Request.Nonce] || entry.Peer.UID != c.PeerUID {
					e = fail("SERVICE_JOURNAL_ENTRY")
					break
				}
				seen[entry.Request.Nonce] = true
				if entry.Phase != "pending" && entry.Phase != "reserved" && entry.Phase != "terminal" {
					e = fail("SERVICE_JOURNAL_PHASE")
					break
				}
				if entry.Phase == "terminal" && entry.Receipt == nil || entry.Phase == "reserved" && entry.Receipt != nil {
					e = fail("SERVICE_JOURNAL_PHASE")
					break
				}
				if entry.Receipt != nil {
					r, err := ParseActionReceipt(canonical(entry.Receipt), pub, entry.Hash, c.Grantee)
					if err != nil || r.Receipt.Sequence != uint64(index+1) || r.Receipt.Peer != entry.Peer || (entry.Phase == "pending") != (r.Receipt.Verdict == "pending") {
						e = fail("SERVICE_JOURNAL_RECEIPT")
						break
					}
				}
			}
		}
	}
	if e != nil {
		store.Close()
		return nil, e
	}
	return s, nil
}
func (s *ActionService) Close() { s.store.Close(); s.wallet.Close() }
func (s *ActionService) persist() error {
	if s.poisoned {
		return fail("SERVICE_STATE_UNAVAILABLE")
	}
	raw := canonical(s.state)
	if len(raw) > 65536 {
		s.poisoned = true
		return fail("SERVICE_JOURNAL_LIMIT")
	}
	if e := s.store.Write("service.json", raw); e != nil {
		s.poisoned = true
		return fail("SERVICE_JOURNAL_UNCERTAIN")
	}
	return nil
}
func (s *ActionService) reply(hash string, peer PeerIdentity, seq uint64, height int64, verdict, reason string, effect any) SignedActionReceipt {
	if !boundedCode(reason) {
		reason = "SERVICE_FAILURE"
	}
	return signActionReceipt(ActionReceipt{1, s.config.Service, s.config.Grantee, hash, verdict, reason, canonical(effect), seq, height, peer}, s.key)
}
func (s *ActionService) finish(index int, height int64, verdict, reason string, effect any) []byte {
	entry := &s.state.Entries[index]
	r := s.reply(entry.Hash, entry.Peer, uint64(index+1), height, verdict, reason, effect)
	if len(canonical(r)) > maxServiceReceipt {
		r = s.reply(entry.Hash, entry.Peer, uint64(index+1), height, "uncertain", "SERVICE_RECEIPT_LIMIT", struct{}{})
		verdict = "uncertain"
	}
	entry.Receipt = &r
	entry.Phase = "terminal"
	if verdict == "pending" {
		entry.Phase = "pending"
	}
	if s.persist() != nil {
		return canonical(s.reply(entry.Hash, entry.Peer, uint64(index+1), height, "uncertain", "SERVICE_JOURNAL_UNCERTAIN", struct{}{}))
	}
	return canonical(r)
}
func (s *ActionService) observe(ctx context.Context) (int64, error) {
	o := su.NewReadObservation(ctx, s.wallet.node)
	defer o.Close()
	if e := o.Start(s.wallet.config.Network, s.wallet.config.Genesis); e != nil {
		return 0, e
	}
	return o.Tip().Blocks, nil
}
func (s *ActionService) handle(ctx context.Context, raw []byte, peer PeerIdentity) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	reject := func(hash, code string) []byte {
		return canonical(s.reply(hash, peer, 0, 0, "refused", code, struct{}{}))
	}
	if peer.UID != s.config.PeerUID {
		return reject(Hash(raw), "SERVICE_PEER")
	}
	v, e := ParseActionForNetwork(raw, s.config.Service, s.wallet.config.Network, s.wallet.config.Genesis)
	if e != nil {
		return reject(Hash(raw), safeCode(e))
	}
	r := v.Envelope.Request
	if r.Grantee != s.config.Grantee {
		return reject(v.Hash, "GRANTEE_MISMATCH")
	}
	if s.poisoned {
		return reject(v.Hash, "SERVICE_STATE_UNAVAILABLE")
	}
	index := -1
	for i, entry := range s.state.Entries {
		if entry.Request.Nonce == r.Nonce {
			if entry.Hash != v.Hash {
				return reject(v.Hash, "NONCE_CONFLICT")
			}
			index = i
			if entry.Phase == "terminal" {
				return canonical(entry.Receipt)
			}
			if entry.Phase == "reserved" {
				return s.finish(i, 0, "uncertain", "DURABLE_RESERVATION_NO_RETRY", struct{}{})
			}
			break
		}
	}
	if index < 0 {
		now := s.clock()
		if r.CreatedAt < now-s.config.SkewSeconds || r.CreatedAt > now+s.config.SkewSeconds {
			return reject(v.Hash, "ACTION_SKEW")
		}
		if len(s.state.Entries) >= maxServiceEntries || len(canonical(s.state))+maxServiceReceipt+len(v.RequestBytes)+1024 > 65536 {
			return reject(v.Hash, "SERVICE_JOURNAL_LIMIT")
		}
		index = len(s.state.Entries)
		s.state.Entries = append(s.state.Entries, serviceEntry{Request: r, Hash: v.Hash, Phase: "pending", Peer: peer})
		if s.persist() != nil {
			return reject(v.Hash, "SERVICE_JOURNAL_UNCERTAIN")
		}
	}
	refused := func(err error) []byte { return s.finish(index, 0, "refused", safeCode(err), struct{}{}) }
	var grantRaw, termsRaw []byte
	if r.Grant.Kind != "none" {
		grantRaw, e = LoadGrant(s.wallet.config, r.Grant.ID)
		if e != nil {
			return refused(e)
		}
		g, err := s.wallet.Grant(grantRaw)
		if err != nil {
			return refused(err)
		}
		kind := g.Kind
		if kind == "" {
			kind = "standing"
		}
		if g.Grantee != r.Grantee {
			return refused(fail("GRANT_GRANTEE_MISMATCH"))
		}
		if kind != r.Grant.Kind {
			return refused(fail("GRANT_KIND"))
		}
		termsRaw, e = LoadTerms(s.wallet.config, g)
		if e != nil {
			return refused(e)
		}
	}
	height, e := s.observe(ctx)
	if e != nil {
		return refused(e)
	}
	switch r.Action {
	case "balance":
		value, e := s.wallet.Balance(ctx)
		if e != nil {
			return refused(e)
		}
		return s.finish(index, height, "executed", "READ", value)
	case "history":
		value, e := s.wallet.History(ctx)
		if e != nil {
			return refused(e)
		}
		return s.finish(index, height, "executed", "READ", value)
	case "budget":
		value, e := s.wallet.Budget(ctx, grantRaw, termsRaw)
		if e != nil {
			return refused(e)
		}
		return s.finish(index, height, "executed", "READ", value)
	case "receive":
		entry := &s.state.Entries[index]
		entry.Phase = "reserved"
		entry.Receipt = nil
		if s.persist() != nil {
			return reject(v.Hash, "SERVICE_JOURNAL_UNCERTAIN")
		}
		if s.hook != nil {
			s.hook("after-service-reservation")
		}
		height, e = s.observe(ctx)
		if e != nil {
			return s.finish(index, 0, "refused", safeCode(e), struct{}{})
		}
		address, e := s.wallet.Receive(ctx)
		if e != nil {
			return s.finish(index, height, "uncertain", safeCode(e), struct{}{})
		}
		return s.finish(index, height, "executed", "ALLOCATED", struct {
			Address string `json:"address"`
		}{address})
	case "spend":
		use := ""
		if v.Envelope.Proof != nil {
			use = v.Envelope.Proof.UseTxID
		}
		before := func(rec Record) error {
			entry := &s.state.Entries[index]
			entry.Phase = "reserved"
			entry.Plan = &rec
			entry.Receipt = nil
			if e := s.persist(); e != nil {
				return e
			}
			if s.hook != nil {
				s.hook("after-service-reservation")
			}
			return nil
		}
		s.wallet.mu.Lock()
		var result Receipt
		if s.wallet.poisoned {
			result = refuse(fail("STATE_UNAVAILABLE"))
		} else {
			result = s.wallet.executeAuthenticated(ctx, grantRaw, termsRaw, v.walletRequest(), r.Grantee, r.CreatedAt, v.RequestBytes, use, before)
		}
		s.wallet.mu.Unlock()
		status := result.Status
		if status == "already-executed" {
			status = "uncertain"
		}
		return s.finish(index, height, status, result.Reason, struct {
			TxID     string `json:"txid,omitempty"`
			Reserved int64  `json:"reserved_sat"`
			Phase    string `json:"phase,omitempty"`
		}{result.TxID, result.Reserved, result.Phase})
	}
	return refused(fail("ACTION_UNSUPPORTED"))
}
