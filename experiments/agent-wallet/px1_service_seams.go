package wallet

// PX1 stream S2 seam bodies and the service-layer G2 state (owner S2). Under
// W2 (ActionService.g2 == nil) the service keeps its W2 journal and behaviour
// and the seams expose no journal and no profile.

import su "github.com/relux-works/swarma-chain-lab/experiments/single-use"

// Service-layer journal v2 location: the service state_dir, next to the W2
// service.json, under its own lock so the W2 store lock is never shared.
const px1jServiceJournalLock = "service-v2.lock"

// px1jServiceReserve is the bytes kept free in an empty segment for the
// terminal record of an admitted request (request + receipt + plan + JSON).
const px1jServiceReserve = maxServiceReceipt + 4096

// px1jService is the G2 service-layer state. ActionService.g2 == nil means W2.
type px1jService struct {
	operator G2OperatorConfig
	journal  JournalV2
	clock    ClockGuard
	reads    *px1jReadLimiter
	limits   JournalLimitsV2
	entries  map[string]*px1jServiceEntry // by action nonce (one grantee)
	// halt is S3's admission halt for spends (px1jProbeHalt in product);
	// unit fixtures substitute it, because S3's runtime is not theirs to set.
	halt func(*ActionService) string
}

// px1jServiceEntry is the folded service-layer state of one admitted request.
type px1jServiceEntry struct {
	admit   JournalRecordV2 // the admit record (Seq is the receipt journal_seq)
	phase   string          // pending | reserved | terminal
	plan    JournalRecordV2 // plan fields of the service-reserve record (spend)
	receipt *SignedActionReceipt
}

// px1jServiceDeps are the cross-stream entry points the service layer
// consumes. Product values are the frozen functions; unit tests substitute
// fakes of the same frozen signatures while S1's validator is still a stub.
type px1jServiceDeps struct {
	validate func(G2OperatorConfig) error
	open     func(dir, lockName string, h JournalHeaderV2, l JournalLimitsV2) (JournalV2, error)
}

func px1jServiceProductDeps() px1jServiceDeps {
	return px1jServiceDeps{validate: ValidateG2OperatorConfig, open: OpenJournalV2}
}

// px1jProfileOf selects the G2 profile from the service configuration. The
// `g2` member of ServiceConfig belongs to S1 (service_config.go) and is not
// on the frozen base, so until S1 lands every service stays W2. Integration
// step 3 (PX1-INTERFACES.md) replaces the body with `return c.G2` and attaches
// the wallet layer with S1's px1Attach before px1jOpenService.
func px1jProfileOf(c ServiceConfig) *G2OperatorConfig { return nil }

// px1jOpenService attaches the G2 service layer: it opens the service-layer
// journal v2 bound to the W2 service binding, re-verifies every admitted
// request and stored receipt, and starts the clock guard at the journal's
// last_time (CLOCK_ROLLBACK at startup) and the read limiter.
func (s *ActionService) px1jOpenService(op G2OperatorConfig, binding string, deps px1jServiceDeps) error {
	if s.g2 != nil || len(s.state.Entries) != 0 {
		// A W2 service journal with entries is never silently continued
		// under G2: its nonces would be forgotten.
		return fail("SERVICE_PROFILE")
	}
	if deps.validate == nil || deps.open == nil {
		return fail("SERVICE_CONFIG")
	}
	if e := deps.validate(op); e != nil {
		return e
	}
	// Defence in depth under S1's validator: the PX1 decisions this layer
	// relies on (Q7, terms v2 only, a usable read limit and capacity).
	if op.RequireTermsVersion != TermsV2Version || op.AllowSingleUse || op.ReadRatePerHour < 1 || op.JournalSpendCapacity < 1 || op.MaxDayCount < 1 || op.MaxDayCount > MaxDayCountCap {
		return fail("SERVICE_CONFIG")
	}
	limits := JournalLimitsV2{SpendCapacity: op.JournalSpendCapacity, SegmentMaxRecords: px1jDefaultSegmentRecords, SegmentMaxBytes: px1jDefaultSegmentBytes}
	header := JournalHeaderV2{Version: 2, Layer: JournalLayerService, Binding: binding}
	j, e := deps.open(s.config.StateDir, px1jServiceJournalLock, header, limits)
	if e != nil {
		return e
	}
	x := &px1jService{operator: op, journal: j, limits: limits, entries: map[string]*px1jServiceEntry{}, halt: func(s *ActionService) string { return px1jProbeHalt(s) }}
	if j == nil || j.Header() != header {
		if j != nil {
			j.Close()
		}
		return fail(CodeJournalSegment)
	}
	if e = s.px1jLoadEntries(x); e == nil {
		x.clock, e = NewClockGuard(s.clock, j.Usage().LastTime)
	}
	if e != nil {
		j.Close()
		return e
	}
	x.reads = NewReadLimiter(op.ReadRatePerHour).(*px1jReadLimiter)
	s.g2 = x
	return nil
}

// px1jLoadEntries folds the service-layer journal and re-verifies what W2
// verifies at open: request shape and network, pinned grantee and peer, and
// every stored receipt against this instance's receipt key and admit Seq.
func (s *ActionService) px1jLoadEntries(x *px1jService) error {
	return x.journal.Iterate(1, func(r JournalRecordV2) error {
		entry := x.entries[r.Nonce]
		if r.Kind == RecordAdmit {
			q := r.Service.Request
			if _, e := actionFieldsForNetwork(q, s.config.Service, s.wallet.config.Network, s.wallet.config.Genesis); e != nil || q.Grantee != s.config.Grantee || r.Service.Peer.UID != s.config.PeerUID || entry != nil {
				return fail("SERVICE_JOURNAL_ENTRY")
			}
			x.entries[r.Nonce] = &px1jServiceEntry{admit: r, phase: "pending"}
			return nil
		}
		if entry == nil {
			return fail("SERVICE_JOURNAL_ENTRY")
		}
		entry.phase = r.Phase
		if r.Kind == RecordServiceReserve {
			entry.plan = r
			return nil
		}
		receipt, e := ParseActionReceipt(canonical(r.Service.Receipt), s.pub, entry.admit.RequestHash, s.config.Grantee)
		if e != nil || receipt.Receipt.Sequence != entry.admit.Seq || receipt.Receipt.Peer != entry.admit.Service.Peer || receipt.Receipt.Verdict == "pending" {
			return fail("SERVICE_JOURNAL_RECEIPT")
		}
		entry.receipt = &receipt
		return nil
	})
}

// px1jAppend writes one service-layer follow-up of entry with the guarded clock.
func (s *ActionService) px1jAppend(entry *px1jServiceEntry, kind, phase string, plan JournalRecordV2, receipt *SignedActionReceipt) error {
	now, e := s.g2.clock.Now()
	if e != nil {
		return e
	}
	rec := entry.admit
	rec.Seq, rec.Kind, rec.Phase, rec.LastTime = 0, kind, phase, now
	rec.Reserved, rec.Fee, rec.Day, rec.Inputs, rec.TxID = plan.Reserved, plan.Fee, plan.Day, plan.Inputs, plan.TxID
	if rec.Inputs == nil {
		rec.Inputs = []su.Point{}
	}
	service := *entry.admit.Service
	service.Receipt = receipt
	rec.Service = &service
	if _, e = s.g2.journal.Append(rec); e != nil {
		return e
	}
	entry.phase = phase
	if kind == RecordServiceReserve {
		entry.plan = rec
	}
	if receipt != nil {
		stored := *receipt
		entry.receipt = &stored
	}
	return nil
}

// px1jJournalCode maps a service-layer append error to the W2 wire code.
func (s *ActionService) px1jJournalCode(e error) string {
	if s.g2.journal.Poisoned() {
		return "SERVICE_JOURNAL_UNCERTAIN"
	}
	return safeCode(e)
}

// px1jTracked finds the wallet-layer reserve record of an executed spend and
// builds the tracker registration (step 23). BroadcastTip is the own-node
// height observed for this request (step 11), the last tip before broadcast.
func (s *ActionService) px1jTracked(result Receipt, height int64) (TrackedPayment, bool) {
	j := s.wallet.PX1Journal()
	if j == nil {
		return TrackedPayment{}, false
	}
	var p TrackedPayment
	found := false
	_ = j.Iterate(1, func(r JournalRecordV2) error {
		if r.Kind == RecordReserve && r.GrantID == result.GrantID && r.Nonce == result.Nonce && r.TxID == result.TxID {
			p = TrackedPayment{GrantID: r.GrantID, Nonce: r.Nonce, TxID: r.TxID, Inputs: r.Inputs, ReserveSeq: r.Seq, BroadcastTip: height, State: TrackPending}
			found = true
		}
		return nil
	})
	return p, found
}

// PX1ServiceJournal returns the service-layer journal v2, or nil under W2.
func (s *ActionService) PX1ServiceJournal() JournalV2 {
	if s.g2 == nil {
		return nil
	}
	return s.g2.journal
}

// PX1Profile returns a copy of the active G2 operator block, or nil under W2.
func (s *ActionService) PX1Profile() *G2OperatorConfig {
	if s.g2 == nil {
		return nil
	}
	op := s.g2.operator
	return &op
}
