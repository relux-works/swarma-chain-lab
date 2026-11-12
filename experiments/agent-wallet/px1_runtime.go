package wallet

// PX1 stream S3 runtime (owner S3): the tracker/canary/float/seal pass behind
// ActionService.PX1Tick, the PX1Enqueue hand-off at spend step 23 and the
// PX1Status projection. All observation state lives in px1Runtime; the
// service and wallet journals are reached only through the frozen seams.

import (
	"context"
	"os"
	"sort"
	"strconv"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// px1oTrackBacklog is the alert detail of a track backlog episode: tracker
// observations are queued but not durable, and the tracker is not polled.
const px1oTrackBacklog = "TRACK_BACKLOG"

// px1oRuntimeDeps are the S3 constructors the runtime uses. Production values
// are the frozen entry points; tests replace them with fakes of the same
// frozen interfaces.
type px1oRuntimeDeps struct {
	newTracker    func(node su.Node, cfg TrackerConfig, wallet JournalV2) (Tracker, error)
	newCanary     func(node su.Node, cfg CanaryConfig) (Canary, error)
	newFloat      func(wallet su.Node, maxFloatSat, lowFloatSat int64) (FloatMonitor, error)
	newReconciler func(walletRoute su.Node) (StartupReconciler, error)
}

func px1oProductRuntimeDeps() px1oRuntimeDeps {
	return px1oRuntimeDeps{newTracker: NewTracker, newCanary: NewCanary, newFloat: NewFloatMonitor, newReconciler: NewStartupReconciler}
}

// px1oEnv is everything one runtime pass reads from the service. The service
// assembles it under ActionService.mu and Wallet.mu (px1oEnvFor).
type px1oEnv struct {
	profile     *G2OperatorConfig
	service     JournalV2 // service layer (S2)
	wallet      JournalV2 // wallet layer (S1)
	observer    su.Node   // w3-observer route
	walletRoute su.Node   // w1-wallet route (getbalances, listtransactions)
	receiptKey  string
	network     string
	now         int64
	poisoned    bool
	poison      func() // marks the service poisoned (in memory, sticky)
	// limitsFor returns min(terms, operator) for a grant id; sealFor returns
	// the kernel verdict for a grant id. Both are nil-safe: a nil function or
	// an error leaves the grant out of the projection / its seal unknown.
	limitsFor func(grantID string) (EffectiveLimits, error)
	sealFor   func(ctx context.Context, grantID string) error
}

// px1Runtime is S3's per-service state. The zero value is ready for use: the
// first tick constructs the observers and runs startup reconciliation.
type px1Runtime struct {
	deps       *px1oRuntimeDeps // nil: product constructors
	sink       AlertSink        // nil: single-line stderr sink
	ready      bool
	failed     string // sticky startup refusal (STATE_RECONCILE_REQUIRED)
	tracker    Tracker
	canary     Canary
	float      FloatMonitor
	alerts     []Alert
	tip        StatusTip
	floatLast  FloatReading
	canaryLast StatusCanary
	seals      map[string]StatusSealCheck
	limits     map[string]EffectiveLimits
	highWater  bool
	clockBack  bool
	lastSeq    uint64 // wallet-layer Seq already scanned for uncertain records
	lastSvcSeq uint64 // service-layer Seq already scanned for uncertain verdicts
	// tracks holds tracker transitions that are observed but not yet durable,
	// oldest first. A refused append leaves them queued; the next pass retries
	// exactly these before it polls the tracker again (the tracker has already
	// moved on), so the queue never holds more than one Tick's transitions.
	tracks []TrackTransition
	// backlog is set while tracks could not drain (backpressure: the tracker
	// is not polled); the backlog alert is raised once per such episode.
	backlog bool
}

func (r *px1Runtime) constructors() px1oRuntimeDeps {
	if r.deps != nil {
		return *r.deps
	}
	return px1oProductRuntimeDeps()
}

func (r *px1Runtime) raise(code string, at int64, detail string) {
	a, ok := px1oSanitizeAlert(Alert{Code: code, At: at, Detail: detail})
	if !ok {
		return
	}
	r.alerts = append(r.alerts, a)
	if len(r.alerts) > px1oAlertTail {
		r.alerts = append([]Alert{}, r.alerts[len(r.alerts)-px1oAlertTail:]...)
	}
	sink := r.sink
	if sink == nil {
		sink = NewLogAlertSink(func(line string) { os.Stderr.WriteString(line + "\n") })
	}
	sink.Raise(a)
}

func (r *px1Runtime) validEnv(env px1oEnv) error {
	if env.profile == nil {
		return fail("SERVICE_PROFILE")
	}
	if env.service == nil || env.wallet == nil || env.observer == nil || env.walletRoute == nil || env.poison == nil {
		return fail("STATE_UNAVAILABLE")
	}
	return nil
}

// start builds the observers and reconciles the hot wallet against the
// wallet-layer journal. A reconciliation refusal poisons the service and is
// sticky: every later pass returns the same code until a restart.
func (r *px1Runtime) start(ctx context.Context, env px1oEnv) error {
	d := r.constructors()
	op := env.profile
	tracker, e := d.newTracker(env.observer, TrackerConfig{ConfirmationsK: op.ConfirmationsK, ConflictBlocksN: op.ConflictBlocksN}, env.wallet)
	if e != nil {
		return e
	}
	canary, e := d.newCanary(env.observer, op.Canary)
	if e != nil {
		return e
	}
	float, e := d.newFloat(env.walletRoute, op.MaxFloatSat, op.LowFloatSat)
	if e != nil {
		return e
	}
	reconciler, e := d.newReconciler(env.walletRoute)
	if e != nil {
		return e
	}
	if tracker == nil || canary == nil || float == nil || reconciler == nil {
		return fail("STATE_UNAVAILABLE")
	}
	if e := reconciler.Reconcile(ctx, env.wallet); e != nil {
		if e.Error() == CodeStateReconcileRequired {
			r.failed = CodeStateReconcileRequired
			env.poison()
		}
		return e
	}
	r.tracker, r.canary, r.float = tracker, canary, float
	r.canaryLast = StatusCanary{Outpoint: op.Canary.Outpoint, ValueSat: op.Canary.ValueSat, State: CanaryUnknown}
	r.floatLast = FloatReading{MaxFloatSat: op.MaxFloatSat, LowFloatSat: op.LowFloatSat, State: "unknown"}
	r.ready = true
	return nil
}

// px1oSealVerdict maps a kernel refusal code to the status verdict.
func px1oSealVerdict(e error) StatusSealCheck {
	if e == nil {
		return StatusSealCheck{Verdict: "live", Reason: "LIVE"}
	}
	code := safeCode(e)
	switch code {
	case "GRANT_SEAL_SPENT", "GRANT_EXPIRED", "GRANT_LANDLORD_KEY_ROTATED", "GRANT_AGENT_LANDLORD_CHANGED":
		return StatusSealCheck{Verdict: "closed", Reason: code}
	case "GRANT_NOT_YET_VALID", "GRANT_ISSUANCE_UNCONFIRMED", "GRANT_SEAL_UNCONFIRMED":
		return StatusSealCheck{Verdict: "pending", Reason: code}
	}
	return StatusSealCheck{Verdict: "unknown", Reason: code}
}

// grantIDs lists the grants named by spend records of either journal.
func px1oGrantIDs(env px1oEnv) ([]string, error) {
	seen := map[string]bool{}
	collect := func(rec JournalRecordV2) error {
		if hexN(rec.GrantID, 32) {
			seen[rec.GrantID] = true
		}
		return nil
	}
	if e := env.wallet.Iterate(1, collect); e != nil {
		return nil, e
	}
	if e := env.service.Iterate(1, collect); e != nil {
		return nil, e
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// tick is one observation pass. Order: startup (once), clock, tip, canary,
// tracker (queued track records first, then a poll only if they were all
// written: new track records + conflict alerts; a backlog alert while they
// cannot be written), uncertain records, journal high-water, float, seals. Every step runs even if an earlier one failed.
// The first failure of a safety step (tip, canary, tracker, journals) is
// returned; a float or grant read failure shows only in the projection
// (float "unknown", seal "unknown", grant omitted) and never fails the pass,
// so a status-only fault cannot block startup. A spent canary poisons.
func (r *px1Runtime) tick(ctx context.Context, env px1oEnv) error {
	if e := r.validEnv(env); e != nil {
		return e
	}
	if r.failed != "" {
		env.poison()
		return fail(r.failed)
	}
	if !r.ready {
		if e := r.start(ctx, env); e != nil {
			return e
		}
	}
	var first error
	keep := func(e error) {
		if e != nil && first == nil {
			first = e
		}
	}
	now := env.now
	// Clock: a wall clock below either journal's last_time is a rollback.
	last := max(env.service.Usage().LastTime, env.wallet.Usage().LastTime)
	if now < last {
		if !r.clockBack {
			r.raise(AlertClockRollback, max(now, 0), CodeClockRollback)
		}
		r.clockBack = true
	} else {
		r.clockBack = false
	}
	tip, e := px1oReadTip(ctx, env.observer)
	keep(e)
	if e == nil {
		r.tip = StatusTip{Height: tip.Height, Hash: tip.Hash, ObservedAt: now}
	}
	// Canary: spent poisons; unknown is recorded and never read as unspent.
	state, e := r.canary.Check(ctx)
	keep(e)
	if state != CanaryUnspent && state != CanarySpent {
		state = CanaryUnknown
	}
	if state == CanarySpent || r.canaryLast.State == CanarySpent {
		env.poison()
		if r.canaryLast.State != CanarySpent {
			op := env.profile.Canary.Outpoint
			r.raise(AlertCanarySpent, now, op.TxID+":"+px1oItoa(int64(op.Vout)))
		}
	}
	if r.canaryLast.State != CanarySpent {
		r.canaryLast.State = state
	}
	r.canaryLast.At = now
	// Tracker: each transition becomes a wallet-layer track record. The
	// tracker commits its state when it returns a transition, so the runtime
	// owns every returned transition until its record is durable, and never
	// discards one (except for a fully released or unbound request, see
	// appendTracks). Order: the queued, undurable transitions are retried
	// first; only when they have all been written is the tracker polled, its
	// transitions queued (the conflict alert is raised once, on observation)
	// and written. A refused append (for example CLOCK_ROLLBACK) keeps the
	// refused transition and every later one queued, and the tracker is not
	// polled again until the queue drains (backpressure). The queue therefore
	// never holds more than one Tick's transitions: the tracker returns at
	// most one per tracked payment, and it tracks at most px1oMaxTracked.
	var stalled error
	write := func() {
		e := r.appendTracks(env)
		keep(e)
		if len(r.tracks) > 0 {
			stalled = e
		}
	}
	if len(r.tracks) > 0 {
		write()
	}
	if len(r.tracks) == 0 {
		r.backlog = false
		transitions, e := r.tracker.Tick(ctx)
		keep(e)
		if e == nil && len(transitions) > 0 {
			for _, t := range transitions {
				if t.Record.State == TrackConflicted {
					r.raise(AlertPaymentConflicted, now, t.Payment.TxID)
				}
			}
			r.tracks = append(r.tracks, transitions...)
			write()
		}
	}
	// Backlog: once per episode in which observations could not be made
	// durable, an alert from the closed set names the cause: a clock refusal
	// raises ALERT_CLOCK_ROLLBACK, any other refusal ALERT_JOURNAL_HIGH_WATER
	// (the wallet journal takes no records); the detail is TRACK_BACKLOG.
	if len(r.tracks) > 0 && !r.backlog {
		r.backlog = true
		code := AlertJournalHighWater
		if stalled != nil && stalled.Error() == CodeClockRollback {
			code = AlertClockRollback
		}
		r.raise(code, now, px1oTrackBacklog)
	}
	// Uncertain verdicts: one alert per new uncertain record of either layer.
	keep(r.scanUncertain(env))
	// Journal high-water: once per upward crossing.
	usage := env.service.Usage()
	if usage.SpendCapacity > 0 && usage.Admitted*100 >= JournalAlertPercent*usage.SpendCapacity {
		if !r.highWater {
			r.raise(AlertJournalHighWater, now, px1oItoa(int64(usage.Admitted))+"."+px1oItoa(int64(usage.SpendCapacity)))
		}
		r.highWater = true
	} else {
		r.highWater = false
	}
	// Float: an alert on each entry into low or excess.
	reading, _ := r.float.Check(ctx)
	if reading.State != r.floatLast.State {
		switch reading.State {
		case "low":
			r.raise(AlertFloatLow, now, px1oItoa(reading.BalanceSat))
		case "excess":
			r.raise(AlertFloatExcess, now, px1oItoa(reading.BalanceSat))
		}
	}
	r.floatLast = reading
	// Seals and effective limits of every grant the journals name.
	keep(r.observeGrants(ctx, env, now))
	return first
}

// appendTracks writes the queued transitions in order, one track record
// each, and removes a transition only after its Append succeeded. The record
// repeats the request's binding fields from its reserve record (S2 validates
// them), carries the tracker observation, and never changes a debit. An
// Append refusal stops the pass and keeps that transition and every later
// one queued, so a retry writes each record exactly once and in order. A
// transition whose reserve record is missing or does not match can never be
// written: it is dropped and the pass refuses JOURNAL_SEGMENT. A request
// whose whole debit an operator released is closed: its observation is
// alert-only, so its transition is dropped without a record (the journal
// table has no track after a full release).
func (r *px1Runtime) appendTracks(env px1oEnv) error {
	reserves := map[uint64]JournalRecordV2{}
	released := map[uint64]int64{}
	if e := env.wallet.Iterate(1, func(rec JournalRecordV2) error {
		if rec.Kind == RecordReserve {
			reserves[rec.Seq] = rec
		}
		if rec.Kind == RecordReconcile && rec.Reconcile != nil {
			released[rec.Reconcile.TargetSeq] += rec.Reconcile.ReleasedSat
		}
		return nil
	}); e != nil {
		return e
	}
	var unbound error
	for len(r.tracks) > 0 {
		t := r.tracks[0]
		reserve, ok := reserves[t.Payment.ReserveSeq]
		if !ok || reserve.GrantID != t.Payment.GrantID || reserve.Nonce != t.Payment.Nonce || reserve.TxID != t.Payment.TxID {
			r.tracks = r.tracks[1:]
			unbound = fail(CodeJournalSegment)
			continue
		}
		if released[reserve.Seq] >= reserve.Reserved {
			r.tracks = r.tracks[1:]
			continue
		}
		track := t.Record
		rec := JournalRecordV2{Kind: RecordTrack, GrantID: reserve.GrantID, Nonce: reserve.Nonce, RequestHash: reserve.RequestHash, Action: reserve.Action, Phase: track.State,
			Reserved: reserve.Reserved, Fee: reserve.Fee, Day: reserve.Day, Inputs: append([]su.Point{}, reserve.Inputs...), TxID: reserve.TxID, Created: reserve.Created, LastTime: env.now, Track: &track}
		if _, e := env.wallet.Append(rec); e != nil {
			return e
		}
		r.tracks = r.tracks[1:]
	}
	if len(r.tracks) == 0 {
		r.tracks = nil
	}
	return unbound
}

// scanUncertain raises ALERT_UNCERTAIN_VERDICT once for each uncertain record
// appended since the previous pass (startup scans all): a wallet-layer
// uncertain record (detail: its txid) and a service-layer terminal record
// whose receipt verdict is uncertain (detail: the receipt's bounded reason
// code). One request can therefore raise one alert per layer.
func (r *px1Runtime) scanUncertain(env px1oEnv) error {
	e := env.wallet.Iterate(r.lastSeq+1, func(rec JournalRecordV2) error {
		if rec.Seq > r.lastSeq {
			r.lastSeq = rec.Seq
		}
		if rec.Kind == RecordUncertain {
			r.raise(AlertUncertainVerdict, env.now, rec.TxID)
		}
		return nil
	})
	if e != nil {
		return e
	}
	return env.service.Iterate(r.lastSvcSeq+1, func(rec JournalRecordV2) error {
		if rec.Seq > r.lastSvcSeq {
			r.lastSvcSeq = rec.Seq
		}
		if rec.Kind == RecordTerminal && rec.Service != nil && rec.Service.Receipt != nil && rec.Service.Receipt.Receipt.Verdict == "uncertain" {
			reason := rec.Service.Receipt.Receipt.Reason
			if !boundedCode(reason) {
				reason = "SERVICE_FAILURE"
			}
			r.raise(AlertUncertainVerdict, env.now, reason)
		}
		return nil
	})
}

func (r *px1Runtime) observeGrants(ctx context.Context, env px1oEnv, now int64) error {
	ids, e := px1oGrantIDs(env)
	if e != nil {
		return e
	}
	if r.seals == nil {
		r.seals = map[string]StatusSealCheck{}
	}
	if r.limits == nil {
		r.limits = map[string]EffectiveLimits{}
	}
	for _, id := range ids {
		if _, ok := r.limits[id]; !ok && env.limitsFor != nil {
			// Grants and terms are hash-addressed and immutable: cache once.
			// A grant whose limits cannot be computed is left out of the
			// projection and retried on the next pass.
			if l, e := env.limitsFor(id); e == nil && l.GrantID == id {
				r.limits[id] = l
			}
		}
		if env.sealFor == nil {
			continue
		}
		seal := px1oSealVerdict(env.sealFor(ctx, id))
		seal.Height, seal.At = r.tip.Height, now
		if seal.Verdict == "closed" && r.seals[id].Verdict != "closed" {
			r.raise(AlertSealClosed, now, id)
		}
		r.seals[id] = seal
	}
	return nil
}

// enqueue hands a complete payment to the tracker. Before the first pass the
// tracker does not exist yet; the payment's complete record is already
// durable, so the startup fold of the wallet journal picks it up.
func (r *px1Runtime) enqueue(p TrackedPayment) error {
	if r.failed != "" {
		return fail(r.failed)
	}
	if !r.ready {
		return nil
	}
	return r.tracker.Enqueue(p)
}

// status projects the journals and the cached observations; no node call.
func (r *px1Runtime) status(env px1oEnv) (StatusProjectionV1, error) {
	if e := r.validEnv(env); e != nil {
		return StatusProjectionV1{}, e
	}
	limits := make([]EffectiveLimits, 0, len(r.limits))
	for _, l := range r.limits {
		limits = append(limits, l)
	}
	tracked := []TrackedPayment{}
	if r.tracker != nil {
		tracked = r.tracker.Snapshot()
	}
	canary := r.canaryLast
	if !r.ready {
		canary = StatusCanary{Outpoint: env.profile.Canary.Outpoint, ValueSat: env.profile.Canary.ValueSat, State: CanaryUnknown}
	}
	floatReading := r.floatLast
	if !r.ready {
		floatReading = FloatReading{MaxFloatSat: env.profile.MaxFloatSat, LowFloatSat: env.profile.LowFloatSat, State: "unknown"}
	}
	seals := map[string]StatusSealCheck{}
	for id, s := range r.seals {
		seals[id] = s
	}
	return ProjectStatus(StatusInputs{Service: env.service, Wallet: env.wallet, Limits: limits, Seals: seals, Tip: r.tip, Tracked: tracked, Float: floatReading, Canary: canary,
		Alerts: append([]Alert{}, r.alerts...), ReceiptKey: env.receiptKey, Network: env.network, Poisoned: env.poisoned || r.failed != "" || r.canaryLast.State == CanarySpent, Now: env.now})
}

// ---------------------------------------------------------------------------
// ActionService seams (frozen in px1_seams_api.go).

// px1oState returns this service's S3 runtime: the single field
// `px1 px1Runtime` that S2 adds to ActionService in service.go (cross-stream
// request S3-R1, bound at integration). The zero runtime is ready to use: the
// first PX1Tick builds the observers, and until a pass succeeds px1oHalted
// refuses SERVICE_STATE_UNAVAILABLE (fail closed).
func (s *ActionService) px1oState() *px1Runtime { return &s.px1 }

// px1oHalted is the G2 admission halt check that S2 calls in handleG2 before
// a spend, with ActionService.mu held (cross-stream request S2 To S3 #1). It
// returns "" or the bounded refusal code for the spend. No node call, no
// journal write. Unbound runtime: PX1_NOT_IMPLEMENTED (fail closed).
func (s *ActionService) px1oHalted() string {
	r := s.px1oState()
	if r == nil {
		return ErrNotImplemented.Error()
	}
	return r.halted()
}

// halted maps the runtime's observation state to an admission refusal:
//   - a sticky startup refusal keeps its code (STATE_RECONCILE_REQUIRED);
//   - a canary ever observed spent refuses FLOAT_CANARY_SPENT (T14);
//   - before the first successful pass, or while the last canary read is
//     unknown, SERVICE_STATE_UNAVAILABLE: unknown is never read as unspent;
//   - otherwise "" (admission continues to the cap checks).
func (r *px1Runtime) halted() string {
	switch {
	case r.failed != "":
		return r.failed
	case r.canaryLast.State == CanarySpent:
		return CodeFloatCanarySpent
	case !r.ready || r.canaryLast.State != CanaryUnspent:
		return "SERVICE_STATE_UNAVAILABLE"
	}
	return ""
}

// px1Observer is the S3 observers' own-node client: the wallet's observer node,
// with getrawtransaction on the transaction lookup route when the wallet has
// one (OpenWallet always builds it).
func (w *Wallet) px1Observer() su.Node {
	if w.txLookup == nil {
		return w.node
	}
	return px1ObserverNode{Node: w.node, tx: w.txLookup}
}

// px1oEnvFor assembles one pass's view of the service. Caller holds s.mu and
// s.wallet.mu, in that order.
func (s *ActionService) px1oEnvFor() (px1oEnv, error) {
	profile := s.PX1Profile()
	if profile == nil {
		return px1oEnv{}, fail("SERVICE_PROFILE")
	}
	w := s.wallet
	env := px1oEnv{profile: profile, service: s.PX1ServiceJournal(), wallet: w.PX1Journal(), observer: w.px1Observer(), walletRoute: w.wallet, receiptKey: s.pub, network: w.config.Network,
		now: s.clock(), poisoned: s.poisoned, poison: func() { s.poisoned = true }}
	env.limitsFor = func(id string) (EffectiveLimits, error) {
		raw, e := LoadGrant(w.config, id)
		if e != nil {
			return EffectiveLimits{}, e
		}
		g, e := w.Grant(raw)
		if e != nil {
			return EffectiveLimits{}, e
		}
		termsRaw, e := LoadTerms(w.config, g)
		if e != nil {
			return EffectiveLimits{}, e
		}
		terms, e := ParseTermsV2(termsRaw, TermsV2Pins{Network: w.config.Network, Genesis: w.config.Genesis, ExecutorKey: s.pub, GrantBudget: g.Budget})
		if e != nil {
			return EffectiveLimits{}, e
		}
		return EffectiveLimitsFor(g, terms, *profile)
	}
	env.sealFor = func(ctx context.Context, id string) error {
		raw, e := LoadGrant(w.config, id)
		if e != nil {
			return e
		}
		g, e := w.Grant(raw)
		if e != nil {
			return e
		}
		return w.authority.Check(ctx, raw, g.Grantee, env.now)
	}
	return env, nil
}

// PX1Enqueue registers a complete payment with the tracker. S2 calls it at
// step 23 with ActionService.mu held, so it takes no lock.
func (s *ActionService) PX1Enqueue(p TrackedPayment) error {
	r := s.px1oState()
	if r == nil {
		return ErrNotImplemented
	}
	return r.enqueue(p)
}

// PX1Tick runs one observation pass under ActionService.mu then Wallet.mu.
func (s *ActionService) PX1Tick(ctx context.Context) error {
	r := s.px1oState()
	if r == nil {
		return ErrNotImplemented
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wallet.mu.Lock()
	defer s.wallet.mu.Unlock()
	env, e := s.px1oEnvFor()
	if e != nil {
		return e
	}
	return r.tick(ctx, env)
}

// PX1Status returns the status projection; no node call, no journal write.
func (s *ActionService) PX1Status() (StatusProjectionV1, error) {
	r := s.px1oState()
	if r == nil {
		return StatusProjectionV1{}, ErrNotImplemented
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wallet.mu.Lock()
	defer s.wallet.mu.Unlock()
	env, e := s.px1oEnvFor()
	if e != nil {
		return StatusProjectionV1{}, e
	}
	return r.status(env)
}

// px1oTickLoop drives tick every interval until ctx ends, reporting each
// failure as one bounded code line. It is the agent-walletd tick loop.
func px1oTickLoop(ctx context.Context, every time.Duration, tick func(context.Context) error, report func(code string)) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// A pass holds the service lock: bound it by the interval.
			callCtx, cancel := context.WithTimeout(ctx, every)
			e := tick(callCtx)
			cancel()
			if e != nil && report != nil {
				report(safeCode(e))
			}
		}
	}
}

func px1oItoa(v int64) string { return strconv.FormatInt(max(v, 0), 10) }
