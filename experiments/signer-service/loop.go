package signerservice

import (
	"context"
	"time"
)

// Pull persists every immutable intake item and the checkpoint in one ledger
// update. An orphan content blob is harmless; a cursor never skips an item
// that has not reached durable intake. No caller-supplied source flag is read
// from an item. Each service has exactly one configured source per class.
func (x *Engine) Pull(ctx context.Context, s Source, class SourceClass, now int64) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e := x.ready(now); e != nil {
		return e
	}
	if s == nil || (class != BookingSource && class != OperatorSource) {
		return fail("SOURCE_CONFIG")
	}
	batch, e := s.Pull(ctx, x.state.Cursors[class], MaxRecords)
	if e != nil {
		return e
	}
	if len(batch) > MaxRecords {
		return fail("PULL_BOUND")
	}
	next := cloneState(x.state)
	writes := map[string][]byte{}
	for _, p := range batch {
		var v Item
		if strict(p.Raw, &v) != nil || !digest(v.ID) || p.After == "" || len(p.After) > 2048 {
			return fail("OUTBOX_ITEM")
		}
		exists := false
		for _, in := range next.Intake {
			if in.ID == v.ID {
				if in.Hash != hash(p.Raw) || in.Source != class {
					return fail("ITEM_CONFLICT")
				}
				exists = true
			}
		}
		if !exists {
			if len(next.Intake) >= MaxRecords {
				return fail("INTAKE_BOUND")
			}
			next.Intake = append(next.Intake, intake{v.ID, hash(p.Raw), class})
			writes[hash(p.Raw)] = p.Raw
		}
		next.Cursors[class] = p.After
	}
	if len(batch) == 0 {
		return nil
	}
	next.LastTime = now
	if len(encode(next)) > 65536 {
		return fail("LEDGER_FULL")
	}
	for h, b := range writes {
		if e = x.store.Write("item-"+h+".json", b); e != nil {
			x.poisoned = true
			return e
		}
	}
	x.at("intake_written")
	return x.commit(next)
}

// Step tries revokes first so a later sticky revoke cannot be hidden behind an
// earlier issuance that is still pending confirmation. Refusals stay available
// for retry; immutable intake is bounded and requires explicit archival later.
func (x *Engine) Step(ctx context.Context, now int64) []Result {
	x.mu.Lock()
	defer x.mu.Unlock()
	started := time.Now()
	results := []Result{}
	if e := x.ready(now); e != nil {
		return []Result{{Reason: e.Error()}}
	}
	for _, kind := range []string{"revoke", "grant-issue"} {
		for _, in := range x.state.Intake {
			raw, e := x.store.Read("item-"+in.Hash+".json", 65536)
			if e != nil || hash(raw) != in.Hash {
				results = append(results, Result{ID: in.ID, Reason: "INTAKE_CORRUPT"})
				continue
			}
			var v Item
			if strict(raw, &v) != nil {
				results = append(results, Result{ID: in.ID, Reason: "OUTBOX_ITEM"})
				continue
			}
			if v.Kind != kind {
				if kind == "revoke" && v.Kind != "grant-issue" {
					results = append(results, Result{ID: in.ID, Reason: "TEMPLATE_REFUSED"})
				}
				continue
			}
			r, e := x.process(ctx, raw, in.Source, now+int64(time.Since(started)/time.Second))
			if e != nil {
				r.Reason = e.Error()
			}
			r.ID = in.ID
			results = append(results, r)
		}
	}
	return results
}

type Sources struct {
	Booking  Source
	Operator Source
}

// Run is interruptible and never spawns a watcher. Result diagnostics contain
// closed codes and public operation IDs, never requests, credentials or keys.
func (x *Engine) Run(ctx context.Context, s Sources, interval time.Duration, report func(Result)) error {
	if interval < time.Second || interval > time.Hour || s.Booking == nil {
		return fail("LOOP_CONFIG")
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		now := time.Now().Unix()
		for _, entry := range []struct {
			source Source
			class  SourceClass
		}{{s.Booking, BookingSource}, {s.Operator, OperatorSource}} {
			if entry.source != nil {
				if e := x.Pull(ctx, entry.source, entry.class, now); e != nil {
					return e
				}
			}
		}
		for _, r := range x.Step(ctx, time.Now().Unix()) {
			if report != nil {
				report(r)
			}
		}
		r, e := x.Refill(ctx, time.Now().Unix())
		if e != nil {
			r.Reason = e.Error()
		}
		if report != nil {
			report(r)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}
