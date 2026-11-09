package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// Closer-facing operation errors. A retry with the same operation
// id returns the durable record; these distinguish why no new
// effect ran.
var (
	// ErrOperationConflict: a different operation id (or different
	// final-message content) for an operation kind that already has
	// a started/done record on the slot.
	ErrOperationConflict = errors.New("gateway: operation conflict")
	// ErrOperationUncertain: the effect may have happened but its
	// outcome could not be durably recorded. The caller must stop
	// and reconcile manually, never guess (M4b contract).
	ErrOperationUncertain = errors.New("gateway: operation outcome uncertain")
	// ErrOperationFailed: the recorded definitive failure of a
	// previous attempt with the same operation id.
	ErrOperationFailed = errors.New("gateway: operation previously failed")
)

// LookupOperation returns the durable result record for (slot,
// operation id): the closer's first move after an uncertain outcome.
func (g *Gateway) LookupOperation(slotID, opID string) (journal.OpRecord, bool) {
	return g.cfg.Journal.LookupOperation(slotID, opID)
}

// endSlotE is the error-returning slot-end core: durably mark ended
// (channel secret dies), stop the station session, notify the
// station queue, optionally DM the renter. Journal and driver
// errors are returned, never swallowed.
func (g *Gateway) endSlotE(ctx context.Context, slotID, reason, renterDM string) error {
	slot, ok := g.cfg.Journal.Get(slotID)
	if !ok {
		return fmt.Errorf("gateway: no slot %s", slotID)
	}
	if err := g.cfg.Journal.MarkEnded(slotID, reason); err != nil {
		return err
	}
	st, endErr := g.recoverStation(ctx, slot)
	if endErr == nil && st != nil {
		endErr = g.cfg.Driver.End(ctx, st, reason)
	}
	q := g.queueFor(slotID)
	select {
	case q <- &stationlink.Frame{Type: stationlink.TypeEnd, SlotID: slotID, Reason: reason}:
	default:
	}
	if renterDM != "" {
		fresh, _ := g.cfg.Journal.Get(slotID)
		_ = g.dmRenter(ctx, fresh, renterDM)
	}
	return endErr
}

// EndSlot ends a slot's session as a recorded closer operation.
// Repeating it with the same opID returns the recorded result and
// performs nothing; a crash-leftover started record is completed
// on retry (ending an ended session is a no-op).
func (g *Gateway) EndSlot(ctx context.Context, slotID, opID, reason string) (journal.OpRecord, error) {
	if reason == "" {
		reason = "closer_end"
	}
	return g.runOperation(ctx, slotID, journal.OpEndSlot, opID, reason,
		func(ctx context.Context, slot *journal.Slot, rec journal.OpRecord) ([]string, []string, error) {
			if slot.Destroyed {
				return nil, nil, fmt.Errorf("gateway: slot %s destroyed", slotID)
			}
			return nil, nil, g.endSlotE(ctx, slotID, reason, "")
		})
}

// SendFinalMessage delivers the closer's end-of-slot message as a
// recorded operation. The exact gift-wrap event is built once and
// persisted (id + bytes + content hash) before the first publish;
// any retry with the same opID re-publishes that identical event
// (relays and renters dedup by event id) and can never produce a
// second, different message. Different content under the same opID
// (or a new opID once a final message is started/done) conflicts.
// It is the one deliberate exemption from the live-grant outbound
// rule: it is the end-of-slot notice to the grantee of record, and
// it is refused after Destroy so end -> final -> destroy is
// enforceable.
func (g *Gateway) SendFinalMessage(ctx context.Context, slotID, opID, content string) (journal.OpRecord, error) {
	if content == "" {
		return journal.OpRecord{}, fmt.Errorf("gateway: empty final message")
	}
	sum := sha256.Sum256([]byte(content))
	contentSHA := hex.EncodeToString(sum[:])
	if existing, found := g.LookupOperation(slotID, opID); found &&
		existing.ContentSHA256 != "" && existing.ContentSHA256 != contentSHA {
		return existing, ErrOperationConflict
	}
	rec, err := g.runOperation(ctx, slotID, journal.OpFinalMessage, opID, "",
		func(ctx context.Context, slot *journal.Slot, rec journal.OpRecord) ([]string, []string, error) {
			if slot.Destroyed {
				return nil, nil, fmt.Errorf("gateway: slot %s destroyed: final message must precede destroy", slotID)
			}
			// Build + persist the exact event before first publish.
			if rec.EventB64 == "" {
				wrap, _, err := nostr.WrapDM(g.cfg.AgentKey, slot.RenterPubKey, content, nil, g.cfg.Now().Unix())
				if err != nil {
					return nil, nil, err
				}
				raw, err := json.Marshal(wrap)
				if err != nil {
					return nil, nil, err
				}
				rec, err = g.cfg.Journal.AttachOperationEvent(slotID, opID,
					wrap.ID, base64.StdEncoding.EncodeToString(raw), contentSHA, g.cfg.Now().Unix())
				if err != nil {
					return nil, nil, fmt.Errorf("%w: persist final event: %v", ErrOperationUncertain, err)
				}
			} else if rec.ContentSHA256 != contentSHA {
				return nil, nil, ErrOperationConflict
			}
			raw, err := base64.StdEncoding.DecodeString(rec.EventB64)
			if err != nil {
				return nil, nil, err
			}
			ev, err := nostr.ParseEvent(raw)
			if err != nil {
				return nil, nil, err
			}
			if err := g.cfg.Publisher.Publish(ctx, ev); err != nil {
				return nil, nil, err
			}
			return nil, nil, nil
		})
	if err == nil && rec.ContentSHA256 != "" && rec.ContentSHA256 != contentSHA {
		return rec, ErrOperationConflict
	}
	return rec, err
}

// DestroySlot ends and destroys the station as a recorded closer
// operation (token revoke + home/secret removal by the driver).
// It works after a gateway restart: the station handle is
// re-derived from durable journal facts (home, OS user, booking
// id) — never from a remembered PID. Repeating with the same opID
// returns the recorded report; a crash-leftover started record is
// completed on retry (teardown asserts already-gone as success).
func (g *Gateway) DestroySlot(ctx context.Context, slotID, opID string) (station.DestroyReport, journal.OpRecord, error) {
	rec, err := g.runOperation(ctx, slotID, journal.OpDestroy, opID, "destroyed",
		func(ctx context.Context, slot *journal.Slot, rec journal.OpRecord) ([]string, []string, error) {
			// End first (durable). Its error is superseded by a
			// successful Destroy below (station gone either way);
			// a failing Destroy returns its own error.
			_ = g.endSlotE(ctx, slotID, "destroyed", "")
			st, recoverErr := g.recoverStation(ctx, slot)
			if recoverErr != nil {
				return nil, nil, recoverErr
			}
			var report station.DestroyReport
			if st != nil {
				var derr error
				report, derr = g.cfg.Driver.Destroy(ctx, st)
				if derr != nil {
					return nil, nil, derr
				}
			} else {
				report = station.DestroyReport{Kept: append([]string(nil), station.KeptElsewhere...)}
			}
			g.mu.Lock()
			delete(g.stations, slotID)
			g.mu.Unlock()
			if err := g.cfg.Journal.MarkDestroyed(slotID); err != nil {
				return nil, nil, err
			}
			return report.Removed, report.Kept, nil
		})
	if err != nil {
		return station.DestroyReport{}, rec, err
	}
	return station.DestroyReport{Removed: rec.Removed, Kept: rec.Kept}, rec, nil
}

// recoverStation gives remote drivers their own durable lookup. The local
// fallback preserves the existing home/user recovery without inventing paths.
func (g *Gateway) recoverStation(ctx context.Context, slot *journal.Slot) (*station.Station, error) {
	g.mu.Lock()
	st := g.stations[slot.ID]
	g.mu.Unlock()
	if st != nil {
		return st, nil
	}
	spec := station.SlotSpec{SlotID: slot.ID, StationName: slot.StationName, BookingID: slot.BookingID}
	if remote, ok := g.cfg.Driver.(station.Recoverer); ok {
		recovered, err := remote.Reattach(ctx, spec)
		if err != nil {
			return nil, err
		}
		if recovered == nil || recovered.SlotID != slot.ID {
			return nil, station.ErrCleanupPending
		}
		st = recovered
	} else if slot.StationHome != "" {
		st = station.Reattach(spec, slot.StationHome, slot.StationUser)
	}
	if st != nil {
		g.mu.Lock()
		if existing := g.stations[slot.ID]; existing != nil {
			st = existing
		} else {
			g.stations[slot.ID] = st
		}
		g.mu.Unlock()
	}
	return st, nil
}

// opCall is one in-flight closer operation. Concurrent callers for
// the same (slot, op id) wait for the owner and return its recorded
// result instead of racing the effect (RM2-03 C1).
type opCall struct {
	done chan struct{}
	rec  journal.OpRecord
	err  error
}

// opEnter coalesces by (slot, kind, op id): the kind is part of
// the key so the same op id used for two different operation kinds
// never shares one call (RM2-04 F1).
func (g *Gateway) opEnter(slotID, kind, opID string) (key string, call *opCall, owner bool) {
	key = slotID + "\x00" + kind + "\x00" + opID
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if c, ok := g.inFlight[key]; ok {
		return key, c, false
	}
	c := &opCall{done: make(chan struct{})}
	if g.inFlight == nil {
		g.inFlight = map[string]*opCall{}
	}
	g.inFlight[key] = c
	return key, c, true
}

func (g *Gateway) opLeave(key string, call *opCall, rec journal.OpRecord, err error) {
	call.rec, call.err = rec, err
	g.opMu.Lock()
	delete(g.inFlight, key)
	g.opMu.Unlock()
	close(call.done)
}

// runOperation is the shared exactly-once skeleton: begin (durable
// started) -> effect -> complete/fail (durable). Existing done
// returns as-is; existing failed returns the recorded failure;
// existing started with no in-flight owner (crash leftover) resumes
// the effect (all three operation kinds are retry-completable by
// construction); a persist failure after the effect reports
// ErrOperationUncertain. Concurrent same-id callers are coalesced
// by opEnter above; different ids for one slot+kind are serialized
// by the journal's atomic conflict check.
func (g *Gateway) runOperation(ctx context.Context, slotID, kind, opID, reason string,
	effect func(ctx context.Context, slot *journal.Slot, rec journal.OpRecord) ([]string, []string, error),
) (rec journal.OpRecord, err error) {
	key, call, owner := g.opEnter(slotID, kind, opID)
	if !owner {
		// Waiters honour their own ctx (RM2-04 F2): a cancelled
		// waiter leaves without disturbing the owner.
		select {
		case <-call.done:
			return call.rec, call.err
		case <-ctx.Done():
			return journal.OpRecord{}, ctx.Err()
		}
	}
	defer func() { g.opLeave(key, call, rec, err) }()
	slot, ok := g.cfg.Journal.Get(slotID)
	if !ok {
		return journal.OpRecord{}, fmt.Errorf("gateway: no slot %s", slotID)
	}
	rec, beginState, err := g.cfg.Journal.BeginOperation(slotID, kind, opID, reason, g.cfg.Now().Unix())
	if errors.Is(err, journal.ErrOpConflict) {
		return rec, ErrOperationConflict
	}
	if err != nil {
		return journal.OpRecord{}, err
	}
	if beginState == journal.BeginExisting {
		switch rec.State {
		case journal.OpStateDone:
			return rec, nil
		case journal.OpStateFailed:
			return rec, fmt.Errorf("%w: %s", ErrOperationFailed, rec.Error)
		}
		// started: fall through and complete the effect on retry.
		slot, _ = g.cfg.Journal.Get(slotID)
	}
	removed, kept, effErr := effect(ctx, slot, rec)
	if effErr != nil {
		if errors.Is(effErr, station.ErrCleanupPending) {
			return rec, fmt.Errorf("%w: station cleanup pending", ErrOperationUncertain)
		}
		if errors.Is(effErr, ErrOperationConflict) || errors.Is(effErr, ErrOperationUncertain) {
			return rec, effErr
		}
		if _, ferr := g.cfg.Journal.FailOperation(slotID, opID, effErr.Error(), g.cfg.Now().Unix()); ferr != nil {
			return rec, fmt.Errorf("%w: %v (record failure: %v)", ErrOperationUncertain, effErr, ferr)
		}
		return rec, effErr
	}
	done, err := g.cfg.Journal.CompleteOperation(slotID, opID, removed, kept, g.cfg.Now().Unix())
	if err != nil {
		return rec, fmt.Errorf("%w: complete persist: %v", ErrOperationUncertain, err)
	}
	return done, nil
}
