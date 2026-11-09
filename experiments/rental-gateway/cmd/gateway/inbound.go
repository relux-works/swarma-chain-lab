package main

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// A fixed worker pool keeps station startup and kernel calls off the relay's
// ACK pump. Saturation drops events without acknowledging gateway delivery;
// no per-event goroutine or unbounded pending work is created.
type inboundQueue struct {
	ctx         context.Context
	cancel      context.CancelFunc
	events      chan *nostr.Event
	workers     sync.WaitGroup
	admitted    atomic.Uint64
	droppedFull atomic.Uint64
}

func newInbound(parent context.Context, capacity int, handle func(context.Context, *nostr.Event)) *inboundQueue {
	ctx, cancel := context.WithCancel(parent)
	q := &inboundQueue{ctx: ctx, cancel: cancel, events: make(chan *nostr.Event, capacity)}
	for range 4 {
		q.workers.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case ev := <-q.events:
					if ctx.Err() != nil {
						return
					}
					handle(ctx, ev)
				}
			}
		})
	}
	return q
}
func (q *inboundQueue) offer(ev *nostr.Event) bool {
	if ev == nil || q.ctx.Err() != nil {
		return false
	}
	select {
	case q.events <- ev:
		q.admitted.Add(1)
		return true
	default:
		q.droppedFull.Add(1)
		return false
	}
}
func (q *inboundQueue) close() { q.cancel(); q.workers.Wait() }

// Counters are process-local totals. Each field is sampled independently;
// queue depth is instantaneous, not a count of completed gateway deliveries.
type inboundStatus struct {
	Kind        string `json:"kind"`
	Admitted    uint64 `json:"admitted"`
	DroppedFull uint64 `json:"dropped_full"`
	Queued      int    `json:"queued"`
	Capacity    int    `json:"capacity"`
	WorkerLimit int    `json:"worker_limit"`
}

func (q *inboundQueue) status() inboundStatus {
	return inboundStatus{"inbound_status", q.admitted.Load(), q.droppedFull.Load(), len(q.events), cap(q.events), 4}
}

// Status output never runs on the relay ACK pump. Emit on startup, at the
// caller's fixed cadence, and on shutdown, regardless of incoming event volume.
func (q *inboundQueue) reportStatus(out io.Writer, ticks <-chan time.Time) {
	enc := json.NewEncoder(out)
	_ = enc.Encode(q.status())
	for {
		select {
		case <-q.ctx.Done():
			_ = enc.Encode(q.status())
			return
		case <-ticks:
			_ = enc.Encode(q.status())
		}
	}
}
