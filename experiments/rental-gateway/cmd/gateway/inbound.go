package main

import (
	"context"
	"sync"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// A fixed worker pool keeps station startup and kernel calls off the relay's
// ACK pump. Saturation drops events without acknowledging gateway delivery;
// no per-event goroutine or unbounded pending work is created.
type inboundQueue struct {
	ctx     context.Context
	cancel  context.CancelFunc
	events  chan *nostr.Event
	workers sync.WaitGroup
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
		return true
	default:
		return false
	}
}
func (q *inboundQueue) close() { q.cancel(); q.workers.Wait() }
