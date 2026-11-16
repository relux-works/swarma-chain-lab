package chaingateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// A collection is bound to protected configuration and to one request per reply.
// Raw middle replies pass canonical validation before any field is inspected.
type collectionAttempt struct {
	Before, After           map[string]any
	BeforeReply, AfterReply map[string]any
	Requests                []map[string]any
	Replies                 []map[string]any
	ReplyWires              []string
	Bestblocks              []string
	Failure                 error
}

func configuredReads(c Configuration) []map[string]any {
	out := []map[string]any{}
	for _, n := range c.Names {
		out = append(out, map[string]any{"method": "name_show", "params": map[string]any{"name": n}, "v": json.Number("1")})
	}
	for _, p := range c.Seals {
		out = append(out, map[string]any{"method": "gettxout", "params": map[string]any{"txid": p.Txid, "vout": json.Number(fmt.Sprint(p.Vout))}, "v": json.Number("1")})
	}
	return out
}
func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
func projectedReply(c Configuration, method string, value any, at map[string]any) map[string]any {
	return map[string]any{"method": method, "network": c.Network, "ok": true, "result": value, "tip": at, "v": json.Number("1")}
}
func assessCollection(c Configuration, a collectionAttempt, headers map[string]map[string]any) error {
	failure := a.Failure
	fail := func(e error) { failure = strongerFailure(failure, e) }
	wanted := map[string]bool{}
	for _, req := range configuredReads(c) {
		wanted[string(encoded(req))] = true
	}
	var first map[string]any
	remember := func(at map[string]any) {
		if tip(at) != nil {
			fail(bad("tip"))
			return
		}
		h := str(at["hash"])
		if old := headers[h]; old != nil && !equalTip(old, at) {
			fail(bad("inconsistent header"))
		}
		headers[h] = at
		if first == nil {
			first = at
		} else if first["hash"] != at["hash"] {
			fail(readFailure("tip_moved"))
		}
	}
	read := func(reply, req map[string]any) {
		if response(reply) != nil {
			fail(bad("response"))
			return
		}
		if reply["ok"] == false {
			fail(readFailure(str(reply["error"].(map[string]any)["code"])))
			return
		}
		if reply["network"] != c.Network || reply["method"] != req["method"] {
			fail(bad("correlation"))
		}
		params := req["params"].(map[string]any)
		result := reply["result"].(map[string]any)
		switch req["method"] {
		case "name_show":
			if params["name"] != result["name"] {
				fail(bad("name echo"))
			}
		case "gettxout":
			if params["txid"] != result["txid"] || params["vout"] != result["vout"] {
				fail(bad("outpoint echo"))
			}
		}
		remember(reply["tip"].(map[string]any))
	}
	bracketReq := map[string]any{"method": "getblockcount", "params": map[string]any{}}
	bracket := func(at, reply map[string]any) {
		if reply != nil {
			read(reply, bracketReq)
		} else if at != nil {
			remember(at)
		} else {
			fail(bad("missing bracket"))
		}
	}
	bracket(a.Before, a.BeforeReply)
	if a.BeforeReply != nil && a.BeforeReply["ok"] == false {
		return failure
	}
	replies := a.Replies
	if a.ReplyWires != nil {
		replies = nil
		for _, w := range a.ReplyWires {
			if validate("response", []byte(w)) != nil {
				fail(bad("wire"))
				replies = append(replies, nil)
			} else {
				m, _ := parse([]byte(w), 4096)
				replies = append(replies, m)
			}
		}
	}
	if len(replies) != len(a.Requests) {
		fail(bad("reply count"))
	}
	for i, req := range a.Requests {
		if request(req) != nil {
			fail(bad("request"))
			continue
		}
		key := string(encoded(req))
		if !wanted[key] {
			fail(bad("request set"))
		}
		delete(wanted, key)
		if i < len(replies) {
			read(replies[i], req)
		}
	}
	if len(wanted) != 0 {
		fail(bad("missing records"))
	}
	bracket(a.After, a.AfterReply)
	for _, h := range a.Bestblocks {
		if !hash(h) || first == nil {
			fail(bad("bestblock"))
		} else if h != first["hash"] {
			fail(readFailure("tip_moved"))
		}
	}
	return failure
}
func retryOutcome(e error, ordinal int) (int, time.Duration) {
	switch failureClass(e) {
	case "":
		return 0, 0
	case "tip_moved":
		if ordinal == 3 {
			return ExitTipMoved, 0
		}
		return -1, time.Duration(ordinal) * 100 * time.Millisecond
	case "rate_limited":
		if ordinal == 3 {
			return ExitNode, 0
		}
		return -1, time.Second
	default:
		return ExitNode, 0
	}
}

// The reservation is invocation-local: 512 initially full tokens, 128/s refill.
// The worker pool separately limits active RPCs to sixteen.
type rpcPacer struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newPacer() *rpcPacer { return &rpcPacer{tokens: 512, last: time.Now()} }
func (p *rpcPacer) take(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if p == nil {
		return nil
	}
	for {
		p.mu.Lock()
		now := time.Now()
		p.tokens = min(512, p.tokens+now.Sub(p.last).Seconds()*128)
		p.last = now
		if p.tokens >= 1 {
			p.tokens--
			p.mu.Unlock()
			return nil
		}
		delay := time.Duration((1 - p.tokens) / 128 * float64(time.Second))
		p.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
