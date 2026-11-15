package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: malformed RPC error envelopes remain retryable on all public routes without state writes, beside a genuine live grant and complete application-error controls.
func TestCoreMalformedRPCEnvelopeRetryable(t *testing.T) {
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	p := corePresentation(t, l.grant(peer, "rpc-envelope", l.seal(), true))
	info, now := coreTip(t, l)
	for _, status := range []int{200, 500, 503} {
		for _, tc := range []struct {
			name, body string
			code       Code
			closed     bool
			retry      bool
		}{
			{"missingResult", `{"id":1,"error":{"code":-4,"message":"name expired"}}`, CodeVerifierUnavailable, false, true},
			{"nonNullResult", `{"id":1,"result":"live","error":{"code":-4,"message":"name expired"}}`, CodeVerifierUnavailable, false, true},
			{"missingID", `{"result":null,"error":{"code":-4,"message":"name expired"}}`, CodeVerifierUnavailable, false, true},
			{"validApplication", `{"id":1,"result":null,"error":{"code":-8,"message":"invalid parameter"}}`, CodeCheckFailed, false, false},
		} {
			t.Run(fmt.Sprintf("%d/%s", status, tc.name), func(t *testing.T) {
				c := freshCoreChecker(t, l, l.observer, now, testFreshness(time.Minute, 2*time.Minute, info.Blocks), xonly(9))
				// Claim: the genuine live grant primes the cache before the response fault is introduced.
				assertVerdict(t, coreInbound(c, p), Live, CodeLive, false, false)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(status)
					_, _ = w.Write([]byte(tc.body))
				}))
				defer server.Close()
				host, port, err := net.SplitHostPort(server.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				number, err := strconv.Atoi(port)
				if err != nil {
					t.Fatal(err)
				}
				rpc, err := su.NewRPC(su.Route{Host: host, Port: number, Username: "w3-observer", Password: "regtest-fixture-only"})
				if err != nil {
					t.Fatal(err)
				}
				// Only name reads use the response seam; all chain observations remain genuine Core.
				c.node.Node = nodeFunc(func(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
					if method == "name_show" {
						return rpc.Call(ctx, method, args...)
					}
					return l.observer.Call(ctx, method, args...)
				})
				for _, call := range []func() Verdict{
					func() Verdict {
						return c.InboundFrom(context.Background(), SenderProof{SwarmEnvelopeV2, peer.PubKeyHex()}, &p)
					},
					func() Verdict {
						return c.InboundFrom(context.Background(), SenderProof{SwarmEnvelopeV2, peer.PubKeyHex()}, nil)
					},
					func() Verdict {
						return c.OutboundFrom(context.Background(), RecipientProof{SwarmEnvelopeV2, []string{peer.PubKeyHex()}})
					},
				} {
					before, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
					if err != nil {
						t.Fatal(err)
					}
					v := call()
					assertVerdict(t, v, Refused, tc.code, tc.closed, tc.retry)
					decision, reason, retry := v.A2ADecision()
					wantReason := "dependency_unavailable"
					if !tc.retry {
						wantReason = "policy_error"
					}
					if decision != "refused" || reason != wantReason || retry != tc.retry {
						t.Fatalf("RPC envelope route classification: %s/%s/%v", decision, reason, retry)
					}
					// Claim: malformed failures preserve the complete durable checker state.
					if tc.retry {
						after, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
						if err != nil || !bytes.Equal(before, after) {
							t.Fatal("malformed envelope wrote checker state")
						}
					}
				}
			})
		}
	}
}

// Claim: genuine Core expiry of either current identity closes outbound, inbound and cached re-check by name beside live, same-value renewal and stopped-node controls.
func TestCoreIdentityExpired(t *testing.T) {
	for _, expiredName := range []string{e2eAgentName, e2eLandlordName} {
		t.Run(expiredName, func(t *testing.T) {
			agent, err := nostr.GeneratePrivKey()
			if err != nil {
				t.Fatal(err)
			}
			peer, err := nostr.GeneratePrivKey()
			if err != nil {
				t.Fatal(err)
			}
			l := newCoreLab(t, agent.PubKeyHex())
			p := corePresentation(t, l.grant(peer, "identity-expiry", l.seal(), true))
			info, now := coreTip(t, l)
			c := freshCoreChecker(t, l, l.observer, now, testFreshness(time.Minute, 2*time.Minute, info.Blocks), xonly(9))
			ctx := context.Background()
			sender := SenderProof{SwarmEnvelopeV2, peer.PubKeyHex()}
			recipient := RecipientProof{SwarmEnvelopeV2, []string{peer.PubKeyHex()}}
			routes := func(code Code, closed, retry bool) {
				t.Helper()
				for _, route := range []struct {
					name string
					call func() Verdict
				}{
					{"outbound", func() Verdict { return c.OutboundFrom(ctx, recipient) }},
					{"inbound", func() Verdict { return c.InboundFrom(ctx, sender, &p) }},
					{"re-check", func() Verdict { return c.InboundFrom(ctx, sender, nil) }},
				} {
					v := route.call()
					decision := Refused
					if code == CodeLive {
						decision = Live
					}
					assertVerdict(t, v, decision, code, closed, retry)
					if code == CodeIdentityExpired {
						verdict, reason, again := v.A2ADecision()
						if verdict != "refused" || reason != "identity_expired" || again {
							t.Fatalf("%s unnamed expiry: %s/%s/%v", route.name, verdict, reason, again)
						}
					}
				}
			}
			// Claim: the same genuine issued grant is live before name expiry on every route.
			assertVerdict(t, coreInbound(c, p), Live, CodeLive, false, false)
			routes(CodeLive, false, false)
			read := func(name string) su.NameView {
				var n su.NameView
				if err := json.Unmarshal(l.rpc("", "name_show", name, map[string]any{"allowExpired": true}), &n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			l.mine(int(read(expiredName).ExpiresIn) - 2)
			// Claim: same-value name_update renewals extend lifetime without revoking the same grant.
			for _, name := range []string{e2eAgentName, e2eLandlordName} {
				n := read(name)
				l.rpc("issuer", "name_update", name, n.Value)
			}
			l.mine(1)
			routes(CodeLive, false, false)
			remaining := read(expiredName).ExpiresIn
			l.mine(int(remaining) - 2)
			other := e2eAgentName
			if expiredName == other {
				other = e2eLandlordName
			}
			l.rpc("issuer", "name_update", other, read(other).Value)
			l.mine(1)
			routes(CodeLive, false, false)
			// Claim: crossing the real name expiry boundary refuses the expired role while the other role remains live.
			l.mine(2)
			if !read(expiredName).Expired || read(other).Expired {
				t.Fatal("missing selective expiry witness")
			}
			_, err = l.observer.Call(ctx, "name_show", expiredName)
			var application *su.RPCError
			if !errors.As(err, &application) {
				t.Fatalf("missing Core RPC error: %v", err)
			}
			if !application.NameExpired() {
				t.Fatalf("Core expiry RPC code=%d message=%q", application.Code, application.Message)
			}
			// Claim: the public observation wrapper preserves the genuine application error instead of blanketing it as node-down.
			observation := su.NewReadObservation(ctx, l.observer)
			var raw json.RawMessage
			err = observation.Call("name_show", &raw, expiredName)
			observation.Close()
			if !errors.As(err, &application) || !application.NameExpired() {
				t.Fatalf("missing Core RPC error: %v", err)
			}
			routes(CodeIdentityExpired, true, false)
			// Claim: a stopped genuine node still yields retryable verifier_unavailable on each route.
			l.stop()
			routes(CodeVerifierUnavailable, false, true)
		})
	}
}
