package payload

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// Actual TLS/HMAC sessions and the real model proxy are reopened at interrupted
// persistence/ACK boundaries. This is controlled fault injection, not a power-loss
// simulation. Replays retain the recorded answer and never repeat model work.
func TestTurnSessionRecovery(t *testing.T) { turnSessionRecovery(t, answer, answer) }

// The actual proxy returns maximum-size escaped/plain text. The station saves
// the bounded outcome before ready and reuses it after lost ACK/restart without
// another generation. Ready-write failure retains the existing uncertain rule.
func TestTurnWrappedSizeRecovery(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"html", strings.Repeat("<", 32768), "reply exceeded deliverable size"},
		{"quotes", strings.Repeat(`"`, 32768), "reply exceeded deliverable size"},
		{"plain", strings.Repeat("a", 32768), "reply exceeded deliverable size"},
		{"fitting", strings.Repeat("a", 24000), strings.Repeat("a", 24000)},
	} {
		t.Run(tc.name, func(t *testing.T) { turnSessionRecovery(t, tc.text, tc.want) })
	}
}
func turnSessionRecovery(t *testing.T, modelAnswer, expectedAnswer string) {
	for _, fault := range []string{"before-record", "receive-ack", "reply-ack", "ready-write", "changed-input"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t, modelAnswer)
			dir := root(t)
			id := strings.Repeat("d", 64)
			run := func(mode, input string) (error, string) {
				t.Helper()
				c, e := New(encoded(t, f.doc), Options{JournalDir: dir, Model: modelID, MaxTokens: 10, Roots: f.roots})
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				if mode == "ready-write" {
					transport := c.http.Transport
					c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
						res, e := transport.RoundTrip(r)
						if e == nil {
							if err := os.Chmod(dir, 0500); err != nil {
								return nil, err
							}
						}
						return res, e
					})
				}
				ln, e := tls.Listen("tcp", "127.0.0.1:0", f.front.TLS.Clone())
				if e != nil {
					t.Fatal(e)
				}
				defer ln.Close()
				type result struct {
					reply string
					err   error
				}
				done := make(chan result, 1)
				go func() {
					var output string
					script := func() error {
						conn, e := ln.Accept()
						if e != nil {
							return e
						}
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(5 * time.Second))
						read := func(want string) (*stationlink.Frame, error) {
							v, e := stationlink.ReadFrame(conn)
							if e != nil {
								return nil, e
							}
							if v.Type != want {
								return nil, fmt.Errorf("expected %s, got %s", want, v.Type)
							}
							return v, nil
						}
						send := func(v *stationlink.Frame) error { return stationlink.WriteFrame(conn, v) }
						hello, e := read(stationlink.TypeHello)
						if e != nil {
							return e
						}
						if hello.SlotID != f.doc.BookingID {
							return fmt.Errorf("hello slot")
						}
						nonce := strings.Repeat("e", 64)
						if e = send(&stationlink.Frame{Type: stationlink.TypeChallenge, Nonce: nonce}); e != nil {
							return e
						}
						auth, e := read(stationlink.TypeAuth)
						if e != nil {
							return e
						}
						if !stationlink.VerifyResponse(f.doc.ChannelSecret, nonce, f.doc.BookingID, f.doc.StationName, auth.Response) {
							return fmt.Errorf("auth")
						}
						if e = send(&stationlink.Frame{Type: stationlink.TypeSystem, RelayMaxEventBytes: 65536, SlotID: f.doc.BookingID}); e != nil {
							return e
						}
						if _, e = read(stationlink.TypePull); e != nil {
							return e
						}
						if mode == "before-record" {
							if e = os.Chmod(dir, 0500); e != nil {
								return e
							}
						}
						if e = send(&stationlink.Frame{Type: stationlink.TypeDeliver, SlotID: f.doc.BookingID, DeliveryID: id, Content: input}); e != nil {
							return e
						}
						received, e := read(stationlink.TypeReceived)
						if mode == "before-record" || mode == "changed-input" {
							if e == nil {
								return fmt.Errorf("ack escaped refused input")
							}
							return nil
						}
						if e != nil {
							return e
						}
						if received.DeliveryID != id {
							return fmt.Errorf("receive ID")
						}
						raw, e := os.ReadFile(filepath.Join(dir, "turn-"+id+".json"))
						if e != nil {
							return fmt.Errorf("ACK preceded durable input")
						}
						var saved turn
						if json.Unmarshal(raw, &saved) != nil || !validTurn(saved) || saved.Input != input {
							return fmt.Errorf("ACK preceded durable input")
						}
						if mode == "receive-ack" {
							return nil
						}
						if e = send(&stationlink.Frame{Type: stationlink.TypeAck, SlotID: f.doc.BookingID, DeliveryID: id}); e != nil {
							return e
						}
						reply, e := read(stationlink.TypeReply)
						if mode == "ready-write" {
							if e == nil {
								return fmt.Errorf("reply escaped failed durable result")
							}
							return nil
						}
						if e != nil {
							return e
						}
						if reply.DeliveryID != id {
							return fmt.Errorf("reply ID")
						}
						raw, e = os.ReadFile(filepath.Join(dir, "turn-"+id+".json"))
						if e != nil || json.Unmarshal(raw, &saved) != nil || !validTurn(saved) || saved.Reply != reply.Content || (saved.Phase != "ready" && saved.Phase != "accepted") {
							return fmt.Errorf("reply preceded durable ready outcome")
						}
						if reply.Content != expectedAnswer && reply.Content != TurnUncertain {
							return fmt.Errorf("station saved unwrappable ready reply")
						}
						output = reply.Content
						if mode == "reply-ack" {
							return nil
						}
						if e = send(&stationlink.Frame{Type: stationlink.TypeAck, SlotID: f.doc.BookingID, DeliveryID: id}); e != nil {
							return e
						}
						if _, e = read(stationlink.TypePull); e != nil {
							return e
						}
						return send(&stationlink.Frame{Type: stationlink.TypeEnd})
					}
					e := script()
					done <- result{output, e}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				runErr := c.Run(ctx, ln.Addr().String(), pin(f.front.Certificate()), f.roots)
				// Run can refuse before dialing. Release Accept before joining the peer,
				// so a startup regression reports its error instead of hanging the suite.
				ln.Close()
				var peer result
				select {
				case peer = <-done:
				case <-ctx.Done():
					t.Fatalf("script did not finish after client returned %v: %v", runErr, ctx.Err())
				}
				if peer.err != nil {
					t.Fatalf("script after client returned %v: %v", runErr, peer.err)
				}
				if e = os.Chmod(dir, 0700); e != nil {
					t.Fatal(e)
				}
				return runErr, peer.reply
			}
			first := fault
			if first == "changed-input" {
				first = "reply-ack"
			}
			err, firstReply := run(first, prompt)
			expected := error(ErrChannel)
			if fault == "before-record" || fault == "ready-write" {
				expected = ErrJournal
			}
			if err != expected {
				t.Fatalf("fault result %v, want %v", err, expected)
			}
			wantCalls := int32(1)
			if fault == "before-record" || fault == "receive-ack" {
				wantCalls = 0
			}
			if f.upstream.Load() != wantCalls {
				t.Fatal("fault retried or generated before durable receipt")
			}
			if fault == "changed-input" {
				before, e := os.ReadFile(filepath.Join(dir, "turn-"+id+".json"))
				if e != nil {
					t.Fatal(e)
				}
				if err, _ = run("changed-input", prompt+" changed"); err != ErrJournal {
					t.Fatal("changed input accepted", err)
				}
				after, e := os.ReadFile(filepath.Join(dir, "turn-"+id+".json"))
				if e != nil || string(before) != string(after) {
					t.Fatal("refusal changed durable state")
				}
			}
			want := expectedAnswer
			if fault == "ready-write" {
				want = TurnUncertain
			}
			for i := 0; i < 2; i++ {
				err, reply := run("normal", prompt)
				if err != nil || reply != want {
					t.Fatalf("recovery %v reply %q", err, reply)
				}
				if firstReply != "" && reply != firstReply {
					t.Fatal("recorded reply changed")
				}
				if f.upstream.Load() != 1 {
					t.Fatal("recovery regenerated or lost positive control")
				}
			}
		})
	}
}
