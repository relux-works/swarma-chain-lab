package signerservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	rental "relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type crashInput struct {
	Config               Config
	Read, Send           su.Route
	Store, Outbox, Stage string
	Item                 Item
}

// Actual child exits73 at the requested service persistence/signing boundary;
// this hook exists only in tests, never as a production environment switch.
func TestCrashChild(t *testing.T) {
	if os.Getenv("SG1_CRASH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	raw, e := os.ReadFile(os.Getenv("SG1_CRASH_INPUT"))
	if e != nil {
		t.Fatal(e)
	}
	var in crashInput
	if e = json.Unmarshal(raw, &in); e != nil {
		t.Fatal(e)
	}
	clear(raw)
	node, e := su.NewRPC(in.Read)
	if e != nil {
		t.Fatal(e)
	}
	broadcast, e := NewRPCBroadcast(in.Send, in.Read)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(in.Config.GrantKeyPath)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := nostr.PrivKeyFromBytes(b)
	clear(b)
	if e != nil {
		t.Fatal(e)
	}
	sink, e := NewS1Store(in.Store, signer, in.Config.Policy.Policy.IssuerPubkey, in.Config.Policy.Policy.AgentPubkey)
	if e != nil {
		t.Fatal(e)
	}
	x, e := Open(in.Config, V1Issuer{in.Config.Policy, node, in.Config.GrantKeyPath}, node, broadcast, sink)
	if e != nil {
		t.Fatal(e)
	}
	defer x.Close()
	x.boundary = func(stage string) {
		if stage == in.Stage {
			os.Exit(73)
		}
	}
	source, e := OpenFileSource(in.Outbox)
	if e != nil {
		t.Fatal(e)
	}
	if e = x.Pull(context.Background(), source, BookingSource, 500); e != nil {
		t.Fatal(e)
	}
	rows := x.Step(context.Background(), 500)
	t.Fatalf("crash boundary not reached: %s %+v", in.Stage, rows)
}
func (l *coreLab) renew() {
	p := l.cfg.Policy.Policy
	landlord, _ := rental.LandlordValue(rental.LandlordBinding{Grant: p.IssuerPubkey})
	agent, _ := rental.AgentBindingValue(rental.AgentBinding{Nostr: p.AgentPubkey, Landlord: p.LandlordName})
	l.rpc("lab", "name_update", p.LandlordName, landlord)
	l.rpc("lab", "name_update", p.AgentName, agent)
	l.mine(1)
}
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	m := map[string]string{}
	for _, v := range entries {
		if v.IsDir() || v.Name() == "rental.lock" {
			continue
		}
		b, e := os.ReadFile(filepath.Join(root, v.Name()))
		if e != nil {
			t.Fatal(e)
		}
		m[v.Name()] = hash(b)
	}
	return m
}

// Every real subprocess crash preserves the same booking/seal/funding binding.
// K1 complete records replay byte-identically; uncertainty before durable tx
// bytes refuses to sign again. Lost broadcast/store ACKs recover exact content.
func TestCoreCrashRecovery(t *testing.T) {
	l := newCore(t)
	ctx := context.Background()
	for _, stage := range []string{"intake_written", "reserved", "issuer_returned", "prepared", "signing_uncertain", "chain_signed", "signed", "broadcast_returned", "broadcast", "store_returned", "stored"} {
		t.Run(stage, func(t *testing.T) {
			l.renew()
			l.cfg.StateDir = dir(t)
			l.cfg.Policy.Policy.StateDir = dir(t)
			seal := l.fund("seal", 200000)
			fund := l.fund("funding", 2000000)
			item := l.item(stage, true)
			x := l.engine()
			if e := x.Enroll(ctx, []su.PlanInput{seal, fund}, 500); e != nil {
				t.Fatal(e)
			}
			x.Close()
			outbox := dir(t)
			appendItem(t, outbox, nil, item)
			in := crashInput{l.cfg, l.read, l.send, l.sink.url, outbox, stage, item}
			input := filepath.Join(l.private, "child-"+stage+".json")
			write(t, input, encode(in))
			childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestCrashChild$", "-test.v")
			cmd.Env = append(os.Environ(), "SG1_CRASH_CHILD=1", "SG1_CRASH_INPUT="+input)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			pid := cmd.Process.Pid
			e := cmd.Wait()
			exit, ok := e.(*exec.ExitError)
			if !ok || exit.ExitCode() != 73 {
				t.Fatalf("expected exit73 at %s: %v %s", stage, e, output.Bytes())
			}
			l.events = append(l.events, map[string]any{"crash_boundary": stage, "child_pid": pid, "exit": 73})
			before := snapshot(t, l.cfg.Policy.Policy.StateDir)
			x = l.engine()
			defer x.Close()
			source, e := OpenFileSource(outbox)
			if e != nil {
				t.Fatal(e)
			}
			if e = x.Pull(ctx, source, BookingSource, 500); e != nil {
				t.Fatal(e)
			}
			rows := x.Step(ctx, 500)
			if len(rows) != 1 {
				t.Fatal("intake recovery", rows)
			}
			if stage == "signing_uncertain" || stage == "chain_signed" {
				if rows[0].Reason != "SIGNING_UNCERTAIN" {
					t.Fatal("uncertainty signed again", rows)
				}
				r, e := x.readRecord(x.state.Operations[0])
				if e != nil || r.RawTx != "" {
					t.Fatal("uncertain bytes", e)
				}
			} else {
				if rows[0].Reason != "" || rows[0].Phase != "stored" {
					t.Fatal("recovery", stage, rows)
				}
			}
			if len(x.state.Operations) != 1 || x.state.Operations[0].Intent.BookingID != hash([]byte(stage)) {
				t.Fatal("double issuance")
			}
			r, e := x.readRecord(x.state.Operations[0])
			if e != nil {
				t.Fatal(e)
			}
			if r.Spec.Pool.Point != (rental.Point{TxID: seal.Point.TxID, Vout: seal.Point.Vout}) {
				t.Fatal("recovery changed seal")
			}
			if stage != "intake_written" && stage != "reserved" && !bytes.Equal(encode(before), encode(snapshot(t, l.cfg.Policy.Policy.StateDir))) {
				t.Fatal("K1 record changed on recovery")
			}
			l.save(fmt.Sprintf("crash-%s.json", stage), map[string]any{"stage": stage, "child_exit": 73, "result": rows[0], "operations": len(x.state.Operations), "seal": seal.Point, "issuer_records_preserved": stage != "intake_written" && stage != "reserved"})
		})
	}
}
