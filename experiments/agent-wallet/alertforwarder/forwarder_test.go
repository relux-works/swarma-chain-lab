package alertforwarder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

func fixture(t *testing.T) (Config, *durable.Store) {
	return fixtureAt(t, t.TempDir())
}
func fixtureAt(t *testing.T, root string) (Config, *durable.Store) {
	t.Helper()
	dir := filepath.Join(root, "state")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	store, e := durable.Open(dir, "forwarder.lock")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(store.Close)
	c := Config{JournalCommand: "/usr/bin/journalctl", A2ACommand: "/fixture/a2a", Identity: "host_alerts_orch", A2AConfigDir: filepath.Join(dir, "a2a"), Operator: Destination{"!operator:example.invalid", "$ops"}, OwnerDM: Destination{"!owner:example.invalid", "$dm"}, StateDir: dir, StartSince: "2026-11-13T00:00:00Z"}
	return c, store
}
func entry(cursor, unit, message string) string {
	b, _ := json.Marshal(map[string]string{"__CURSOR": cursor, "_SYSTEMD_UNIT": unit, "MESSAGE": message})
	return string(b) + "\n"
}

// Claim: only typed wallet-unit alerts are sent to BOTH exact configured
// destinations; unrelated log text/units never leave the host. Unknown details
// are redacted before the sender sees them; both ACKs precede cursor advancement.
func TestForwarderBothDestinations(t *testing.T) {
	c, store := fixture(t)
	saved := checkpoint{}
	var got []Destination
	var messages []string
	input := entry("1", "other.service", "PX1_ALERT code=ALERT_UNCERTAIN_VERDICT at=123 detail=secret-text") + entry("2", "swarma-wallet.service", "not an alert secret-text") + entry("3", "swarma-wallet.service", "PX1_ALERT code=ALERT_UNCERTAIN_VERDICT at=123 detail=secret-text")
	e := consume(context.Background(), c, strings.NewReader(input), store, &saved, func(_ context.Context, _ Config, d Destination, m string) (string, error) {
		if saved.Cursor == "3" {
			t.Fatal("CURSOR_BEFORE_ACK")
		}
		got = append(got, d)
		messages = append(messages, m)
		return "$ack", nil
	})
	if e == nil || e.Error() != "FORWARDER_JOURNAL_EOF" || len(got) != 2 || got[0] != c.Operator || got[1] != c.OwnerDM || saved.Cursor != "3" || saved.InFlight != "" {
		t.Fatal("FORWARDER_TWO_AUDIENCES", saved, got, e)
	}
	for _, m := range messages {
		if strings.Contains(m, "secret-text") || !strings.HasSuffix(m, "detail=REDACTED") {
			t.Fatal("FORWARDER_DETAIL_LEAK", m)
		}
	}
}

// Claim: a missing second ACK retains UNKNOWN and the prior cursor; a restart
// refuses without resending either destination, including after the first ACK.
func TestForwarderUnknownNoResend(t *testing.T) {
	var c Config
	root := t.TempDir()
	t.Run("lost-second-ack", func(t *testing.T) {
		var store *durable.Store
		c, store = fixtureAt(t, root)
		saved := checkpoint{Cursor: "old"}
		n := 0
		input := entry("next", "swarma-wallet.service", "PX1_ALERT code=ALERT_UNCERTAIN_VERDICT at=123 detail=BROADCAST_UNCERTAIN")
		e := consume(context.Background(), c, strings.NewReader(input), store, &saved, func(context.Context, Config, Destination, string) (string, error) {
			n++
			if n == 2 {
				return "", errors.New("private transport diagnostics")
			}
			return "$first", nil
		})
		if e == nil || e.Error() != "FORWARDER_DELIVERY_UNKNOWN" || saved.Cursor != "old" || saved.InFlight != "next" || n != 2 {
			t.Fatal("FORWARDER_UNKNOWN_LOST", saved, e)
		}
		b, _ := store.Read("cursor.json", 16384)
		var persisted checkpoint
		json.Unmarshal(b, &persisted)
		if persisted.InFlight != "next" || len(persisted.Events) != 1 {
			t.Fatal("FORWARDER_ACK_NOT_PERSISTED")
		}
	}) // Cleanup releases the real lock before simulating a restart.
	path := filepath.Join(t.TempDir(), "config.json")
	raw, _ := json.Marshal(c)
	os.WriteFile(path, raw, 0600)
	if e := Run(context.Background(), path); e == nil || e.Error() != "FORWARDER_DELIVERY_UNKNOWN" {
		t.Fatal("FORWARDER_UNKNOWN_RETRIED", e)
	}
}

// Claim: malformed/oversized journal events and unsafe config/unknown alert codes
// refuse or are dropped, with nearby valid controls. No real journal/a2a traffic.
func TestForwarderInputs(t *testing.T) {
	c, store := fixture(t)
	if c.validate() != nil {
		t.Fatal("valid config")
	}
	for _, mut := range []func(*Config){func(c *Config) { c.OwnerDM = c.Operator }, func(c *Config) { c.Identity = "bad name" }, func(c *Config) { c.A2ACommand = "a2a" }, func(c *Config) { c.StartSince = "" }, func(c *Config) { c.OwnerDM.Topic = "slug" }} {
		changed := c
		mut(&changed)
		if changed.validate() == nil {
			t.Fatal("FORWARDER_CONFIG_ACCEPTED")
		}
	}
	if alert("PX1_ALERT code=ALERT_UNKNOWN at=123 detail=secret") != "" || alert("PX1_ALERT code=ALERT_UNCERTAIN_VERDICT at=123 detail=x\nsecret") != "" {
		t.Fatal("FORWARDER_UNTYPED_LEAK")
	}
	for _, input := range []string{"{}\n", "not-json\n", strings.Repeat("x", 32769) + "\n"} {
		n := 0
		e := consume(context.Background(), c, strings.NewReader(input), store, &checkpoint{}, func(context.Context, Config, Destination, string) (string, error) { n++; return "$bad", nil })
		if e == nil || e.Error() != "FORWARDER_JOURNAL" || n != 0 {
			t.Fatal("FORWARDER_BAD_JOURNAL_SENT", e)
		}
	}
	path := filepath.Join(t.TempDir(), "config")
	raw, _ := json.Marshal(c)
	os.WriteFile(path, raw, 0600)
	if _, e := Load(path); e != nil {
		t.Fatal(e)
	}
	os.Chmod(path, 0644)
	if _, e := Load(path); e == nil || e.Error() != "FORWARDER_CONFIG_FILE" {
		t.Fatal("FORWARDER_PUBLIC_CONFIG")
	}
}

// A test executable emulates only the supported CLI's publication ACK. It does
// not load an identity or access a room, credentials, the journal or the network.
func init() {
	if os.Getenv("F6_FORWARDER_CHILD") != "1" || len(os.Args) < 3 || os.Args[1] != "post" {
		return
	}
	if os.Getenv("F6_FORWARDER_BAD_ACK") == "1" {
		fmt.Fprint(os.Stderr, "private diagnostic must stay withheld")
		fmt.Print(`{"event_id":"$sent","room_id":"!wrong:example.invalid","topic_root":"$ops","reply_to":"$ops"}`)
		os.Exit(0)
	}
	fmt.Printf(`{"event_id":"$sent","room_id":%q,"topic_root":%q,"reply_to":%q}`, os.Args[2], os.Args[4], os.Args[4])
	os.Exit(0)
}

// Claim: real subprocess argv uses the fixed post/topic/json/stdin interface,
// validates the exact room/topic ACK, and withholds malformed remote diagnostics.
func TestForwarderCLIContract(t *testing.T) {
	c, _ := fixture(t)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	c.A2ACommand = exe
	t.Setenv("F6_FORWARDER_CHILD", "1")
	id, e := post(context.Background(), c, c.Operator, "typed public line")
	if e != nil || id != "$sent" {
		t.Fatal("FORWARDER_CLI_ACK", id, e)
	}
	t.Setenv("F6_FORWARDER_BAD_ACK", "1")
	id, e = post(context.Background(), c, c.Operator, "typed public line")
	if e == nil || e.Error() != "FORWARDER_DELIVERY_UNKNOWN" || id != "" {
		t.Fatal("FORWARDER_WRONG_ACK", id, e)
	}
}
