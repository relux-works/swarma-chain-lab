// Package alertforwarder adapts the wallet unit's typed journald alerts to the
// supported a2a CLI. It has no access to wallet state, RPC or receipt keys.
package alertforwarder

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	wallet "github.com/relux-works/swarma-chain-lab/experiments/agent-wallet"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type Destination struct {
	Room  string `json:"room"`
	Topic string `json:"topic"`
}
type Config struct {
	JournalCommand string      `json:"journal_command"`
	A2ACommand     string      `json:"a2a_command"`
	Identity       string      `json:"identity"`
	A2AConfigDir   string      `json:"a2a_config_dir"`
	Operator       Destination `json:"operator"`
	OwnerDM        Destination `json:"owner_dm"`
	StateDir       string      `json:"state_dir"`
	StartSince     string      `json:"start_since"`
}
type checkpoint struct {
	Cursor   string   `json:"cursor"`
	InFlight string   `json:"in_flight"`
	Stage    int      `json:"stage"`
	Events   []string `json:"events"`
}

func refusal(code string) error { return errors.New(code) }

var identity = regexp.MustCompile(`^[a-z0-9._=-]{1,64}$`)

func clean(s string) bool { return s != "" && len(s) <= 1024 && !strings.ContainsAny(s, "\x00\r\n\t ") }
func (c Config) validate() error {
	for _, p := range []string{c.JournalCommand, c.A2ACommand, c.A2AConfigDir, c.StateDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return refusal("FORWARDER_CONFIG")
		}
	}
	if !identity.MatchString(c.Identity) || c.Operator.Room == c.OwnerDM.Room {
		return refusal("FORWARDER_CONFIG")
	}
	for _, d := range []Destination{c.Operator, c.OwnerDM} {
		if !clean(d.Room) || !strings.HasPrefix(d.Room, "!") || !strings.Contains(d.Room, ":") || !clean(d.Topic) || !strings.HasPrefix(d.Topic, "$") {
			return refusal("FORWARDER_CONFIG")
		}
	}
	if _, e := time.Parse(time.RFC3339, c.StartSince); e != nil {
		return refusal("FORWARDER_CONFIG")
	}
	return nil
}
func Load(path string) (Config, error) {
	var c Config
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return c, refusal("FORWARDER_CONFIG_FILE")
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !durable.PrivateRegular(s) || s.Size() > 16384 {
		return c, refusal("FORWARDER_CONFIG_FILE")
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 || su.StrictInput(b, &c) != nil {
		return c, refusal("FORWARDER_CONFIG")
	}
	return c, c.validate()
}

// Run checkpoints only after both destinations ACK. A reserved send with a
// missing ACK is durable UNKNOWN, never an instruction to blindly resend.
// All subprocess output/errors are withheld; only closed local codes escape.
func Run(ctx context.Context, path string) error {
	c, e := Load(path)
	if e != nil {
		return e
	}
	store, e := durable.Open(c.StateDir, "forwarder.lock")
	if e != nil {
		return refusal("FORWARDER_STATE")
	}
	defer store.Close()
	var saved checkpoint
	b, e := store.Read("cursor.json", 16384)
	if e != nil {
		return refusal("FORWARDER_STATE")
	}
	if b != nil && (su.StrictInput(b, &saved) != nil || !validCheckpoint(saved)) {
		return refusal("FORWARDER_STATE")
	}
	if saved.InFlight != "" {
		return refusal("FORWARDER_DELIVERY_UNKNOWN")
	}
	args := []string{"--unit=swarma-wallet.service", "--follow", "--output=json", "--no-pager"}
	if saved.Cursor != "" {
		args = append(args, "--after-cursor="+saved.Cursor)
	} else {
		args = append(args, "--since="+c.StartSince)
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(child, c.JournalCommand, args...)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return refusal("FORWARDER_JOURNAL")
	}
	if e = cmd.Start(); e != nil {
		return refusal("FORWARDER_JOURNAL")
	}
	defer func() { cancel(); cmd.Wait() }()
	return consume(ctx, c, pipe, store, &saved, post)
}
func validCheckpoint(s checkpoint) bool {
	return s.Stage >= 0 && s.Stage <= 2 && len(s.Cursor) <= 4096 && len(s.InFlight) <= 4096 && len(s.Events) <= 2
}
func save(store *durable.Store, s *checkpoint) error {
	b, _ := json.Marshal(s)
	if store.Write("cursor.json", b) != nil {
		return refusal("FORWARDER_STATE")
	}
	return nil
}

type sender func(context.Context, Config, Destination, string) (string, error)

func consume(ctx context.Context, c Config, in io.Reader, store *durable.Store, saved *checkpoint, send sender) error {
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 4096), 32768)
	for scan.Scan() {
		var entry struct {
			Cursor  string `json:"__CURSOR"`
			Unit    string `json:"_SYSTEMD_UNIT"`
			Message string `json:"MESSAGE"`
		}
		if json.Unmarshal(scan.Bytes(), &entry) != nil || entry.Cursor == "" || len(entry.Cursor) > 4096 {
			return refusal("FORWARDER_JOURNAL")
		}
		if entry.Cursor == saved.Cursor {
			continue
		}
		message := ""
		if entry.Unit == "swarma-wallet.service" {
			message = alert(entry.Message)
		}
		if message != "" {
			saved.InFlight = entry.Cursor
			saved.Stage = 0
			saved.Events = nil
			for i, d := range []Destination{c.Operator, c.OwnerDM} {
				// Persist before each external effect. Any failure preserves UNKNOWN.
				saved.Stage = i
				if e := save(store, saved); e != nil {
					return e
				}
				id, e := send(ctx, c, d, message)
				if e != nil {
					return refusal("FORWARDER_DELIVERY_UNKNOWN")
				}
				saved.Events = append(saved.Events, id)
				if e = save(store, saved); e != nil {
					return e
				}
			}
		}
		saved.Cursor = entry.Cursor
		saved.InFlight = ""
		saved.Stage = 0
		saved.Events = nil
		if e := save(store, saved); e != nil {
			return e
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if scan.Err() != nil {
		return refusal("FORWARDER_JOURNAL")
	}
	return refusal("FORWARDER_JOURNAL_EOF")
}

var line = regexp.MustCompile(`^PX1_ALERT code=(ALERT_[A-Z_]+) at=([0-9]{1,12}) detail=([^\r\n]*)$`)

func alert(s string) string {
	m := line.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	var at int64
	if _, e := fmt.Sscan(m[2], &at); e != nil || at < 1 {
		return ""
	}
	out := ""
	wallet.NewLogAlertSink(func(v string) { out = v }).Raise(wallet.Alert{Code: m[1], At: at, Detail: m[3]})
	return out
}

type boundedOutput struct {
	b        []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.b)+n > 8192 {
		b.overflow = true
		return n, nil
	}
	b.b = append(b.b, p...)
	return n, nil
}
func post(ctx context.Context, c Config, d Destination, message string) (string, error) {
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, c.A2ACommand, "post", d.Room, "--topic", d.Topic, "--kind", "notice", "--json", "-")
	// Only the operator's explicitly provisioned infrastructure identity is used.
	cmd.Env = append(os.Environ(), "A2A_AGENT="+c.Identity, "A2A_CONFIG_DIR="+c.A2AConfigDir)
	cmd.Stdin = strings.NewReader(message)
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || out.overflow {
		return "", refusal("FORWARDER_DELIVERY_UNKNOWN")
	}
	var ack struct {
		Event string `json:"event_id"`
		Room  string `json:"room_id"`
		Topic string `json:"topic_root"`
		Reply string `json:"reply_to"`
	}
	if su.StrictInput(out.b, &ack) != nil || !clean(ack.Event) || !strings.HasPrefix(ack.Event, "$") || ack.Room != d.Room || ack.Topic != d.Topic || ack.Reply != d.Topic {
		return "", refusal("FORWARDER_DELIVERY_UNKNOWN")
	}
	return ack.Event, nil
}
