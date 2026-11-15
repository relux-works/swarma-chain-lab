package g2ledger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

type noControlRetry struct {
	*rollbackNode
	t *testing.T
}

func (n noControlRetry) Stop(string) error  { n.t.Fatal("noop retry issued stop"); return nil }
func (n noControlRetry) Start(string) error { n.t.Fatal("noop retry issued start"); return nil }

// Claim: a completed stopped rollback retries without control commands, config/metadata or journal writes, and names the noop after fresh readback.
func TestRollbackIdempotentStoppedRetry(t *testing.T) {
	for _, baseline := range []bool{false, true} {
		t.Run(fmt.Sprintf("baseline-running=%v", baseline), func(t *testing.T) {
			f, n := rollbackFixture(t, baseline)
			installRollbackConfig(t, f, n, true)
			n.readable = false
			must(t, f.l.Rollback("station", n))
			f.reopen(t)
			before, err := observe(n.config, "modify")
			must(t, err)
			content, err := os.ReadFile(n.config)
			must(t, err)
			rows := len(f.l.rows)
			calls := len(n.calls)
			var out bytes.Buffer
			f.l.output = &out
			must(t, f.l.Rollback("station", noControlRetry{n, t}))
			after, err := observe(n.config, "modify")
			must(t, err)
			got, err := os.ReadFile(n.config)
			must(t, err)
			if !bytes.Equal(content, got) || !identityEqual(*before, *after) || n.running || len(n.calls) != calls || len(f.l.rows) != rows {
				t.Fatal("noop retry changed config identity/bytes, journal or node state")
			}
			if !strings.Contains(out.String(), "\nROLLBACK_OK node=stopped config=baseline-verified retry=noop\n") || !strings.Contains(out.String(), `"type":"rollback_verified"`) {
				t.Fatalf("missing noop receipt: %s", out.String())
			}
		})
	}
}

// Claim: a completed receipt cannot label restarted or config-drifted state noop; ordinary reconciliation or a named refusal remains required.
func TestRollbackNoopRequiresCurrentState(t *testing.T) {
	for _, drift := range []string{"running", "config"} {
		t.Run(drift, func(t *testing.T) {
			f, n := rollbackFixture(t, false)
			installRollbackConfig(t, f, n, true)
			must(t, f.l.Rollback("station", n))
			f.reopen(t)
			var out bytes.Buffer
			f.l.output = &out
			if drift == "running" {
				n.running = true
			} else {
				must(t, os.WriteFile(n.config, []byte("foreign\n"), 0640))
			}
			err := f.l.Rollback("station", n)
			if drift == "running" {
				must(t, err)
				if n.running {
					t.Fatal("node not reconciled")
				}
			} else {
				code(t, err, 1)
				if !strings.Contains(err.Error(), "ROLLBACK_CONFIG_MISMATCH") {
					t.Fatal(err)
				}
				got, e := os.ReadFile(n.config)
				must(t, e)
				if string(got) != "foreign\n" {
					t.Fatal("foreign config overwritten")
				}
			}
			if strings.Contains(out.String(), "retry=noop") {
				t.Fatal("drift incorrectly named noop")
			}
		})
	}
}

type rejectRollbackLine struct{ bytes.Buffer }

func (w *rejectRollbackLine) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte("ROLLBACK_OK")) {
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}

// Claim: failure writing the plain success line returns the named exit-1 refusal after JSON; a fresh stopped retry can still succeed without node effects.
func TestRollbackSuccessLineWriteFailure(t *testing.T) {
	f, n := rollbackFixture(t, false)
	installRollbackConfig(t, f, n, true)
	w := new(rejectRollbackLine)
	f.l.output = w
	err := f.l.Rollback("station", n)
	code(t, err, 1)
	if !strings.Contains(err.Error(), "ROLLBACK_OUTPUT_FAILED state=verified safe-to-rerun") || !strings.Contains(w.String(), `"type":"rollback_verified"`) || strings.Contains(w.String(), "ROLLBACK_OK") {
		t.Fatal("wrong output refusal or lost JSON receipt")
	}
	f.reopen(t)
	var out bytes.Buffer
	f.l.output = &out
	must(t, f.l.Rollback("station", noControlRetry{n, t}))
	if !strings.HasSuffix(out.String(), "ROLLBACK_OK node=stopped config=baseline-verified retry=noop\n") {
		t.Fatal("output failure did not safely retry")
	}
}
