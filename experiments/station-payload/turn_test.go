package payload

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real private journal recovery keeps ready bytes, preserves received input and
// converts crash-left model work to uncertain without any model invocation.
func TestTurnJournalRecovery(t *testing.T) {
	for _, phase := range []string{"received", "in-flight", "ready", "accepted"} {
		t.Run(phase, func(t *testing.T) {
			root := root(t)
			id := strings.Repeat("a", 64)
			j, e := openTurns(root, "binding")
			if e != nil {
				t.Fatal(e)
			}
			turn, e := j.receive(id, "prompt")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = j.receive(id, "different"); e == nil {
				t.Fatal("changed input accepted")
			}
			turn.Phase = phase
			if phase == "ready" || phase == "accepted" {
				turn.Reply = "exact response"
			}
			if e = j.save(turn); e != nil {
				t.Fatal(e)
			}
			j.close()
			j, e = openTurns(root, "binding")
			if e != nil {
				t.Fatal(e)
			}
			defer j.close()
			got, e := j.receive(id, "prompt")
			if e != nil {
				t.Fatal(e)
			}
			if phase == "in-flight" {
				if got.Phase != "ready" || got.Reply != TurnUncertain {
					t.Fatal("generation uncertainty not terminal")
				}
			} else if got.Phase != turn.Phase || got.Input != turn.Input || got.Reply != turn.Reply {
				t.Fatal("ready/input state changed")
			}
		})
	}
}

// Missing/nonprivate/symlink roots, an unknown binding and malformed records
// refuse before a usable journal is returned. Corrupt bytes remain unchanged.
func TestTurnJournalRefusals(t *testing.T) {
	root := root(t)
	id := strings.Repeat("b", 64)
	j, e := openTurns(root, "binding")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = j.receive(id, "prompt"); e != nil {
		t.Fatal(e)
	}
	j.close()
	if _, e = openTurns(root, "other"); e == nil {
		t.Fatal("foreign binding accepted")
	}
	for _, path := range []string{"", "relative", filepath.Join(root, "absent")} {
		if _, e = openTurns(path, "binding"); e == nil {
			t.Fatal("unsafe root accepted")
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if os.Symlink(root, link) != nil {
		t.Fatal("symlink plant")
	}
	if _, e = openTurns(link, "binding"); e == nil {
		t.Fatal("symlink accepted")
	}
	if os.Chmod(root, 0750) != nil {
		t.Fatal("mode plant")
	}
	if _, e = openTurns(root, "binding"); e == nil {
		t.Fatal("nonprivate root accepted")
	}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("mode repair")
	}
	file := filepath.Join(root, "turn-"+id+".json")
	raw, _ := os.ReadFile(file)
	for _, bad := range [][]byte{raw[:len(raw)-1], bytes.Replace(raw, []byte(`"input":"prompt"`), []byte(`"input":"changed"`), 1), bytes.Replace(raw, []byte(`"phase":"received"`), []byte(`"phase":"unknown"`), 1), bytes.Replace(raw, []byte(`"phase":"received"`), []byte(`"phase":"ready"`), 1)} {
		if bytes.Equal(bad, raw) {
			t.Fatal("plant not applied")
		}
		if os.WriteFile(file, bad, 0600) != nil {
			t.Fatal("write")
		}
		if _, e = openTurns(root, "binding"); e == nil {
			t.Fatal("corrupt record accepted")
		}
		after, _ := os.ReadFile(file)
		if !bytes.Equal(after, bad) {
			t.Fatal("corrupt bytes rewritten")
		}
		if os.WriteFile(file, raw, 0600) != nil {
			t.Fatal("restore")
		}
		j, e = openTurns(root, "binding")
		if e != nil {
			t.Fatal("valid neighbor", e)
		}
		j.close()
	}
}
