package signerservice

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/presentationdir"
)

func publicDir(t *testing.T) string {
	t.Helper()
	p := dir(t)
	if e := os.Chmod(p, 0755); e != nil {
		t.Fatal(e)
	}
	return p
}
func fixturePresentation(t *testing.T) (string, []byte) {
	t.Helper()
	raw, e := os.ReadFile("../rental/testdata/grant-v3/presentation.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		t.Fatal(e)
	}
	return p.SignedGrant.Grant.Consent.ConsentEvent.Tags[2][1], raw
}

// Actual atomic publisher output reaches the actual gateway source byte-for-byte.
// Concurrent repeats/reopen are idempotent. Frozen signed bytes test filesystem
// composition only; chain confirmation is separately exercised by genuine Core.
func TestPresentationPublication(t *testing.T) {
	id, raw := fixturePresentation(t)
	root := publicDir(t)
	ctx := context.Background()
	p, e := presentationdir.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { p.Close() }()
	if b, e := p.Presentation(ctx, id); e != nil || b != nil {
		t.Fatal("absent not pending")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := publishPresentation(ctx, root, id, raw); e != nil {
				t.Error("idempotent publication", e)
			}
		}()
	}
	wg.Wait()
	b, e := p.Presentation(ctx, id)
	if e != nil || !bytes.Equal(b, raw) {
		t.Fatal("gateway did not read publisher bytes", e)
	}
	st, e := os.Stat(filepath.Join(root, id+".json"))
	if e != nil || !publicOwner(st, false) {
		t.Fatal("wrong public file mode")
	}
	before := st.ModTime()
	if e := publishPresentation(ctx, root, id, raw); e != nil {
		t.Fatal(e)
	}
	st, _ = os.Stat(filepath.Join(root, id+".json"))
	if st.ModTime() != before {
		t.Fatal("retry rewrote file")
	}
	files, e := os.ReadDir(root)
	if e != nil || len(files) != 1 {
		t.Fatal("temporary file leaked")
	}
	p.Close()
	p, e = presentationdir.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	if b, e := p.Presentation(ctx, id); e != nil || !bytes.Equal(b, raw) {
		t.Fatal("reopened reader changed bytes")
	}
}

// Malformed input never becomes public; corrupt/partial/linked/conflicting
// existing output is preserved and refused, with a valid positive neighbor.
func TestPresentationRefusals(t *testing.T) {
	id, raw := fixturePresentation(t)
	ctx := context.Background()
	for _, mode := range []string{"partial", "conflict", "mode", "symlink", "hardlink", "input", "wrong-id", "cancel", "dir-mode", "dir-symlink", "special-mode"} {
		t.Run(mode, func(t *testing.T) {
			root := publicDir(t)
			path := filepath.Join(root, id+".json")
			input := raw
			key := id
			callCtx := ctx
			switch mode {
			case "partial":
				if e := os.WriteFile(path, []byte("{"), 0644); e != nil {
					t.Fatal(e)
				}
			case "conflict":
				bad := bytes.Clone(raw)
				bad[len(bad)-3] ^= 1
				if e := os.WriteFile(path, bad, 0644); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				target := filepath.Join(dir(t), "proof")
				write(t, target, raw)
				if e := os.Symlink(target, path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.WriteFile(path, raw, 0644); e != nil {
					t.Fatal(e)
				}
				if e := os.Link(path, path+"-link"); e != nil {
					t.Fatal(e)
				}
			case "input":
				input = append(bytes.Clone(raw), ' ')
			case "wrong-id":
				key = strings.Repeat("f", 64)
			case "cancel":
				var cancel context.CancelFunc
				callCtx, cancel = context.WithCancel(ctx)
				cancel()
			case "special-mode":
				if e := os.WriteFile(path, raw, 0644); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(path, 0644|os.ModeSetuid); e != nil {
					t.Fatal(e)
				}
			case "dir-mode":
				os.Chmod(root, 0775)
			case "dir-symlink":
				alias := filepath.Join(dir(t), "alias")
				if e := os.Symlink(root, alias); e != nil {
					t.Fatal(e)
				}
				root = alias
			}
			before, _ := os.ReadFile(path)
			e := publishPresentation(callCtx, root, key, input)
			after, _ := os.ReadFile(path)
			want := map[string]string{"partial": "PRESENTATION_CONFLICT", "conflict": "PRESENTATION_CONFLICT", "mode": "PRESENTATION_CONFLICT", "symlink": "PRESENTATION_FILE", "hardlink": "PRESENTATION_CONFLICT", "input": "PRESENTATION_ENCODING", "wrong-id": "PRESENTATION_ENCODING", "cancel": "CANCELED", "dir-mode": "PRESENTATION_ROOT", "dir-symlink": "PRESENTATION_ROOT", "special-mode": "PRESENTATION_CONFLICT"}[mode]
			if e == nil || e.Error() != want || !bytes.Equal(before, after) {
				t.Fatal("unsafe presentation published or overwritten", mode, e)
			}
			if e := publishPresentation(ctx, publicDir(t), id, raw); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
}

// The public output destination is custody configuration, not an input hint:
// changing it on a durable ledger refuses before any node/key/effect call.
func TestPresentationConfigBinding(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		c := config(t)
		if enabled {
			c.PresentationDir = publicDir(t)
		}
		x, e := Open(c, preflightIssuer{t, Intent{}}, noNode{t}, noBroadcast{t}, noStore{t})
		if e != nil {
			t.Fatal(e)
		}
		if e = x.commit(cloneState(x.state)); e != nil {
			t.Fatal(e)
		}
		x.Close()
		before := outboxLedger(t, c.StateDir)
		changed := c
		changed.PresentationDir = publicDir(t)
		_, e = Open(changed, preflightIssuer{t, Intent{}}, noNode{t}, noBroadcast{t}, noStore{t})
		wantError(t, e, "LEDGER_CORRUPT")
		if !bytes.Equal(before, outboxLedger(t, c.StateDir)) {
			t.Fatal("publisher reconfiguration rewrote custody")
		}
		x, e = Open(c, preflightIssuer{t, Intent{}}, noNode{t}, noBroadcast{t}, noStore{t})
		if e != nil {
			t.Fatal("original config refused", e)
		}
		x.Close()
	}
}
func outboxLedger(t *testing.T, root string) []byte {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(root, "ledger.json"))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
