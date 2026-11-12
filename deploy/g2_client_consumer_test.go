package deploy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// g2SetClientMember sets one client.json member to a resolved JSON value the
// way an operator fills in that placeholder. It locates the member by its key,
// not by the renderer's placeholder constant, so a changed placeholder text is
// still exercised. It fails unless the member occurs exactly once.
func g2SetClientMember(t *testing.T, raw []byte, member, value string) []byte {
	t.Helper()
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(member) + `":("[^"\\]*"|[0-9]+)`)
	if n := len(re.FindAllIndex(raw, -1)); n != 1 {
		t.Fatalf("G2_CLIENT_CONSUMER_SETUP member %s occurs %d times in %s", member, n, raw)
	}
	return re.ReplaceAllLiteral(raw, []byte(`"`+member+`":`+value))
}

// g2ClientMemberValue returns the raw JSON value of one client.json member.
func g2ClientMemberValue(t *testing.T, raw []byte, member string) string {
	t.Helper()
	m := regexp.MustCompile(`"` + regexp.QuoteMeta(member) + `":("[^"\\]*"|[0-9]+)`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("G2_CLIENT_CONSUMER_SETUP member %s absent in %s", member, raw)
	}
	return string(m[1])
}

// Claim: the actual consumer of the rendered client.json, the agent-wallet CLI
// built from this checkout (its first step is LoadActionClientConfig), refuses
// with exactly CLIENT_CONFIG when service_uid is unresolved, when key_file is
// unresolved, and when both are; the valid neighbour with both members set is
// accepted, which the CLI shows by moving on to the request file and refusing
// that (absent) file with PUBLIC_FILE. Nothing reaches a signing key, socket or
// network: the request file is absent and the resolved key path does not exist.
// Limit: one rendering (the main fixture parameters) and this checkout's
// agent-wallet source, built as a subprocess; deploy does not import it.
func TestPX1S5ClientConsumerPlaceholders(t *testing.T) {
	goBin, e := exec.LookPath("go")
	if e != nil {
		t.Fatal("G2_CLIENT_CONSUMER_SETUP go toolchain not on PATH", e)
	}
	cwd, _ := os.Getwd()
	walletModule := filepath.Join(cwd, "..", "experiments", "agent-wallet")
	if _, e := os.Stat(filepath.Join(walletModule, "cmd", "agent-wallet", "main.go")); e != nil {
		t.Fatal("G2_CLIENT_CONSUMER_SETUP agent-wallet CLI source", e)
	}
	work := t.TempDir()
	cli := filepath.Join(work, "agent-wallet")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	// Build in the agent-wallet module's own context: its go.mod and go.sum,
	// read-only, no workspace. The binary goes to the test temp directory.
	build := exec.CommandContext(ctx, goBin, "build", "-mod=readonly", "-buildvcs=false", "-o", cli, "./cmd/agent-wallet")
	build.Dir = walletModule
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "GOWORK=") {
			build.Env = append(build.Env, v)
		}
	}
	build.Env = append(build.Env, "GOWORK=off")
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("G2_CLIENT_CONSUMER_SETUP build agent-wallet: %v\n%s", e, out)
	}

	files, e := RenderG2PayTemplates(g2Params())
	if e != nil {
		t.Fatal("G2_CLIENT_CONSUMER_SETUP render", e)
	}
	emitted := files[G2FileClientConfig]
	// The emitted members must be placeholders; otherwise the refusal rows
	// below would not test unresolved fields.
	for _, member := range []string{"service_uid", "key_file"} {
		if v := g2ClientMemberValue(t, emitted, member); !strings.Contains(v, "PLACEHOLDER") {
			t.Fatalf("G2_CLIENT_CONSUMER_SETUP %s is not a placeholder: %s", member, v)
		}
	}
	absentKey := filepath.Join(work, "absent-action.key")
	absentRequest := filepath.Join(work, "absent-request.json")
	setUID := func(b []byte) []byte { return g2SetClientMember(t, b, "service_uid", g2SvcUID) }
	setKey := func(b []byte) []byte { return g2SetClientMember(t, b, "key_file", `"`+absentKey+`"`) }

	const refused = "{\"error\":\"CLIENT_CONFIG\"}\n"
	const accepted = "{\"error\":\"PUBLIC_FILE\"}\n" // config loaded; the absent request file is refused next
	cases := []struct {
		name   string
		config []byte
		want   string
	}{
		{"both-unresolved", emitted, refused},
		{"uid-unresolved", setKey(emitted), refused},
		{"key-unresolved", setUID(emitted), refused},
		{"resolved", setKey(setUID(emitted)), accepted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(work, c.name)
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal("G2_CLIENT_CONSUMER_SETUP", e)
			}
			config := filepath.Join(dir, G2FileClientConfig)
			// Written exactly as deploy-kit g2-render writes it: the bytes, mode 0600.
			if e := os.WriteFile(config, c.config, 0600); e != nil {
				t.Fatal("G2_CLIENT_CONSUMER_SETUP", e)
			}
			run, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(run, cli, "--config", config, "--request", absentRequest)
			cmd.Env = []string{}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			e := cmd.Run()
			var exit *exec.ExitError
			if c.want == refused && stdout.String() == accepted {
				t.Fatalf("G2_CLIENT_PLACEHOLDER_ACCEPTED %s: the consumer loaded an unresolved client.json\nconfig=%s", c.name, c.config)
			}
			if !errors.As(e, &exit) || exit.ExitCode() != 2 || stdout.String() != c.want || stderr.Len() != 0 {
				t.Fatalf("G2_CLIENT_CONSUMER %s: run=%v stdout=%q stderr=%q, want exit 2 and %q\nconfig=%s", c.name, e, stdout.String(), stderr.String(), c.want, c.config)
			}
		})
	}
	for _, p := range []string{absentKey, absentRequest} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("G2_CLIENT_CONSUMER_SETUP a path that must stay absent exists", p, e)
		}
	}
}
