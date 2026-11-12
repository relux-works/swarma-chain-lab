package deploy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// g2SetClientMember sets one client.json member to the given raw JSON value,
// located by its key. It fails unless the member occurs exactly once.
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

// Claim: the rendered client.json is resolved: it carries the parameters
// service UID as a JSON number and the agent key file verbatim, with no
// placeholder; and its actual consumer, the agent-wallet CLI built from this
// checkout (its first step is LoadActionClientConfig), accepts it, which the
// CLI shows by moving on to the request file and refusing that (absent) file
// with PUBLIC_FILE. The refusing neighbours prove the loader discriminates:
// the same file with service_uid quoted, with a relative key_file, or with
// key_file still a placeholder each print exactly CLIENT_CONFIG. Nothing
// reaches a signing key, socket or network: the request file is absent.
// Limit: one rendering (the main fixture parameters) and this checkout's
// agent-wallet source, built as a subprocess; deploy does not import it. The
// rendered-bytes checks run before the build. The consumer part skips only
// where GOPROXY=off and the agent-wallet dependency modules are not in the
// module cache (a job that downloads only deploy's own dependencies); the
// deploy workflow downloads them. A skip is never a plant kill, and any other
// build failure fails.
func TestPX1S5ClientConsumerResolved(t *testing.T) {
	p := g2Params()
	files, e := RenderG2PayTemplates(p)
	if e != nil {
		t.Fatal("G2_CLIENT_CONSUMER_SETUP render", e)
	}
	emitted := files[G2FileClientConfig]
	if bytes.Contains(bytes.ToUpper(emitted), []byte("PLACEHOLDER")) || g2ClientMemberValue(t, emitted, "service_uid") != strconv.FormatUint(uint64(p.ServiceUID), 10) || g2ClientMemberValue(t, emitted, "key_file") != strconv.Quote(p.AgentKeyFile) {
		t.Fatalf("G2_CLIENT_UNRESOLVED the rendered client.json is not resolved from the parameters: %s", emitted)
	}

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
		if os.Getenv("GOPROXY") == "off" && bytes.Contains(out, []byte("module lookup disabled by GOPROXY=off")) {
			t.Skipf("G2_CLIENT_CONSUMER_SKIP agent-wallet dependencies are not in the module cache and GOPROXY=off forbids fetching them: %v\n%s", e, out)
		}
		t.Fatalf("G2_CLIENT_CONSUMER_SETUP build agent-wallet: %v\n%s", e, out)
	}

	absentRequest := filepath.Join(work, "absent-request.json")
	const refused = "{\"error\":\"CLIENT_CONFIG\"}\n"
	const accepted = "{\"error\":\"PUBLIC_FILE\"}\n" // config loaded; the absent request file is refused next
	cases := []struct {
		name   string
		config []byte
		want   string
	}{
		{"rendered", emitted, accepted},
		{"uid-quoted", g2SetClientMember(t, emitted, "service_uid", strconv.Quote(strconv.FormatUint(uint64(p.ServiceUID), 10))), refused},
		{"key-relative", g2SetClientMember(t, emitted, "key_file", strconv.Quote(strings.TrimPrefix(p.AgentKeyFile, "/"))), refused},
		{"key-placeholder", g2SetClientMember(t, emitted, "key_file", `"PLACEHOLDER_AGENT_SIGNING_KEY_ABSOLUTE_PATH"`), refused},
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
				t.Fatalf("G2_CLIENT_CONSUMER_ACCEPTED %s: the consumer loaded an invalid client.json\nconfig=%s", c.name, c.config)
			}
			if !errors.As(e, &exit) || exit.ExitCode() != 2 || stdout.String() != c.want || stderr.Len() != 0 {
				t.Fatalf("G2_CLIENT_CONSUMER %s: run=%v stdout=%q stderr=%q, want exit 2 and %q\nconfig=%s", c.name, e, stdout.String(), stderr.String(), c.want, c.config)
			}
		})
	}
	if _, e := os.Lstat(absentRequest); !os.IsNotExist(e) {
		t.Fatal("G2_CLIENT_CONSUMER_SETUP the request path that must stay absent exists", e)
	}
}
