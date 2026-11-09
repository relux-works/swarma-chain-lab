package booking

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type guardPlant struct {
	name, file, old, new, selector, marker string
	core                                   bool
}

// The base has no booking API, so a base compile failure cannot prove a guard.
// Each plant removes one specified protection in an isolated source copy; only
// the corresponding assertion failure counts, never a build/setup failure.
func TestGuardRemovalControls(t *testing.T) {
	if os.Getenv("M3_MUTATIONS") != "1" {
		t.Skip("explicit M3_MUTATIONS=1 and a new M3_MUTATION_ROOT required")
	}
	root := os.Getenv("M3_MUTATION_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute root required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	plants := []guardPlant{
		{"v2-http-origin", "http.go", "if r.Method == \"POST\" && r.Header.Get(\"Origin\") != h.origin {", "if false && r.Method == \"POST\" && r.Header.Get(\"Origin\") != h.origin {", "TestHTTPV2/btc/origin", "v2 HTTP guard changed state or accepted", false},
		{"v2-service-version", "cmd/rental-booking/config.go", "c.ServiceVersion != 2", "false", "TestServiceConfigSelection/unknown-version", "ambiguous service config accepted", false},

		{"start-window-entry", "service.go", "if s.startWindowClosed(*slot, now) {", "if false && s.startWindowClosed(*slot, now) {", "TestStartNowRemainingWindow/below", "remaining-window refusal/state", false},
		{"start-window-node-delay", "service.go", "if s.startWindowClosed(*slot, later) {", "if false && s.startWindowClosed(*slot, later) {", "TestStartNowRemainingWindow/node_delay", "remaining-window refusal/state", false},
		{"surplus-amount", "service.go", "surplus = r.Payment.ValueSat - b.Contract.PriceNMCSat", "surplus = 0", "TestGenuineCoreSurplus/over", "selected surplus/review not recorded", true},
		{"surplus-review", "service.go", "review := surplus > 0 ||", "review := false ||", "TestGenuineCoreSurplus/over", "selected surplus/review not recorded", true},
		{"surplus-backfill", "service.go", "if changed {", "if false && changed {", "TestGenuineCoreSurplus/over", "legacy surplus backfill not persisted", true},
		{"late-relay-expiry", "service.go", "if b.Issuance == nil && now >= b.HoldExpiresAt {", "if false && b.Issuance == nil && now >= b.HoldExpiresAt {", "TestGenuineCoreLateRelay", "late relay retained paid/issued state", true},
		{"provider-signature", "nostr.go", "if !verifySignature(provider, p.Contract.Hash(), p.ProviderSignature) {", "if false && !verifySignature(provider, p.Contract.Hash(), p.ProviderSignature) {", "TestProviderCountersignature", "provider signature:", false},
		{"package-hold", "nostr.go", "p.HoldExpiresAt != expires ||", "false ||", "TestPackageHoldBinding", "hold tamper:", false},
		{"station-grammar", "contract.go", "return false\n\t\t}\n\t}\n\treturn true\n}\nfunc actionPartition", "return true\n\t\t}\n\t}\n\treturn true\n}\nfunc actionPartition", "TestStationNameGrammar", "invalid station accepted", false},

		{"xpub-pin", "address.go", "if Hash([]byte(publicBranch)) != pin {", "if false && Hash([]byte(publicBranch)) != pin {", "TestAddressGuards/wrong_pin", "want XPUB_PIN", false},
		{"watch-only", "address.go", "err != nil || k.IsPrivate() ||", "err != nil || false ||", "TestAddressGuards/private", "want WATCH_ONLY_REGTEST_KEY", false},
		{"network-pin", "address.go", "!k.IsForNet(&chaincfg.RegressionNetParams)", "false && !k.IsForNet(&chaincfg.RegressionNetParams)", "TestAddressGuards/wrong_network", "want WATCH_ONLY_REGTEST_KEY", false},
		{"stale-rate", "quote.go", "now-asOf > maxAge", "false", "TestQuoteGuards/stale", "refusal/state", false},
		{"future-rate", "quote.go", "now < asOf", "false", "TestQuoteGuards/future", "refusal/state", false},
		{"quote-overflow", "quote.go", "if !n.IsInt64() || n.Sign() <= 0 || n.Int64() > 21000000*100000000 {", "if false {", "TestQuoteGuards/overflow", "refusal/state", false},
		{"privacy", "service.go", "if !in.PrivacyAcknowledged {", "if false && !in.PrivacyAcknowledged {", "TestBookingInputRefusals/privacy", "refusal/state", false},
		{"capacity", "service.go", "if c.StationName == slot.StationName &&", "if false && c.StationName == slot.StationName &&", "TestCapacityAndExpiry", "capacity:", false},
		{"consent-key", "nostr.go", "if e.Pubkey != c.RenterPubkey {", "if false && e.Pubkey != c.RenterPubkey {", "TestConsentRefusals/other_key", "refusal/state", false},
		{"consent-hash", "nostr.go", "if e.Kind != want.Kind || e.Content != \"\" || !bytes.Equal(canonical(e.Tags), canonical(want.Tags)) {", "if false && e.Kind != want.Kind {", "TestConsentRefusals/other_hash", "refusal/state", false},
		{"consent-booking", "nostr.go", "if e.Kind != want.Kind || e.Content != \"\" || !bytes.Equal(canonical(e.Tags), canonical(want.Tags)) {", "if false && e.Kind != want.Kind {", "TestConsentRefusals/other_booking", "refusal/state", false},
		{"consent-privacy", "nostr.go", "if e.Kind != want.Kind || e.Content != \"\" || !bytes.Equal(canonical(e.Tags), canonical(want.Tags)) {", "if false && e.Kind != want.Kind {", "TestConsentRefusals/other_privacy", "refusal/state", false},
		{"event-id", "nostr.go", "if e.ID != id {", "if false && e.ID != id {", "TestConsentRefusals/event_id", "refusal/state", false},
		{"event-signature", "nostr.go", "if !verifySignature(e.Pubkey, id, e.Sig) {", "if false && !verifySignature(e.Pubkey, id, e.Sig) {", "TestConsentRefusals/signature", "refusal/state", false},
		{"consent-early", "nostr.go", "e.CreatedAt < created ||", "false ||", "TestConsentRefusals/before_hold", "refusal/state", false},
		{"consent-future", "nostr.go", "e.CreatedAt > now ||", "false ||", "TestConsentRefusals/future", "refusal/state", false},
		{"profile-pin", "contract.go", "Hash(profile) != t.ProfileSHA256 ||", "false ||", "TestTemplatePinsAndScope/profile", "want TEMPLATE_PROFILE_PIN", false},
		{"scope-partition", "contract.go", "if !actionPartition(t.Allowed, t.Forbidden) ||", "if false ||", "TestTemplatePinsAndScope/unknown", "want TEMPLATE_SCOPE", false},
		{"scope-budget", "contract.go", "t.BudgetSat < 0 ||", "false ||", "TestTemplatePinsAndScope/negative_budget", "want TEMPLATE_SCOPE", false},
		{"http-origin", "http.go", "if r.Method == \"POST\" && r.Header.Get(\"Origin\") != h.origin {", "if false && r.Method == \"POST\" && r.Header.Get(\"Origin\") != h.origin {", "TestHTTPGuardsAndConsent/origin", "guard 201", false},
		{"json-duplicate", "contract.go", "singleuse.StrictInput(raw, v)", "func() error { _ = singleuse.StrictInput; return json.Unmarshal(raw,v) }()", "TestHTTPGuardsAndConsent/duplicate", "guard 201", false},
		{"json-alias", "contract.go", "singleuse.StrictInput(raw, v)", "func() error { _ = singleuse.StrictInput; return json.Unmarshal(raw,v) }()", "TestHTTPGuardsAndConsent/alias", "guard 201", false},
		{"json-unknown", "contract.go", "singleuse.StrictInput(raw, v)", "func() error { _ = singleuse.StrictInput; return json.Unmarshal(raw,v) }()", "TestHTTPGuardsAndConsent/unknown", "guard 201", false},
		{"relay-id", "relay.go", "id != event.ID ||", "false ||", "TestLocalRelayProtocol", "wrong ack:", false},
		{"writer-lock", "store.go", "e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)", "e = nil", "TestStoreLockAndOutbox", "parallel writer accepted", false},
		{"outbox-conflict", "store.go", "if !bytes.Equal(old, b) {", "if false && !bytes.Equal(old, b) {", "TestStoreLockAndOutbox", "conflict:", false},
		{"underpayment", "service.go", "eligible := p.ValueSat >= b.Contract.PriceNMCSat &&", "eligible := true &&", "TestGenuineCorePayments/underpayment_and_wrong_address", "under/wrong payment admitted", true},
		{"mempool-advance", "service.go", "p.Height > 0 && r.ConfirmedAt > 0 &&", "true &&", "TestGenuineCorePayments/advance_pending_then_confirmed_duplicate_restart", "mempool admitted advance", true},
		{"reorg", "service.go", "if !present || reorged {", "if false && (!present || reorged) {", "TestGenuineCorePayments/confirmed_reorg", "reorg did not revoke", true},
		{"replacement", "service.go", "p.Height > 0 && r.ConfirmedAt > 0 &&", "true &&", "TestGenuineCorePayments/start_now_replacement", "mempool admitted start_now replacement", true},
		{"drop", "service.go", "p.Height > 0 && r.ConfirmedAt > 0 &&", "true &&", "TestGenuineCorePayments/start_now_dropped", "mempool admitted start_now drop", true},
		{"revoked-status", "service.go", "b.Status = \"revoked\"", "b.Status = \"pending\"", "TestGenuineCorePayments/confirmed_reorg", "reorg did not revoke", true},
		{"http-not-found", "http.go", "httpFail(w, 404, \"NOT_FOUND\")", "httpFail(w, 200, \"NOT_FOUND\")", "TestHTTPUnknownPaths", "unknown path not 404", false},
	}
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	source := filepath.Dir(cwd)
	copyTree := func(src, dst string) error {
		return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(src, path)
			if e != nil {
				return e
			}
			to := filepath.Join(dst, rel)
			if d.IsDir() {
				if d.Name() == ".temp" {
					return filepath.SkipDir
				}
				return os.MkdirAll(to, 0700)
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			return os.WriteFile(to, b, 0600)
		})
	}
	rows := []map[string]any{}
	for _, p := range plants {
		t.Run(p.name, func(t *testing.T) {
			dir := filepath.Join(root, p.name)
			for _, module := range []string{"rental-booking", "single-use", "sealwatch", "payment-chain"} {
				if e := copyTree(filepath.Join(source, module), filepath.Join(dir, module)); e != nil {
					t.Fatal(e)
				}
			}
			file := filepath.Join(dir, "rental-booking", p.file)
			raw, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Count(string(raw), p.old) != 1 {
				t.Fatalf("control not applied: expected one guard, got %d", strings.Count(string(raw), p.old))
			}
			mutant := strings.Replace(string(raw), p.old, p.new, 1)
			if e = os.WriteFile(file, []byte(mutant), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, c := context.WithTimeout(context.Background(), 90*time.Second)
			defer c()
			selector := "^" + strings.ReplaceAll(p.selector, "/", "$/^") + "$"
			pkg := "."
			if strings.HasPrefix(p.file, "cmd/") {
				pkg = "./" + filepath.Dir(p.file)
			}
			cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", selector, pkg)
			cmd.Dir = filepath.Join(dir, "rental-booking")
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "M3_") {
					cmd.Env = append(cmd.Env, v)
				}
			}
			if p.core {
				cmd.Env = append(cmd.Env, "M3_REGTEST=1", "M3_RUN_ROOT="+filepath.Join(dir, "core"), "M3_CORE_CLI="+os.Getenv("M3_CORE_CLI"), "M3_CORE_DAEMON="+os.Getenv("M3_CORE_DAEMON"))
			}
			out, err := cmd.CombinedOutput()
			exit := -1
			if cmd.ProcessState != nil {
				exit = cmd.ProcessState.ExitCode()
			}
			if e = os.WriteFile(filepath.Join(dir, "test.log"), out, 0600); e != nil {
				t.Fatal(e)
			}
			killed := err != nil && ctx.Err() == nil && strings.Contains(string(out), p.marker) && strings.Contains(string(out), "--- FAIL:") && !strings.Contains(string(out), "[build failed]") && !strings.Contains(string(out), "panic:")
			rows = append(rows, map[string]any{"name": p.name, "source_sha256": Hash(raw), "mutant_sha256": Hash([]byte(mutant)), "file": p.file, "selector": selector, "expected_assertion": p.marker, "exit_code": exit, "killed": killed, "genuine_core": p.core})
			if !killed {
				t.Fatalf("plant not killed by intended assertion: exit %d; log %s", exit, filepath.Join(dir, "test.log"))
			}
		})
	}
	if e = os.WriteFile(filepath.Join(root, "results.json"), canonical(rows), 0600); e != nil {
		t.Fatal(e)
	}
}
