// DK5 installed-input controls use Go overlays: no source or live state is modified.
// file_kind and membership assert exact refusal reasons:
// downstream checks also reject those planted inputs. Other plants exercise
// admission, service bindings, native defaults and preflight exit behavior.
// Run at repository root: go run .scripts/dk5-guards.go -out /absolute/new-dir.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type plant struct{ Name, Module, File, Before, After, Test, Witness, Package string }
type result struct {
	Name, SourceSHA256, MutantSHA256     string
	BaselinePID, PID, BaselineExit, Exit int
	Detected                             bool
}

var plants = []plant{
	{"fixture_root_umask", "experiments/single-use", "configguard/reader_test.go", "if e := os.Chmod(root, 0755); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: fixture root chmod removed", "^TestFixtureUmask$/0002$", "umask signed neighbor: DK5_ANCHOR_FILE", "./configguard"},
	{"fixture_child_selected", "experiments/single-use", "configguard/umask_test.go", "-test.run=^TestFixtureUmask$", "-test.run=^NoSuchFixtureTest$", "^TestFixtureUmask$", "fixture umask child did not run:", "./configguard"},
	{"fixture_gateway_broad_umask", "experiments/rental-gateway", "cmd/gateway/inbound_test.go", "if e = os.Chmod(broad, 0755); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestDK5Umask$", "broad state accepted", "./cmd/gateway"},
	{"fixture_directory_umask", "experiments/single-use", "configguard/reader_test.go", "if e := os.Chmod(path, mode); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestFixtureUmask$", "umask signed neighbor: DK5_ANCHOR_FILE", "./configguard"},
	{"fixture_file_umask", "experiments/single-use", "configguard/signature_test.go", "if e := os.Chmod(path, mode); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestFixtureUmask$", "umask signed neighbor: DK5_ANCHOR_FILE", "./configguard"},
	{"fixture_station-lifecycle_umask", "experiments/station-lifecycle", "cmd/station-manager/dk5_fixture_test.go", "if e := os.Chmod(path, 0640); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestDK5FixtureUmask$", "DK5 valid neighbor: DK5_FILE_MODE", "./cmd/station-manager"},
	{"fixture_relay_umask", "experiments/relay", "cmd/swarma-relay/dk5_fixture_test.go", "if e := os.Chmod(path, 0640); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestDK5FixtureUmask$", "DK5 valid neighbor: DK5_FILE_MODE", "./cmd/swarma-relay"},
	{"fixture_grant-store_umask", "experiments/grant-store", "cmd/grant-store/dk5_fixture_test.go", "if e := os.Chmod(path, 0640); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestDK5FixtureUmask$", "DK5 valid neighbor: DK5_FILE_MODE", "./cmd/grant-store"},
	{"fixture_rental-gateway_umask", "experiments/rental-gateway", "cmd/gateway/dk5_fixture_test.go", "if e := os.Chmod(path, 0640); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestDK5Umask$", "DK5 valid neighbor: DK5_FILE_MODE", "./cmd/gateway"},
	{"fixture_station-payload_umask", "experiments/station-payload", "cmd/station-payload/dk5_fixture_test.go", "if e := os.Chmod(path, 0640); e != nil {\n\t\tt.Fatal(e)\n\t}", "// control: explicit chmod removed", "^TestDK5FixtureUmask$", "DK5 valid neighbor: DK5_FILE_MODE", "./cmd/station-payload"},
	{"native_fixture_default", "experiments/single-use", "configguard/reader.go", "return Reader{EUID: os.Geteuid(), GID: os.Getegid()}", "return Reader{EUID: os.Geteuid(), GID: os.Getegid(), FixtureRoot: \"/fixture\"}", "^TestNativeDefaults$", "native constructor selected fixture authority", "./configguard"},
	{"ancestor_group_narrow", "experiments/single-use", "configguard/reader.go", "s.Mode&0022 != 0", "s.Mode&0002 != 0", "^TestAncestorSubclasses$/group_writable$", "installed refusal:", "./configguard"},
	{"ancestor_special_narrow", "experiments/single-use", "configguard/reader.go", " || s.Mode&07000 != 0", "", "^TestAncestorSubclasses$/(setuid|setgid|sticky)$", "installed refusal:", "./configguard"},
	{"ancestor_owner_narrow", "experiments/single-use", "configguard/reader.go", "if s.Uid != 0 {\n\t\treturn fail(\"DK5_DIRECTORY_OWNER\")", "if immediate && s.Uid != 0 {\n\t\treturn fail(\"DK5_DIRECTORY_OWNER\")", "^TestAncestorSubclasses$/non_root$", "installed refusal:", "./configguard"},
	{"private_group_binding", "experiments/single-use", "configguard/anchor.go", "r.GID = gid", "_ = gid", "^TestComposedPrivateGroup$", "private group binding:", "./configguard"},
	{"preflight_refusal_exit", "experiments/single-use", "configguard/anchor.go", "os.Exit(1)", "os.Exit(0)", "^TestComposedCheckMain$", "preflight refusal exit", "./configguard"},
	{"rsa_public_bounds", "experiments/single-use", "configguard/signature.go", "if p, ok := pub.(*rsa.PublicKey); !ok || p.N.BitLen() < 3072 || p.N.BitLen() > 8192 || p.E != 65537 {", "if _, ok := pub.(*rsa.PublicKey); !ok {", "^TestRSAKeyPolicy$", "installed refusal:", "./configguard"},
	{"consumer_agent-wallet", "experiments/agent-wallet", "installed.go", "const installedService = \"wallet\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "."},
	{"consumer_model-proxy", "experiments/model-proxy", "installed.go", "const installedService = \"model\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "."},
	{"consumer_signer-service", "experiments/signer-service", "installed.go", "const installedService = \"issuer\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "."},
	{"consumer_relay", "experiments/relay", "cmd/swarma-relay/installed.go", "const installedService = \"relay\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "./cmd/swarma-relay"},
	{"consumer_station-lifecycle", "experiments/station-lifecycle", "cmd/station-manager/installed.go", "const installedService = \"stations\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "./cmd/station-manager"},
	{"consumer_rental-booking", "experiments/rental-booking", "cmd/rental-booking/installed.go", "const installedService = \"booking\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "./cmd/rental-booking"},
	{"consumer_station-payload", "experiments/station-payload", "cmd/station-payload/installed.go", "const installedService = \"payload\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "./cmd/station-payload"},
	{"consumer_rental-gateway", "experiments/rental-gateway", "cmd/gateway/installed.go", "const installedService = \"gateway\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "./cmd/gateway"},
	{"consumer_grant-store", "experiments/grant-store", "cmd/grant-store/installed.go", "const installedService = \"store\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "./cmd/grant-store"},
	{"consumer_rental", "experiments/rental", "installed_key.go", "const installedService = \"issuer\"", "const installedService = \"wrong-service\"", "^TestDK5ServiceBinding$", "service binding differs from unit", "."},
	{"staged_content_hash", "experiments/single-use", "configguard/staged.go", "if digest(raw) != entry.SHA256 {", "if false && digest(raw) != entry.SHA256 {", "^TestStagedRefusals$/changed_bytes$", "staged refusal:", "./configguard"},
	{"staged_final_paths", "experiments/single-use", "configguard/staged.go", "if entry.Path != p.Paths[i] {", "if false && entry.Path != p.Paths[i] {", "^TestStagedSignedRelocation$", "staged refusal:", "./configguard"},
	{"staged_signature", "experiments/single-use", "configguard/staged.go", "if e := verifySignature(s.Manifest, s.Signature, a.Algorithm, a.PublicKey); e != nil {", "if e := verifySignature(s.Manifest, s.Signature, a.Algorithm, a.PublicKey); false && e != nil {", "^TestStagedRefusals$/signature_invalid$", "staged refusal:", "./configguard"},

	{"rsa_signature", "experiments/single-use", "configguard/signature.go", "if rsa.VerifyPSS(p, crypto.SHA256, h[:], value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {", "if false && rsa.VerifyPSS(p, crypto.SHA256, h[:], value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {", "^TestSignedAlgorithms$/rsa-pss-sha256$", "installed refusal:", "./configguard"},
	{"file_mode", "experiments/single-use", "configguard/reader.go", "if uint32(s.Mode)&07777 != mode {", "if false && uint32(s.Mode)&07777 != mode {", "^TestInstalledRefusals$/0644$", "installed refusal:", "./configguard"},
	{"file_owner", "experiments/single-use", "configguard/reader.go", "if s.Uid != 0 {\n\t\treturn fail(\"DK5_FILE_OWNER\")", "if false && s.Uid != 0 {\n\t\treturn fail(\"DK5_FILE_OWNER\")", "^TestOwnershipSeam$/owner$", "installed refusal:", "./configguard"},
	{"file_group", "experiments/single-use", "configguard/reader.go", "if s.Gid != gid {", "if false && s.Gid != gid {", "^TestOwnershipSeam$/group$", "installed refusal:", "./configguard"},
	{"directory_mode", "experiments/single-use", "configguard/reader.go", "if uint32(s.Mode)&07777 != parentMode {", "if false && uint32(s.Mode)&07777 != parentMode {", "^TestInstalledRefusals$/dir0755$", "installed refusal:", "./configguard"},
	{"directory_owner", "experiments/single-use", "configguard/reader.go", "if s.Uid != 0 {\n\t\treturn fail(\"DK5_DIRECTORY_OWNER\")", "if false && s.Uid != 0 {\n\t\treturn fail(\"DK5_DIRECTORY_OWNER\")", "^TestDirectoryOwnershipAndChangedFile$/owner$", "installed refusal:", "./configguard"},
	{"directory_group", "experiments/single-use", "configguard/reader.go", "if s.Gid != parentGID {", "if false && s.Gid != parentGID {", "^TestDirectoryOwnershipAndChangedFile$/group$", "installed refusal:", "./configguard"},
	{"hardlink", "experiments/single-use", "configguard/reader.go", "if s.Nlink != 1 {", "if false && s.Nlink != 1 {", "^TestInstalledRefusals$/hardlink$", "installed refusal:", "./configguard"},
	{"file_symlink", "experiments/single-use", "configguard/reader.go", "parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|", "parts[len(parts)-1], unix.O_RDONLY|", "^TestInstalledRefusals$/symlink$", "installed refusal:", "./configguard"},
	{"directory_symlink", "experiments/single-use", "configguard/reader.go", "component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|", "component, unix.O_RDONLY|unix.O_DIRECTORY|", "^TestAncestorAndReadBoundary$", "installed refusal:", "./configguard"},
	{"ancestor_mode", "experiments/single-use", "configguard/reader.go", "} else if s.Mode&0022 != 0 || s.Mode&07000 != 0 {", "} else if false && (s.Mode&0022 != 0 || s.Mode&07000 != 0) {", "^TestAncestorAndReadBoundary$", "installed refusal:", "./configguard"},
	{"service_identity", "experiments/single-use", "configguard/reader.go", "if r.EUID <= 0 || r.GID <= 0 {", "if false && (r.EUID <= 0 || r.GID <= 0) {", "^TestAncestorAndReadBoundary$", "installed refusal:", "./configguard"},
	{"file_kind", "experiments/single-use", "configguard/reader.go", "if s.Mode&unix.S_IFMT != unix.S_IFREG {", "if false && s.Mode&unix.S_IFMT != unix.S_IFREG {", "^TestInstalledRefusals$/directory$", "installed refusal:", "./configguard"},
	{"post_read_change", "experiments/single-use", "configguard/reader.go", "!info.ModTime().Equal(last.ModTime())", "false && !info.ModTime().Equal(last.ModTime())", "^TestDirectoryOwnershipAndChangedFile$/changed$", "installed refusal:", "./configguard"},
	{"manifest_binding", "experiments/single-use", "configguard/manifest.go", "if m.ReleaseSHA256 != release || m.Service != service || m.GID != gid {", "if false && (m.ReleaseSHA256 != release || m.Service != service || m.GID != gid) {", "^TestSignedRefusals$/other_release$", "installed refusal:", "./configguard"},
	{"manifest_hash", "experiments/single-use", "configguard/anchor.go", "if digest(manifest) != a.Digest {", "if false && digest(manifest) != a.Digest {", "^TestSignedRefusals$/manifest_hash$", "installed refusal:", "./configguard"},
	{"content_hash", "experiments/single-use", "configguard/manifest.go", "if digest(raw) != want {", "if false && digest(raw) != want {", "^TestSignedRefusals$/changed_file$", "installed refusal:", "./configguard"},
	{"membership", "experiments/single-use", "configguard/manifest.go", "if !ok {", "if false && !ok {", "^TestSignedRefusals$/unlisted$", "installed refusal:", "./configguard"},
	{"manifest_paths", "experiments/single-use", "configguard/manifest.go", "entry.Path <= previous", "false && entry.Path <= previous", "^TestManifestRefusals$/duplicate$", "installed refusal:", "./configguard"},
	{"signature_verify", "experiments/single-use", "configguard/signature.go", "if !ed25519.Verify(p, message, value) {", "if false && !ed25519.Verify(p, message, value) {", "^TestSignedRefusals$/(bad_signature|wrong_key)$", "installed refusal:", "./configguard"},
	{"signature_algorithm", "experiments/single-use", "configguard/signature.go", "sig.Algorithm != algorithm", "false && sig.Algorithm != algorithm", "^TestSignedRefusals$/wrong_algorithm$", "installed refusal:", "./configguard"},
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func hash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func main() {
	out := flag.String("out", "", "new absolute output directory")
	flag.Parse()
	root, e := os.Getwd()
	must(e)
	if !filepath.IsAbs(*out) || flag.NArg() != 0 {
		panic("absolute new output required")
	}
	must(os.Mkdir(*out, 0700))
	var rows []result
	for _, p := range plants {
		module := filepath.Join(root, p.Module)
		source := filepath.Join(module, p.File)
		raw, e := os.ReadFile(source)
		must(e)
		if bytes.Count(raw, []byte(p.Before)) != 1 {
			panic("non-unique plant: " + p.Name)
		}
		mutant := bytes.Replace(raw, []byte(p.Before), []byte(p.After), 1)
		changed := filepath.Join(*out, p.Name+".go")
		must(os.WriteFile(changed, mutant, 0600))
		overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: changed}})
		op := filepath.Join(*out, p.Name+".json")
		must(os.WriteFile(op, overlay, 0600))
		pkg := p.Package
		run := func(plant bool) (int, int, []byte) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			args := []string{"test", "-count=1", "-v", "-run", p.Test}
			name := p.Name + "-baseline.log"
			if plant {
				args = append(args, "-overlay", op)
				name = p.Name + "-plant.log"
			}
			args = append(args, pkg)
			cmd := exec.CommandContext(ctx, "go", args...)
			cmd.Dir = module
			var log bytes.Buffer
			cmd.Stdout = &log
			cmd.Stderr = &log
			must(cmd.Start())
			pid := cmd.Process.Pid
			e := cmd.Wait()
			code := 0
			if e != nil {
				if x, ok := e.(*exec.ExitError); ok {
					code = x.ExitCode()
				} else {
					code = -1
				}
			}
			if ctx.Err() != nil {
				code = -2
			}
			must(os.WriteFile(filepath.Join(*out, name), log.Bytes(), 0600))
			return pid, code, log.Bytes()
		}
		row := result{Name: p.Name, SourceSHA256: hash(raw), MutantSHA256: hash(mutant)}
		var baseline, output []byte
		row.BaselinePID, row.BaselineExit, baseline = run(false)
		if row.BaselineExit != 0 || !bytes.Contains(baseline, []byte("--- PASS:")) {
			panic("baseline not passing: " + p.Name)
		}
		row.PID, row.Exit, output = run(true)
		row.Detected = row.Exit == 1 && bytes.Contains(output, []byte("--- FAIL:")) && bytes.Contains(output, []byte(p.Witness)) && !bytes.Contains(output, []byte("panic:")) && !bytes.Contains(output, []byte("[build failed]"))
		rows = append(rows, row)
		encoded, _ := json.MarshalIndent(rows, "", "  ")
		must(os.WriteFile(filepath.Join(*out, "results.json"), append(encoded, '\n'), 0600))
		fmt.Printf("%s detected=%v baseline=%d plant=%d\n", p.Name, row.Detected, row.BaselineExit, row.Exit)
		if !row.Detected {
			os.Exit(1)
		}
	}
}
