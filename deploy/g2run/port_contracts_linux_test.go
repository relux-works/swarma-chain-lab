//go:build linux

package g2run

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
)

// Claim: the port's deterministic signature and public-key bytes match a vector
// captured through the unchanged original CLI's -manifest path, and the actual
// production DK5 verifier accepts it. A raw-manifest signature is rejected by
// that verifier, even with the same manifest, public key and anchor.
func TestInstallSignatureDomainOriginalCLI(t *testing.T) {
	var v struct {
		SeedHex                              string `json:"seed_hex"`
		Manifest, Signature, Public, Release string
		GID                                  int
		Files                                map[string]string
	}
	portFixture(t, "install_signature", &v)
	seed, e := hex.DecodeString(v.SeedHex)
	if e != nil {
		t.Fatal(e)
	}
	signature, public, e := signPortInstall([]byte(v.Manifest), bytes.NewReader(seed))
	if e != nil {
		t.Fatal(e)
	}
	if string(signature) != v.Signature || public != v.Public {
		t.Fatal("signature/public bytes differ from original g2-install-sign -manifest vector")
	}
	manifestPath := "/etc/example/wallet/install-manifest.json"
	signaturePath := manifestPath + ".sig"
	anchor, e := configguard.RenderDropIn(configguard.Anchor{Manifest: manifestPath, Signature: signaturePath, Digest: portSHA([]byte(v.Manifest)), Release: v.Release, Algorithm: "ed25519", PublicKey: public})
	if e != nil {
		t.Fatal(e)
	}
	files := map[string][]byte{}
	for p, content := range v.Files {
		files[p] = []byte(content)
	}
	paths := []string{"/etc/example/wallet/receipt.key", "/etc/example/wallet/service.json", "/etc/example/wallet/wallet.json"}
	set := configguard.StagedSet{Anchor: anchor, Manifest: []byte(v.Manifest), Signature: signature, Files: files}
	policy := configguard.StagedPolicy{ManifestPath: manifestPath, SignaturePath: signaturePath, ReleaseSHA256: v.Release, Service: "wallet", GID: v.GID, Paths: paths}
	if e = configguard.ValidateStagedSet(set, policy); e != nil {
		t.Fatal("production DK5 verifier refused original-compatible signature:", e)
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	rawSig, _ := json.Marshal(configguard.Signature{Version: 1, Algorithm: "ed25519", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(private, set.Manifest))})
	set.Signature = append(rawSig, '\n')
	requirePortError(t, configguard.ValidateStagedSet(set, policy), "DK5_SIGNATURE_INVALID")
}

func activationStagedSet(t *testing.T, a Activation) (configguard.StagedSet, configguard.StagedPolicy) {
	t.Helper()
	read := func(p string) []byte {
		b, e := a.FS.read(p)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	manifest := a.Wallet + "/install-manifest.json"
	signature := manifest + ".sig"
	files := map[string][]byte{}
	paths := []string{}
	for _, n := range []string{"receipt.key", "service.json", "wallet.json"} {
		p := a.Wallet + "/" + n
		paths = append(paths, p)
		files[p] = read(p)
	}
	return configguard.StagedSet{Anchor: read(a.UnitDirectory + "/" + a.Unit + ".d/10-install.conf"), Manifest: read(manifest), Signature: read(signature), Files: files}, configguard.StagedPolicy{ManifestPath: manifest, SignaturePath: signature, ReleaseSHA256: portSHA(read(a.Release + "/manifest.json")), Service: "wallet", GID: int(a.ServiceGID), Paths: paths}
}

// Claim: a full activation fixture produces a set accepted by the same DK5
// validator reached by installed admission, rather than a self-consistent raw
// ed25519 verification that could certify a missing signature domain.
func TestActivationProductionDK5Verifier(t *testing.T) {
	a, c, _, _ := activationFixture(t, "station")
	if e := a.Do(c); e != nil {
		t.Fatal(e)
	}
	set, policy := activationStagedSet(t, a)
	if e := configguard.ValidateStagedSet(set, policy); e != nil {
		t.Fatal(e)
	}
}

func mutateInstallUnit(base, mutation, separator string) string {
	switch mutation {
	case "crlf":
		return strings.ReplaceAll(base, "\n", "\r\n")
	case "trailing-space":
		return strings.ReplaceAll(base, "WantedBy=multi-user.target\n", "WantedBy=multi-user.target \n")
	case "hidden":
		return base + "# hidden" + separator + "RequiredBy=other.target\n"
	case "control":
		return base + "# control" + separator + "ignored\n"
	case "spaced-key":
		return base + " RequiredBy=other.target\n"
	}
	return base
}

type installUnitVectors struct {
	Cases []struct {
		Name, Mutation, Separator string
		ScopeOK                   bool   `json:"scope_ok"`
		ActivationOK              bool   `json:"activation_ok"`
		ScopeRefusal              string `json:"scope_refusal"`
		ActivationRefusal         string `json:"activation_refusal"`
	}
}

// Claim: LF/CRLF scope controls agree with the source; every unsupported control
// or hidden Install key refuses before writing scope output. Original oracle
// outcomes are recorded separately where the control policy requires a stricter refusal.
func TestScopeInstallLineModel(t *testing.T) {
	var v struct {
		Commit, Wallet string
		Layout         InstallScopeLayout
	}
	portFixture(t, "scope", &v)
	var cases installUnitVectors
	portFixture(t, "unit_text", &cases)
	for _, tc := range cases.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			fs, root := portFS(t)
			stage := root + "/stage"
			portMkdir(t, stage)
			l := v.Layout
			l.Purpose = "rehearsal"
			l.Commit = v.Commit
			l.Stage = stage
			portWrite(t, stage+"/"+l.WalletSource, []byte(mutateInstallUnit(v.Wallet, tc.Mutation, tc.Separator)))
			out := root + "/scope.json"
			e := WriteInstallScope(fs, l, out)
			if tc.ScopeOK {
				if e != nil {
					t.Fatal(e)
				}
				return
			}
			requirePortError(t, e, tc.ScopeRefusal)
			if _, e = os.Lstat(out); !os.IsNotExist(e) {
				t.Fatal("refusal wrote scope output")
			}
		})
	}
}
func replaceActivationUnitTemplate(t *testing.T, a Activation, mutation, separator string) {
	t.Helper()
	path := a.Release + "/templates/systemd/swarma-wallet.service.in"
	raw, e := a.FS.read(path)
	if e != nil {
		t.Fatal(e)
	}
	body := []byte(mutateInstallUnit(string(raw), mutation, separator))
	portWrite(t, path, body)
	sums, e := a.FS.read(a.Release + "/SHA256SUMS")
	if e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(string(sums), "\n")
	for i, line := range lines {
		if strings.HasSuffix(line, "  templates/systemd/swarma-wallet.service.in") {
			lines[i] = portSHA(body) + "  templates/systemd/swarma-wallet.service.in"
		}
	}
	portWrite(t, a.Release+"/SHA256SUMS", []byte(strings.Join(lines, "\n")))
	portWrite(t, a.Stage+"/"+a.Unit, bytes.ReplaceAll(body, []byte("@VERSION@"), []byte(strings.Repeat("a", 12))))
}

// Claim: activation compares the raw Install key line (including trailing blanks
// or CR), and refuses all control/hidden-key neighbors before installing its unit,
// changing operator membership, checking the binary or starting the service.
func TestActivationInstallLineModel(t *testing.T) {
	var v installUnitVectors
	portFixture(t, "unit_text", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			a, c, h, exec := activationFixture(t, "station")
			replaceActivationUnitTemplate(t, a, tc.Mutation, tc.Separator)
			e := a.Do(c)
			if tc.ActivationOK {
				if e != nil {
					t.Fatal(e)
				}
				return
			}
			requirePortError(t, e, tc.ActivationRefusal)
			for _, event := range h.events {
				if event == "ledger create-file "+a.UnitDirectory+"/"+a.Unit || strings.HasPrefix(event, "ledger add-member") || event == "start "+a.Unit {
					t.Fatal("forbidden post-refusal effect", event)
				}
			}
			if len(exec.commands) != 0 {
				t.Fatal("ran installed check after refusal")
			}
		})
	}
}

// Claim: agent and wallet group names resolve to the declared numeric GIDs;
// a forged key GID or missing/mismatched named group refuses before ledger work.
// Each AgentGID alias of a wallet/peer/status group also refuses at validation.
func TestActivationNamedGroupBindings(t *testing.T) {
	for _, purpose := range []string{"station", "rehearsal"} {
		for _, mutation := range []string{"valid", "agent-gid", "agent-group-missing", "wallet-group", "wallet-group-missing", "wallet-alias", "peer-alias", "status-alias"} {
			t.Run(purpose+"/"+mutation, func(t *testing.T) {
				a, c, h, _ := activationFixture(t, purpose)
				want := "ACTIVATION_ACCOUNT_MISMATCH"
				switch mutation {
				case "agent-gid":
					a.AgentGID = 22
					h.owners[a.AgentKey] = [2]uint32{a.AgentUID, a.AgentGID}
				case "agent-group-missing":
					h.lookup[PortLookup{PortGroup, a.AgentUser}] = Result{RC: 2}
				case "wallet-group":
					h.addGroup(a.ServiceUser, 99)
				case "wallet-group-missing":
					h.lookup[PortLookup{PortGroup, a.ServiceUser}] = Result{RC: 2}
				case "wallet-alias":
					a.AgentGID = a.ServiceGID
					want = "ACTIVATION_GROUP_SEPARATION"
				case "peer-alias":
					a.AgentGID = a.PeerGID
					want = "ACTIVATION_GROUP_SEPARATION"
				case "status-alias":
					a.AgentGID = a.StatusGID
					want = "ACTIVATION_GROUP_SEPARATION"
				}
				e := a.Do(c)
				if mutation == "valid" {
					if e != nil {
						t.Fatal(e)
					}
					return
				}
				requirePortError(t, e, want)
				for _, event := range h.events {
					if strings.HasPrefix(event, "ledger ") {
						t.Fatal("ledger effect before group refusal", event)
					}
				}
			})
		}
	}
}

// Claim: E3's safe import/member extensions stay closed. Ledger launchers, raw
// syscalls and indirect-launch imports still refuse, while schema-only uses pass.
// The original E1 foreign-source and alternate-exec controls remain unchanged.
func TestStaticGateClosedPortExtensions(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		ok        bool
	}{
		{"schema", "package g2run\nimport l \"github.com/relux-works/swarma-chain-lab/deploy/g2ledger\"\nvar s l.Scope\n", true},
		{"ledger-exec", "package g2run\nimport l \"github.com/relux-works/swarma-chain-lab/deploy/g2ledger\"\nvar run=l.Run\n", false},
		{"ledger-system", "package g2run\nimport l \"github.com/relux-works/swarma-chain-lab/deploy/g2ledger\"\nvar s=l.RealSystem{}\n", false},
		{"ledger-rollback", "package g2run\nimport l \"github.com/relux-works/swarma-chain-lab/deploy/g2ledger\"\nvar run=l.RunRollback\n", false},
		{"syscall", "package g2run\nimport \"golang.org/x/sys/unix\"\nvar run=unix.RawSyscall\n", false},
		{"indirect", "package g2run\nimport \"net/http/cgi\"\nvar h=cgi.Handler{}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "plant.go")
			portWrite(t, p, []byte(tc.src))
			v := execViolations(t, []string{p})
			if (len(v) == 0) != tc.ok {
				t.Fatalf("ok=%v violations=%v", tc.ok, v)
			}
		})
	}
}

// Claim: the generated status drop-in obeys the same no-control-text contract
// as the main unit; a hidden boundary there cannot reach unit publication or start.
// The normal drop-in positive is exercised by TestActivationPortPositive.
func TestActivationStatusDropInControls(t *testing.T) {
	for _, control := range []string{"\r", "\v", "\x00", "\x1b", "\u0085", "\u2028"} {
		t.Run(hex.EncodeToString([]byte(control)), func(t *testing.T) {
			a, c, h, _ := activationFixture(t, "station")
			path := a.Release + "/templates/systemd/swarma-wallet-g2-status.conf.in"
			body, e := a.FS.read(path)
			if e != nil {
				t.Fatal(e)
			}
			body = append(body, []byte("# hidden"+control+"RequiredBy=other.target\n")...)
			portWrite(t, path, body)
			sums, e := a.FS.read(a.Release + "/SHA256SUMS")
			if e != nil {
				t.Fatal(e)
			}
			lines := strings.Split(string(sums), "\n")
			for i, line := range lines {
				if strings.HasSuffix(line, "  templates/systemd/swarma-wallet-g2-status.conf.in") {
					lines[i] = portSHA(body) + "  templates/systemd/swarma-wallet-g2-status.conf.in"
				}
			}
			portWrite(t, a.Release+"/SHA256SUMS", []byte(strings.Join(lines, "\n")))
			requirePortError(t, a.Do(c), "ACTIVATION_INSTALL_TEXT")
			if portContains(h.events, "ledger create-file "+a.UnitDirectory+"/"+a.Unit) || portContains(h.events, "start "+a.Unit) {
				t.Fatal("published a unit after invalid drop-in")
			}
		})
	}
}
