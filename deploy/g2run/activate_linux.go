//go:build linux

package g2run

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
)

type ActivationDeps struct {
	Lookup    PortLookupOps
	Groups    PortGroupReader
	Units     PortUnitControl
	Ledger    PortLedgerWriter
	State     PortStateChecker
	Tmpfiles  PortTmpfiles
	Installed PortInstalledChecker
}

// Activation ports the body called by the existing host-flow's Activate
// callback. The caller MUST use RunG2HostFlow, preserving its preflight,
// sysusers and post-apply account checks before invoking this operation.
// The E2 plan adapter is intentionally not provided in this unit.
type Activation struct {
	FS                                                                         PortFS
	Purpose                                                                    string
	Release, Stage, Log, Ledger, Rendered                                      string
	ConfigParent, Wallet, Status, AgentKey, StationAgentKey, RehearsalAgentKey string
	TmpfilesConf, VersionParent, VersionRoot, UnitDirectory, Unit              string
	DataDirs                                                                   []string
	ServiceUser, PeerGroup, StatusGroup, AgentUser, Operator                   string
	ServiceUID, ServiceGID, PeerGID, StatusGID, AgentUID, AgentGID             uint32
	Deps                                                                       ActivationDeps
}

func (Activation) Kind() string { return "activation" }
func (a Activation) Validate() error {
	if e := a.FS.Validate(); e != nil {
		return e
	}
	if !portPurpose(a.Purpose) || !portUnit(a.Unit) {
		return errors.New("ACTIVATION_PARAMETERS")
	}
	if a.Deps.Lookup == nil || a.Deps.Groups == nil || a.Deps.Units == nil || a.Deps.Ledger == nil || a.Deps.State == nil || a.Deps.Tmpfiles == nil || a.Deps.Installed == nil {
		return errors.New("ACTIVATION_E2_DEPENDENCIES")
	}
	for _, n := range []string{a.ServiceUser, a.PeerGroup, a.StatusGroup, a.AgentUser, a.Operator} {
		if !portAccount(n) {
			return errors.New("ACTIVATION_ACCOUNT")
		}
	}
	for _, id := range []uint32{a.ServiceUID, a.ServiceGID, a.PeerGID, a.StatusGID, a.AgentUID, a.AgentGID} {
		if id == ^uint32(0) {
			return errors.New("ACTIVATION_ID")
		}
	}
	if a.ServiceGID == a.PeerGID || a.ServiceGID == a.StatusGID || a.PeerGID == a.StatusGID || a.AgentGID == a.ServiceGID || a.AgentGID == a.PeerGID || a.AgentGID == a.StatusGID {
		return errors.New("ACTIVATION_GROUP_SEPARATION")
	}
	paths := []string{a.Release, a.Stage, a.Log, a.Ledger, a.Rendered, a.ConfigParent, a.Wallet, a.Status, a.AgentKey, a.StationAgentKey, a.RehearsalAgentKey, a.TmpfilesConf, a.VersionParent, a.VersionRoot, a.UnitDirectory, filepath.Dir(a.AgentKey)}
	paths = append(paths, a.DataDirs...)
	if e := portPaths(a.FS, paths...); e != nil {
		return e
	}
	if len(a.DataDirs) == 0 || len(a.DataDirs) > 64 {
		return errors.New("ACTIVATION_DATA_DIRS")
	}
	wantKey := a.StationAgentKey
	if a.Purpose == "rehearsal" {
		wantKey = a.RehearsalAgentKey
	}
	if a.StationAgentKey == a.RehearsalAgentKey || a.AgentKey != wantKey {
		return errors.New("ACTIVATION_AGENT_KEY_PURPOSE")
	}
	livePaths := append([]string{a.Wallet, a.ConfigParent, a.Status, a.TmpfilesConf, a.VersionParent, a.VersionRoot, a.UnitDirectory, a.AgentKey, a.Release, a.Ledger}, a.DataDirs...)
	for _, workspace := range []string{a.Stage, a.Log} {
		for _, live := range livePaths {
			if portWithin(workspace, live) || portWithin(live, workspace) {
				return errors.New("ACTIVATION_WORKSPACE_OVERLAP")
			}
		}
	}
	if !portWithin(a.VersionRoot, a.VersionParent) || a.VersionRoot == a.VersionParent {
		return errors.New("ACTIVATION_VERSION_ROOT")
	}
	return nil
}
func portDigestBytes(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func (a Activation) Do(c *Ctx) error {
	if e := a.Validate(); e != nil {
		return e
	}
	if c == nil || !portAbs(c.State) {
		return errors.New("ACTIVATION_CONTEXT")
	}
	if !portWithin(a.Log, c.State) || a.Log == c.State {
		return errors.New("ACTIVATION_LOG_ROOT")
	}
	return a.activate(c)
}
func (a Activation) activate(c *Ctx) error {
	raw, e := a.FS.read(a.Release + "/manifest.json")
	if e != nil {
		return errors.New("ACTIVATION_RELEASE_READ")
	}
	h12, awSHA, e := releasePortFacts(raw)
	if e != nil {
		return e
	}
	releaseSHA := portDigestBytes(raw)
	sums, e := a.FS.read(a.Release + "/SHA256SUMS")
	if e != nil {
		return errors.New("ACTIVATION_RELEASE_SUMS")
	}
	listed, e := portReleaseSums(sums)
	if e != nil {
		return e
	}
	for _, p := range []string{"templates/systemd/swarma-wallet.service.in", "templates/systemd/swarma-wallet-g2-status.conf.in", "bin/agent-walletd"} {
		want, ok := listed[p]
		if !ok {
			return errors.New("ACTIVATION_RELEASE_UNLISTED")
		}
		got, e := a.FS.hash(a.Release + "/" + p)
		if e != nil || got != want {
			return errors.New("ACTIVATION_RELEASE_DIGEST")
		}
		if p == "bin/agent-walletd" && got != awSHA {
			return errors.New("ACTIVATION_ARTIFACT_DIGEST")
		}
	}
	if e = a.accounts(c); e != nil {
		return e
	}
	keep := "d6"
	if a.Purpose == "rehearsal" {
		keep = "rehearsal"
	}
	file := func(dst, src string, uid, gid, mode uint32, ret string) error {
		return a.change(c, PortLedgerChange{Kind: "create-file", Path: dst, Source: src, UID: uid, GID: gid, Mode: mode, Retention: ret})
	}
	dir := func(p string) error {
		return a.change(c, PortLedgerChange{Kind: "create-dir", Path: p, UID: 0, GID: 0, Mode: 0755, Retention: "remove"})
	}
	// Every installed write is delegated to the ledger, including membership.
	if e = file(a.TmpfilesConf, a.Rendered+"/tmpfiles.conf", 0, 0, 0644, "remove"); e != nil {
		return e
	}
	if e = a.Deps.Tmpfiles.Create(c, a.TmpfilesConf); e != nil {
		return e
	}
	checks := []PortStatExpectation{{Path: a.ConfigParent, UID: 0, GID: 0, Mode: 0755, Directory: true}, {Path: a.Wallet, UID: 0, GID: a.ServiceGID, Mode: 0750, Directory: true}, {Path: a.Status, UID: a.ServiceUID, GID: a.StatusGID, Mode: 0750, Directory: true}}
	for _, d := range a.DataDirs {
		checks = append(checks, PortStatExpectation{Path: d, UID: a.ServiceUID, GID: a.ServiceGID, Mode: 0700, Directory: true})
	}
	if e = a.expect(c, checks); e != nil {
		return e
	}
	if e = file(a.Wallet+"/service.json", a.Rendered+"/service.json", 0, a.ServiceGID, 0640, keep); e != nil {
		return e
	}
	checks = nil
	for _, n := range []string{"service.json", "receipt.key", "wallet.json"} {
		checks = append(checks, PortStatExpectation{Path: a.Wallet + "/" + n, UID: 0, GID: a.ServiceGID, Mode: 0640, Links: 1, NonEmpty: true})
	}
	checks = append(checks, PortStatExpectation{Path: a.AgentKey, UID: a.AgentUID, GID: a.AgentGID, Mode: 0600, Links: 1}, PortStatExpectation{Path: filepath.Dir(a.AgentKey), UID: 0, GID: 0, Mode: 0755, Directory: true})
	if e = a.expect(c, checks); e != nil {
		return e
	}
	spec := InstallManifestSpec{ReleaseSHA: releaseSHA, Service: "wallet", WalletDir: a.Wallet, GID: a.ServiceGID}
	manifest, e := BuildInstallManifest(a.FS, spec)
	if e != nil {
		return e
	}
	if e = a.FS.writeAtomic(a.Stage+"/install-manifest.json", manifest, 0600); e != nil {
		return e
	}
	approved, e := a.FS.read(a.Stage + "/approved-hashes.json")
	if e != nil {
		return errors.New("ACTIVATION_APPROVED_READ")
	}
	if e = CheckInstallManifest(a.FS, manifest, approved, spec); e != nil {
		return e
	}
	if e = file(a.Wallet+"/install-manifest.json", a.Stage+"/install-manifest.json", 0, a.ServiceGID, 0644, keep); e != nil {
		return e
	}
	// Sign the actual installed bytes, after comparing them to the approved candidate.
	installed, e := a.FS.read(a.Wallet + "/install-manifest.json")
	if e != nil || !bytes.Equal(installed, manifest) {
		return errors.New("ACTIVATION_INSTALLED_MANIFEST")
	}
	signature, public, e := signPortInstall(installed, rand.Reader)
	if e != nil {
		return e
	}
	if e = a.FS.writeAtomic(a.Stage+"/install-manifest.json.sig", signature, 0600); e != nil {
		return e
	}
	if e = a.FS.writeAtomic(a.Stage+"/install.pub.b64", []byte(public), 0600); e != nil {
		return e
	}
	if e = file(a.Wallet+"/install-manifest.json.sig", a.Stage+"/install-manifest.json.sig", 0, a.ServiceGID, 0644, keep); e != nil {
		return e
	}
	dropdir := a.UnitDirectory + "/" + a.Unit + ".d"
	if e = dir(dropdir); e != nil {
		return e
	}
	anchor, e := configguard.RenderDropIn(configguard.Anchor{Manifest: a.Wallet + "/install-manifest.json", Signature: a.Wallet + "/install-manifest.json.sig", Digest: portDigestBytes(installed), Release: releaseSHA, Algorithm: "ed25519", PublicKey: public})
	if e != nil {
		return errors.New("ACTIVATION_ANCHOR")
	}
	if e = a.FS.writeAtomic(a.Stage+"/10-install.conf", anchor, 0600); e != nil {
		return e
	}
	if e = file(dropdir+"/10-install.conf", a.Stage+"/10-install.conf", 0, 0, 0644, "remove"); e != nil {
		return e
	}
	for _, d := range []string{a.VersionParent, a.VersionRoot, a.VersionRoot + "/" + h12, a.VersionRoot + "/" + h12 + "/bin"} {
		if e = dir(d); e != nil {
			return e
		}
	}
	binary := a.VersionRoot + "/" + h12 + "/bin/agent-walletd"
	if e = file(binary, a.Release+"/bin/agent-walletd", 0, 0, 0755, "remove"); e != nil {
		return e
	}
	unitTemplate, e := a.FS.read(a.Release + "/templates/systemd/swarma-wallet.service.in")
	if e != nil {
		return e
	}
	statusTemplate, e := a.FS.read(a.Release + "/templates/systemd/swarma-wallet-g2-status.conf.in")
	if e != nil {
		return e
	}
	// Re-check the exact template bytes used, rather than trusting an earlier open.
	if portDigestBytes(unitTemplate) != listed["templates/systemd/swarma-wallet.service.in"] || portDigestBytes(statusTemplate) != listed["templates/systemd/swarma-wallet-g2-status.conf.in"] {
		return errors.New("ACTIVATION_TEMPLATE_CHANGED")
	}
	rendered := bytes.ReplaceAll(unitTemplate, []byte("@VERSION@"), []byte(h12))
	staged, e := a.FS.read(a.Stage + "/" + a.Unit)
	if e != nil || !bytes.Equal(staged, rendered) {
		return errors.New("ACTIVATION_STAGED_UNIT_CHANGED")
	}
	if e = a.FS.writeAtomic(a.Stage+"/"+a.Unit+".s7", rendered, 0600); e != nil {
		return e
	}
	status := bytes.ReplaceAll(statusTemplate, []byte("@VERSION@"), []byte(h12))
	status = bytes.ReplaceAll(status, []byte("@OPERATOR_GID@"), []byte(strconv.FormatUint(uint64(a.StatusGID), 10)))
	if bytes.ContainsRune(staged, '@') || bytes.ContainsRune(status, '@') {
		return errors.New("ACTIVATION_UNFILLED_TOKEN")
	}
	lines, textErr := installLines(staged)
	if textErr != nil || validateUnitText(status) != nil {
		return errors.New("ACTIVATION_INSTALL_TEXT")
	}
	if len(lines) != 1 || lines[0] != "WantedBy=multi-user.target" {
		return errors.New("ACTIVATION_INSTALL_SECTION")
	}
	if e = a.FS.writeAtomic(a.Stage+"/g2-status.conf", status, 0600); e != nil {
		return e
	}
	if e = file(a.UnitDirectory+"/"+a.Unit, a.Stage+"/"+a.Unit, 0, 0, 0644, "remove"); e != nil {
		return e
	}
	if e = file(dropdir+"/g2-status.conf", a.Stage+"/g2-status.conf", 0, 0, 0644, "remove"); e != nil {
		return e
	}
	if a.Purpose == "station" {
		if e = a.operatorGroups(c, false); e != nil {
			return e
		}
		if e = a.change(c, PortLedgerChange{Kind: "add-member", User: a.Operator, Group: a.StatusGroup}); e != nil {
			return e
		}
		if e = a.operatorGroups(c, true); e != nil {
			return e
		}
	}
	if e = a.Deps.Units.Reload(c); e != nil {
		return e
	}
	unit, e := portUnitInfo(c, a.Deps.Units, a.Unit)
	if e != nil {
		return e
	}
	if strings.Count(unit.ExecStartPre, "path=") != 1 || strings.Count(unit.ExecStart, "path=") != 1 {
		return errors.New("ACTIVATION_EXEC_ENTRY_COUNT")
	}
	if !strings.Contains(unit.ExecStartPre, "path="+binary+" ") || !strings.Contains(unit.ExecStartPre, "--check-installed") {
		return errors.New("ACTIVATION_EXEC_PRE")
	}
	statusArgs := "-status-socket " + a.Status + "/status.sock -status-gid " + strconv.FormatUint(uint64(a.StatusGID), 10)
	if !strings.Contains(unit.ExecStart, "path="+binary+" ") || !strings.Contains(unit.ExecStart, statusArgs) {
		return errors.New("ACTIVATION_EXEC_MAIN")
	}
	// E1's output path is relative to the state and is opened by the typed E2
	// wrapper before it starts the program. No argument contains a typed value.
	output, e := filepath.Rel(c.State, a.Log+"/s8-1-check-installed.out")
	if e != nil || !validPackagePath(output) {
		return errors.New("ACTIVATION_OUTPUT")
	}
	check := PortInstalledCheck{Binary: binary, Output: output, Credential: Cred{UID: a.ServiceUID, GID: a.PeerGID, Groups: []uint32{a.ServiceGID, a.StatusGID}}}
	if e = a.Deps.Installed.CheckInstalled(c, check); e != nil {
		return e
	}
	if a.Purpose == "rehearsal" {
		return nil
	}
	if e = a.FS.writeAtomic(a.Stage+"/started-"+a.Unit, nil, 0600); e != nil {
		return e
	}
	return a.Deps.Units.Start(c, a.Unit)
}
func (a Activation) change(c *Ctx, v PortLedgerChange) error {
	if e := v.Validate(); e != nil {
		return e
	}
	if v.Path != "" && !a.FS.allowed(v.Path) || v.Source != "" && !a.FS.allowed(v.Source) {
		return errors.New("ACTIVATION_LEDGER_PATH")
	}
	return a.Deps.Ledger.Apply(c, a.Ledger, v)
}
func (a Activation) expect(c *Ctx, checks []PortStatExpectation) error {
	for _, s := range checks {
		if !a.FS.allowed(s.Path) {
			return errors.New("ACTIVATION_STAT_PATH")
		}
		if e := a.Deps.State.Expect(c, s); e != nil {
			return e
		}
	}
	return nil
}
func (a Activation) accounts(c *Ctx) error {
	for _, q := range []struct {
		db      PortDatabase
		name    string
		id      uint32
		primary *uint32
	}{{PortPasswd, a.ServiceUser, a.ServiceUID, &a.ServiceGID}, {PortGroup, a.ServiceUser, a.ServiceGID, nil}, {PortGroup, a.PeerGroup, a.PeerGID, nil}, {PortGroup, a.StatusGroup, a.StatusGID, nil}, {PortPasswd, a.AgentUser, a.AgentUID, nil}, {PortGroup, a.AgentUser, a.AgentGID, nil}} {
		r, e := lookupPort(c, a.Deps.Lookup, PortLookup{q.db, q.name})
		if e != nil {
			return e
		}
		if r == nil || r.ID != q.id || q.primary != nil && r.Primary != *q.primary {
			return errors.New("ACTIVATION_ACCOUNT_MISMATCH")
		}
	}
	return nil
}
func (a Activation) operatorGroups(c *Ctx, need bool) error {
	groups, e := portGroups(c, a.Deps.Groups, a.Operator)
	if e != nil {
		return e
	}
	status := false
	for _, g := range groups {
		if g.Name == a.PeerGroup || g.ID == a.PeerGID {
			return errors.New("ACTIVATION_OPERATOR_PEER_GROUP")
		}
		if g.Name == a.StatusGroup && g.ID == a.StatusGID {
			status = true
		}
	}
	if need && !status {
		return errors.New("ACTIVATION_OPERATOR_STATUS_GROUP")
	}
	return nil
}
func releasePortFacts(raw []byte) (string, string, error) {
	var m map[string]any
	if decodePortJSON(raw, &m) != nil {
		return "", "", errors.New("ACTIVATION_RELEASE_JSON")
	}
	commit, ok := m["commit"].(string)
	if !ok || !portHex(commit, 40) {
		return "", "", errors.New("ACTIVATION_RELEASE_COMMIT")
	}
	artifacts, ok := m["artifacts"].([]any)
	if !ok {
		return "", "", errors.New("ACTIVATION_ARTIFACTS")
	}
	sha := ""
	for _, v := range artifacts {
		a, ok := portObject(v)
		if !ok {
			return "", "", errors.New("ACTIVATION_ARTIFACTS")
		}
		if a["binary"] != "bin/agent-walletd" {
			continue
		}
		s, ok := a["sha256"].(string)
		if !ok || !portHex(s, 64) || sha != "" {
			return "", "", errors.New("ACTIVATION_ARTIFACTS")
		}
		sha = s
	}
	if sha == "" {
		return "", "", errors.New("ACTIVATION_ARTIFACTS")
	}
	return commit[:12], sha, nil
}
func portReleaseSums(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		p := strings.SplitN(line, "  ", 2)
		if len(p) != 2 || !portHex(p[0], 64) {
			return nil, errors.New("ACTIVATION_RELEASE_SUMS")
		}
		name := strings.TrimPrefix(p[1], "./")
		if !validPackagePath(name) || out[name] != "" {
			return nil, errors.New("ACTIVATION_RELEASE_SUMS")
		}
		out[name] = p[0]
	}
	return out, nil
}
func signPortInstall(raw []byte, random io.Reader) ([]byte, string, error) {
	var seed [ed25519.SeedSize]byte
	defer clear(seed[:])
	if _, e := io.ReadFull(random, seed[:]); e != nil {
		return nil, "", errors.New("ACTIVATION_SIGN_RANDOM")
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	clear(seed[:])
	defer clear(private)
	message := append([]byte(configguard.SignatureDomain), raw...)
	defer clear(message)
	signature := ed25519.Sign(private, message)
	der, e := x509.MarshalPKIXPublicKey(private.Public())
	if e != nil {
		return nil, "", errors.New("ACTIVATION_SIGN_KEY")
	}
	encoded, e := json.Marshal(configguard.Signature{Version: 1, Algorithm: "ed25519", Value: base64.StdEncoding.EncodeToString(signature)})
	if e != nil {
		return nil, "", errors.New("ACTIVATION_SIGNATURE")
	}
	return append(encoded, '\n'), base64.StdEncoding.EncodeToString(der), nil
}
