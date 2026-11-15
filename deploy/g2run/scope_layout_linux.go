//go:build linux

package g2run

import (
	"errors"
	"path/filepath"
	"sort"

	"github.com/relux-works/swarma-chain-lab/deploy/g2ledger"
)

// InstallScopeLayout supplies instance roots and identities to the original
// scope generator's compiled path shapes. It is not the engine parameters type
// or a configurable operation list. Stage sources and the upstream pin are data.
type InstallScopeLayout struct {
	Purpose, Commit, Stage                                                         string
	ConfigParent, WalletConfig, Data, Helper, Tmpfiles                             string
	VersionParent, VersionRoot, UnitDirectory, WantsDirectory                      string
	StationAgent, RehearsalAgent                                                   string
	SlotHomes, SlotHelper, SlotStage, SlotConfig, SlotBinary, SlotStop             string
	WalletUser, AgentUser, WalletGroup, PeerGroup, StatusGroup, SlotUser, Operator string
	WalletUnit, SlotUnit, WalletSource, SlotSource, SlotUnitPin                    string
	Node                                                                           *g2ledger.NodeScope
}

// CompileInstallScope preserves the source's station/rehearsal split, complete
// target inventory and parent closure, using only supplied roots and identities.
func CompileInstallScope(l InstallScopeLayout) (ScopeSpec, error) {
	s := ScopeSpec{Purpose: l.Purpose, Commit: l.Commit, Stage: l.Stage, UnitDirectory: l.UnitDirectory, WantsDirectory: l.WantsDirectory}
	if !portPurpose(l.Purpose) {
		return s, errors.New("SCOPE_PURPOSE")
	}
	roots := []string{l.ConfigParent, l.WalletConfig, l.Data, l.Helper, l.Tmpfiles, l.VersionParent, l.VersionRoot, l.UnitDirectory, l.WantsDirectory}
	agent := l.RehearsalAgent
	if l.Purpose == "station" {
		agent = l.StationAgent
		roots = append(roots, l.SlotHomes, l.SlotHelper, l.SlotStage, l.SlotConfig, l.SlotBinary, l.SlotStop)
	}
	roots = append(roots, agent)
	for _, p := range roots {
		if !portAbs(p) || p == "/" {
			return s, errors.New("SCOPE_LAYOUT_PATH")
		}
	}
	add := func(kind string, paths ...string) {
		for _, p := range paths {
			s.Paths = append(s.Paths, g2ledger.ScopePath{Path: p, Kind: kind})
		}
	}
	version := l.VersionRoot + "/@VERSION@"
	drop := l.UnitDirectory + "/" + l.WalletUnit + ".d"
	add("dir", l.ConfigParent, l.WalletConfig, l.Data, l.Data+"/service", l.Data+"/wallet", l.Data+"/kernel", l.Data+"/objects", l.Helper, drop, l.VersionParent, l.VersionRoot, version, version+"/bin")
	add("file", l.Helper+"/udp-probe.py", l.Tmpfiles, l.WalletConfig+"/service.json", l.WalletConfig+"/install-manifest.json", l.WalletConfig+"/install-manifest.json.sig", drop+"/10-install.conf", drop+"/g2-status.conf", version+"/bin/agent-walletd", l.UnitDirectory+"/"+l.WalletUnit)
	add("secret", l.WalletConfig+"/receipt.key", l.WalletConfig+"/wallet.json")
	s.Users = []string{l.WalletUser, l.AgentUser}
	s.Groups = []string{l.WalletGroup, l.PeerGroup, l.StatusGroup, l.AgentUser}
	s.Units = []StagedUnitSpec{{Name: l.WalletUnit, RelativeSource: l.WalletSource}}
	add("dir", agent)
	add("secret", agent+"/agent.key")
	if l.Purpose == "station" {
		if l.Node == nil || !portHex(l.SlotUnitPin, 64) {
			return s, errors.New("SCOPE_LAYOUT_STATION")
		}
		n := *l.Node
		s.Node = &n
		add("file", n.Config)
		add("dir", l.SlotHomes, l.SlotHelper, l.SlotStage, l.SlotConfig)
		add("file", l.SlotHelper+"/probe", l.SlotHelper+"/client.py", l.SlotStage+"/install.py", l.SlotStage+"/stop.sh", l.SlotStage+"/"+l.SlotUnit, l.SlotStage+"/slotd-linux", l.SlotStage+"/policy.json", l.SlotConfig+"/policy.json", l.SlotBinary, l.UnitDirectory+"/"+l.SlotUnit, l.SlotStop)
		s.Users = append(s.Users, l.SlotUser, l.Operator)
		s.Groups = append(s.Groups, l.SlotUser)
		s.Units = append(s.Units, StagedUnitSpec{Name: l.SlotUnit, RelativeSource: l.SlotSource, Pin: l.SlotUnitPin})
	}
	declared := map[string]bool{}
	parents := map[string]bool{}
	for _, p := range s.Paths {
		declared[p.Path] = true
		parents[filepath.Dir(p.Path)] = true
	}
	if l.Purpose == "station" {
		parents[l.WantsDirectory] = true
	}
	for p := range parents {
		if !declared[p] {
			s.Reused = append(s.Reused, p)
		}
	}
	// Rehearsal's config parent pre-exists, but is also a declared target receiving
	// the wallet child. It is the source's one explicit declared-and-reused parent.
	if l.Purpose == "rehearsal" {
		s.Reused = append(s.Reused, l.ConfigParent)
	}
	sort.Strings(s.Reused)
	return s, nil
}

// BuildInstallScope is the complete g2-scope port: compile the fixed target
// shapes, then validate and bind the staged unit sources without symlinks.
func BuildInstallScope(fs PortFS, l InstallScopeLayout) (g2ledger.Scope, error) {
	s, e := CompileInstallScope(l)
	if e != nil {
		return g2ledger.Scope{}, e
	}
	return BuildScope(fs, s)
}
func WriteInstallScope(fs PortFS, l InstallScopeLayout, out string) error {
	s, e := CompileInstallScope(l)
	if e != nil {
		return e
	}
	return WriteScope(fs, s, out)
}
