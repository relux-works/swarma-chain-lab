package deploy

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func installedUnitValid(raw []byte, service string) bool {
	fields := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = append(fields[key], value)
		}
	}
	if len(fields["ExecStart"]) != 1 || len(fields["ExecStartPre"]) < 1 || len(fields["User"]) != 1 || fields["User"][0] != "swarma-"+service {
		return false
	}
	start := strings.Fields(fields["ExecStart"][0])
	if len(start) == 0 {
		return false
	}
	if fields["ExecStartPre"][0] != start[0]+" --check-installed" {
		return false
	}
	group := "swarma-" + service
	if service == "wallet" || service == "model" {
		return len(fields["Group"]) == 1 && fields["Group"][0] == group+"-peer" && len(fields["SupplementaryGroups"]) == 1 && fields["SupplementaryGroups"][0] == group
	}
	return len(fields["Group"]) == 1 && fields["Group"][0] == group
}

const g2StatusTemplate = "templates/systemd/swarma-wallet-g2-status.conf.in"

func resolvedG2StatusValid(raw, version, gid string) bool {
	if strings.Contains(raw, "@") {
		return false
	}
	n, err := strconv.ParseUint(gid, 10, 32)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != gid {
		return false
	}
	want := "[Service]\n" +
		"SupplementaryGroups=swarma-wallet swarma-wallet-status\n" +
		"ReadWritePaths=/run/swarma-wallet-status\n" +
		"ExecStart=\n" +
		"ExecStart=/opt/swarma/wallet/" + version + "/bin/agent-walletd --config /etc/swarma/wallet/service.json -status-socket /run/swarma-wallet-status/status.sock -status-gid " + gid + "\n"
	return raw == want
}

// Claim: substitution yields exactly the documented status command after its reset; bounded defects refuse without starting systemd.
func TestInstalledG2StatusDropIn(t *testing.T) {
	raw, err := os.ReadFile(g2StatusTemplate)
	if err != nil {
		t.Fatal(err)
	}
	version, gid := "release-test-0123456789ab", "230301"
	if strings.Count(string(raw), "@VERSION@") != 1 || strings.Count(string(raw), "@OPERATOR_GID@") != 1 {
		t.Fatal("drop-in must carry both release placeholders exactly once")
	}
	resolved := strings.NewReplacer("@VERSION@", version, "@OPERATOR_GID@", gid).Replace(string(raw))
	if !resolvedG2StatusValid(resolved, version, gid) {
		t.Fatal("unresolved or invalid G2 status drop-in command/reset")
	}
	main, err := os.ReadFile("templates/systemd/swarma-wallet.service.in")
	if err != nil {
		t.Fatal(err)
	}
	mainResolved := strings.ReplaceAll(string(main), "@VERSION@", version)
	if strings.Contains(mainResolved, "@") || !strings.Contains(mainResolved, "ExecStart=/opt/swarma/wallet/"+version+"/bin/agent-walletd --config /etc/swarma/wallet/service.json\n") {
		t.Fatal("main unit and drop-in version convention differ")
	}
	for name, bad := range map[string]string{
		"unresolved-version": strings.ReplaceAll(resolved, version, "@VERSION@"),
		"unresolved-gid":     strings.ReplaceAll(resolved, gid, "@OPERATOR_GID@"),
		"missing-reset":      strings.Replace(resolved, "ExecStart=\n", "", 1),
		"reset-after-start":  strings.Replace(resolved, "ExecStart=\n", "", 1) + "ExecStart=\n",
		"wrong-version":      strings.ReplaceAll(resolved, version, "other-release"),
		"wrong-binary":       strings.ReplaceAll(resolved, "/bin/agent-walletd", "/bin/other"),
		"missing-status":     strings.ReplaceAll(resolved, " -status-socket /run/swarma-wallet-status/status.sock", ""),
		"extra-flag":         strings.ReplaceAll(resolved, " --config", " --unexpected --config"),
		"nonnumeric-gid":     strings.ReplaceAll(resolved, gid, "operator"),
		"zero-gid":           strings.ReplaceAll(resolved, gid, "0"),
	} {
		t.Run(name, func(t *testing.T) {
			if resolvedG2StatusValid(bad, version, gid) {
				t.Fatal("checker accepted planted drop-in defect")
			}
		})
	}
	if resolvedG2StatusValid(strings.ReplaceAll(resolved, gid, "operator"), version, "operator") || resolvedG2StatusValid(strings.ReplaceAll(resolved, gid, "0"), version, "0") {
		t.Fatal("checker accepted nonnumeric or root operator GID")
	}
}

// Claim: the SERVICE.md status example and source-of-truth link match the committed release template byte for byte.
func TestG2StatusDocumentationMatchesTemplate(t *testing.T) {
	raw, err := os.ReadFile(g2StatusTemplate)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../experiments/agent-wallet/SERVICE.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "### Status socket access (G2)\n")
	if !ok {
		t.Fatal("missing status socket documentation")
	}
	_, example, ok := strings.Cut(section, "```ini\n")
	if !ok {
		t.Fatal("missing status drop-in example")
	}
	example, _, ok = strings.Cut(example, "```")
	if !ok || !bytes.Equal([]byte(example), raw) || !strings.Contains(section, "../../deploy/"+g2StatusTemplate) {
		t.Fatal("SERVICE.md differs from released G2 status template or lacks its source link")
	}
}

// Every DK5 daemon unit uses its own executable's preflight and exclusive
// config group. Bounded missing/wrong-executable counterexamples calibrate this
// inventory checker. This does not claim an actual systemd start on Linux.
func TestInstalledUnitPreflight(t *testing.T) {
	paths, e := filepath.Glob("templates/systemd/*.service.in")
	if e != nil || len(paths) == 0 {
		t.Fatal("missing unit inventory", e)
	}
	for _, path := range paths {
		// The separately provisioned journal forwarder has no wallet DK5 inputs; its unit contract is checked by TestInstalledWalletAlertForwarderUnit.
		if filepath.Base(path) == "swarma-wallet-alert-forwarder.service.in" {
			continue
		}
		service := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "swarma-"), ".service.in")
		t.Run(service, func(t *testing.T) {
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if !installedUnitValid(raw, service) {
				t.Fatal("installed unit lacks own preflight/config group")
			}
			for _, mutant := range []string{strings.Replace(string(raw), "ExecStartPre=", "DisabledPreflight=", 1), strings.Replace(string(raw), " --check-installed", " --wrong-check", 1), strings.Replace(string(raw), "User=swarma-"+service, "User=root", 1)} {
				if installedUnitValid([]byte(mutant), service) {
					t.Fatal("unit checker missed planted violation")
				}
			}
		})
	}
	raw, e := os.ReadFile("templates/wallet/tmpfiles.conf.in")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), "/etc/swarma/wallet 0750 root swarma-wallet ") {
		t.Fatal("wallet config shared with peer group")
	}
}

func resolvedForwarderValid(raw, version string) bool {
	if strings.Contains(raw, "@") {
		return false
	}
	fields := map[string][]string{}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = append(fields[key], value)
		}
	}
	want := map[string]string{
		"Type": "simple", "User": "swarma-wallet-alerts", "Group": "swarma-wallet-alerts",
		"SupplementaryGroups": "systemd-journal", "Restart": "no", "UMask": "0077",
		"StateDirectory": "swarma-wallet-alerts", "StateDirectoryMode": "0700",
		"WorkingDirectory":  "/var/lib/swarma-wallet-alerts",
		"ExecStart":         "/opt/swarma/wallet/" + version + "/bin/agent-wallet-alert-forwarder --config /etc/swarma/wallet-alerts/forwarder.json",
		"ReadWritePaths":    "/var/lib/swarma-wallet-alerts",
		"InaccessiblePaths": "/etc/swarma/wallet /var/lib/swarma-wallet",
		"NoNewPrivileges":   "true", "ProtectSystem": "strict", "ProtectHome": "true",
	}
	for key, value := range want {
		if len(fields[key]) != 1 || fields[key][0] != value {
			return false
		}
	}
	// The forwarder has its own config admission and cannot consume wallet DK5 files or run the reconciler.
	return len(fields["ExecStartPre"]) == 0 && len(fields["Environment"]) == 0 && len(fields["EnvironmentFile"]) == 0
}

// Claim: the shipped F6 follower resolves @VERSION@ to its release binary with a separate journal identity and no restart or wallet access; bounded defects refuse without starting systemd.
func TestInstalledWalletAlertForwarderUnit(t *testing.T) {
	raw, err := os.ReadFile(forwarderTemplate)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile("../experiments/agent-wallet/operator/swarma-wallet-alert-forwarder.service.in")
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("release unit differs from the F6 design", err)
	}
	if strings.Count(string(raw), "@VERSION@") != 1 {
		t.Fatal("expected one release placeholder")
	}
	version := "release-test-0123456789ab"
	resolved := strings.ReplaceAll(string(raw), "@VERSION@", version)
	if !resolvedForwarderValid(resolved, version) {
		t.Fatal("resolved forwarder refused")
	}
	for name, bad := range map[string]string{
		"unresolved-version": string(raw),
		"wrong-version":      strings.ReplaceAll(resolved, version, "other-release"),
		"wrong-binary":       strings.ReplaceAll(resolved, "/bin/agent-wallet-alert-forwarder", "/bin/agent-wallet-reconcile"),
		"wallet-identity":    strings.ReplaceAll(resolved, "User=swarma-wallet-alerts", "User=swarma-wallet"),
		"wallet-group":       strings.ReplaceAll(resolved, "SupplementaryGroups=systemd-journal", "SupplementaryGroups=systemd-journal swarma-wallet"),
		"automatic-retry":    strings.ReplaceAll(resolved, "Restart=no", "Restart=on-failure"),
		"wallet-access":      strings.ReplaceAll(resolved, "InaccessiblePaths=", "DisabledInaccessiblePaths="),
		"dk5-environment":    resolved + "Environment=SWARMA_INSTALL_MANIFEST=/etc/swarma/wallet/install-manifest.json\n",
		"duplicate-start":    resolved + "ExecStart=/bin/false\n",
	} {
		t.Run(name, func(t *testing.T) {
			if resolvedForwarderValid(bad, version) {
				t.Fatal("forwarder checker missed planted defect")
			}
		})
	}
}
