package deploy

import (
	"os"
	"path/filepath"
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

// Every shipped daemon unit uses its own executable's preflight and exclusive
// config group. Bounded missing/wrong-executable counterexamples calibrate this
// inventory checker. This does not claim an actual systemd start on Linux.
func TestInstalledUnitPreflight(t *testing.T) {
	paths, e := filepath.Glob("templates/systemd/*.service.in")
	if e != nil || len(paths) == 0 {
		t.Fatal("missing unit inventory", e)
	}
	for _, path := range paths {
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
