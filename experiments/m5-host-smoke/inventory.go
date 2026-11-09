package smoke

import "regexp"

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var versionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+_-]{0,63}$`)

func (v Inventory) validate() error {
	if !commitPattern.MatchString(v.Source) || !commitPattern.MatchString(v.Tree) || !digest(v.Helper) || !digest(v.StoragePolicySHA256) {
		return refuse("INVENTORY_PINS")
	}
	roles := []string{"booking", "gateway", "store", "relay", "model", "wallet", "signer", "manager", "payload"}
	if len(v.Binaries) != len(roles) || len(v.Configs) != len(roles) || len(v.Hosts) != 3 {
		return refuse("INVENTORY_FIELDS")
	}
	for _, role := range roles {
		if !digest(v.Binaries[role]) || !digest(v.Configs[role]) {
			return refuse("INVENTORY_ROLE")
		}
	}
	for _, host := range []string{"exec1", "demo1", "stations1"} {
		h, ok := v.Hosts[host]
		if !ok || !versionPattern.MatchString(h.Kernel) || !versionPattern.MatchString(h.Systemd) {
			return refuse("INVENTORY_HOST")
		}
	}
	return nil
}
