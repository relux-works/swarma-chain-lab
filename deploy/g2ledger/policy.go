package g2ledger

// retentionPolicy is the single provisional QA policy table. Keep mode rules
// here so the pending plan-owner decision has one implementation edit point.
func retentionPolicy(kind, ret, mode string) (effect, rule string) {
	if kind == "modify" || kind == "unit" || kind == "membership" {
		return "restore", "restore-attempt-transition"
	}
	if ret == "d6" {
		return "keep", "retain-d6"
	}
	if ret == "rehearsal" {
		if mode == "rehearsal" {
			return "remove", "remove-explicit-rehearsal-object"
		}
		return "keep", "rehearsal-retention-forbidden-in-station"
	}
	if ret == "remove" {
		return "remove", "remove-exact-identity"
	}
	if mode == "rehearsal" {
		return "remove", "remove-rehearsal-state"
	}
	return "keep", "retain-station-state"
}

func validPurpose(purpose string) bool { return purpose == "station" || purpose == "rehearsal" }
func purposeMatches(purpose, mode string) bool {
	return purpose == "rehearsal" && mode == "rehearsal" || purpose == "station" && (mode == "station" || mode == "station-remove")
}
