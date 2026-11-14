package g2ledger

// stationProtectedKind covers account creation (user/group) and all key
// creation (secret, including audited exec-create outputs). Membership is a
// modification: undo removes only the added membership, never either account.
func stationProtectedKind(kind string) bool {
	return kind == "user" || kind == "group" || kind == "secret"
}

func stationRetentionAllowed(g Genesis, a Action) error {
	if g.Purpose == "station" && stationProtectedKind(a.Kind) && a.Ret == "remove" {
		return namedError("STATION_PROTECTED_RETENTION", a)
	}
	return nil
}

// retentionPolicy is the single CONFIRMED v1 policy table. The plan owner
// confirmed station and rehearsal replay; post-install removal is a separate
// reviewed procedure and never grants this engine authority to delete d6 data.
func retentionPolicy(kind, ret, mode string) (effect, rule string) {
	if mode == "station" && stationProtectedKind(kind) {
		if ret == "d6" {
			return "keep", "retain-d6"
		}
		return "keep", "retain-station-protected"
	}
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
	return purpose == "rehearsal" && mode == "rehearsal" || purpose == "station" && mode == "station"
}
