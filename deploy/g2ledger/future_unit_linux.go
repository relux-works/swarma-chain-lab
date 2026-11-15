package g2ledger

import (
	"errors"
	"path/filepath"
)

func validateFutureUnits(s Scope) error {
	if s.FutureUnits == nil {
		return nil
	}
	if len(s.FutureUnits) == 0 {
		return errors.New("FUTURE_UNIT_PLAN_EMPTY")
	}
	units, links := map[string]bool{}, map[string]bool{}
	for _, unit := range s.FutureUnits {
		if installName(unit.Name) != nil || units[unit.Name] {
			return errors.New("FUTURE_UNIT_NAME_INVALID_OR_DUPLICATE " + unit.Name)
		}
		declared := false
		for _, name := range s.Units {
			declared = declared || name == unit.Name
		}
		if !declared {
			return errors.New("FUTURE_UNIT_OUTSIDE_SCOPE " + unit.Name)
		}
		units[unit.Name] = true
		if !validPath(unit.Source) {
			return errors.New("FUTURE_UNIT_SOURCE " + unit.Name)
		}
		if err := targetPathPolicy(unit.Source); err != nil {
			return err
		}
		if !isHex(unit.SHA256, 32) {
			return errors.New("FUTURE_UNIT_SHA256 " + unit.Name)
		}
		if len(unit.Links) == 0 {
			return errors.New("FUTURE_UNIT_LINKS_EMPTY " + unit.Name)
		}
		for _, link := range unit.Links {
			if !validPath(link.Path) || !validPath(link.Target) || filepath.Base(link.Target) != unit.Name || links[link.Path] {
				return errors.New("FUTURE_UNIT_LINK_INVALID_OR_DUPLICATE " + unit.Name)
			}
			for _, path := range []string{link.Path, link.Target} {
				if err := targetPathPolicy(path); err != nil {
					return err
				}
			}
			links[link.Path] = true
		}
	}
	for _, name := range s.Units {
		if !units[name] {
			return errors.New("FUTURE_UNIT_PLAN_MISSING " + name)
		}
	}
	return nil
}

// The selected installed bytes and complete derived inventory must match the
// sealed declaration, independently of systemctl's later creation receipt.
func (l *Ledger) checkFutureUnit(name string, actual unitInstall) error {
	for _, unit := range l.rows[0].Body.Genesis.Scope.FutureUnits {
		if unit.Name != name {
			continue
		}
		if actual.SHA256 != unit.SHA256 {
			return fail(1, "FUTURE_UNIT_SHA256_MISMATCH "+name)
		}
		links := make([]UnitLink, 0, len(unit.Links))
		for _, link := range unit.Links {
			links = append(links, UnitLink{Path: link.Path, Target: link.Target})
		}
		if !unitReceiptMatches(actual.Expected, links) || !unitReceiptMatches(actual.Missing, links) {
			return fail(1, "FUTURE_UNIT_LINK_SET_MISMATCH "+name)
		}
		return nil
	}
	return nil // Legacy scopes retain the installed-file and receipt checks.
}
