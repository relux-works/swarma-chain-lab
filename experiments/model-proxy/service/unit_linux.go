//go:build linux

package service

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Install supplies locations and a user-manager-created service account. It
// contains no credential values. RenderUnit performs no privileged operation.
type Install struct{ PlatformRoot, Account, Generation, BrokerUnit, ConfigLocation string }

var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var unitName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\.service$`)
var generationName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func installPath(p string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-+", c)) {
			return false
		}
	}
	return true
}

// RenderUnit refuses unresolved substitutions, account widening and unit/path
// injection. Installation still verifies managed-generation evidence and owners.
func RenderUnit(template []byte, in Install) ([]byte, error) {
	if !installPath(in.PlatformRoot) || !installPath(in.ConfigLocation) || !accountName.MatchString(in.Account) || in.Account == "root" || in.Account == "nobody" || !generationName.MatchString(in.Generation) || !unitName.MatchString(in.BrokerUnit) {
		return nil, ErrInput
	}
	text := string(template)
	for _, token := range []string{"@PLATFORM_ROOT@", "@SERVICE_ACCOUNT@", "@SERVICE_GENERATION@", "@BROKER_UNIT@", "@CONFIG_LOCATION@"} {
		if !strings.Contains(text, token) {
			return nil, ErrInput
		}
	}
	text = strings.NewReplacer("@PLATFORM_ROOT@", in.PlatformRoot, "@SERVICE_ACCOUNT@", in.Account, "@SERVICE_GENERATION@", in.Generation, "@BROKER_UNIT@", in.BrokerUnit, "@CONFIG_LOCATION@", in.ConfigLocation).Replace(text)
	if strings.Contains(text, "@") {
		return nil, ErrInput
	}
	return []byte(text), nil
}
