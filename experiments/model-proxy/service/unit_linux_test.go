//go:build linux

package service

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func installFixture() Install {
	return Install{PlatformRoot: "/fixture/platform", Account: "gateway-service", Generation: "generation-current", BrokerUnit: "broker.service", ConfigLocation: "/fixture/private/gateway.json"}
}
func unitTemplate(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("deploy/credential-gateway.service.in")
	if e != nil {
		t.Fatal("unit template missing")
	}
	return b
}

// Claim: the neutral template resolves to the supplied account, fixed paths,
// per-generation listener and broker ordering. Credential input is location only.
func TestInstallTemplate(t *testing.T) {
	raw := unitTemplate(t)
	b, e := RenderUnit(raw, installFixture())
	if e != nil || bytes.Contains(b, []byte("@")) {
		t.Fatal("valid install rendering refused")
	}
	for _, line := range []string{"User=gateway-service\n", "After=broker.service\n", "Requires=broker.service\n", "BindsTo=broker.service\n", "ExecStart=/fixture/platform/credential-gateway/bin/credential-gateway -config %d/gateway-config\n", "LoadCredential=gateway-config:/fixture/private/gateway.json\n", "Environment=GATEWAY_LISTENER=/fixture/platform/run/credential-gateway/generation-current/gateway.sock\n", "LimitCORE=0\n", "Restart=no\n"} {
		if !bytes.Contains(b, []byte(line)) {
			t.Fatal("unit contract changed")
		}
	}
	for _, forbidden := range []string{"DynamicUser=", "\nGroup=", "API_KEY=", "ACCESS_TOKEN=", fixtureMaterial} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatal("unit widened custody")
		}
	}
	// Claim: the inactive template retains each declared hardening directive;
	// effective kernel/systemd enforcement still needs installer qualification.
	for _, line := range []string{"CapabilityBoundingSet=", "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes", "RestrictNamespaces=yes", "LockPersonality=yes", "RestrictRealtime=yes", "MemoryDenyWriteExecute=yes", "SystemCallArchitectures=native", "ProtectProc=invisible", "ProcSubset=pid", "PrivateIPC=yes", "RemoveIPC=yes"} {
		if !bytes.Contains(b, []byte("\n"+line+"\n")) {
			t.Fatal("unit hardening changed")
		}
	}
}

// Claim: missing parameters, account escalation and path/unit interpolation
// refuse beside the same valid rendering. A new generation gets a new listener.
func TestInstallTemplateRefusals(t *testing.T) {
	raw := unitTemplate(t)
	for _, mode := range []string{"root", "missing-account", "relative-root", "root-path", "path-space", "path-escape", "path-variable", "path-glob", "generation", "dot-generation", "parent-generation", "hidden-generation", "long-generation", "unit-injection", "unresolved", "missing-token"} {
		t.Run(mode, func(t *testing.T) {
			in := installFixture()
			template := raw
			switch mode {
			case "root":
				in.Account = "root"
			case "missing-account":
				in.Account = ""
			case "relative-root":
				in.PlatformRoot = "relative"
			case "root-path":
				in.PlatformRoot = "/"
			case "path-space":
				in.ConfigLocation = "/fixture/private name"
			case "path-escape":
				in.ConfigLocation = "/fixture/%s"
			case "path-variable":
				in.PlatformRoot = "/fixture/$OTHER"
			case "path-glob":
				in.PlatformRoot = "/fixture/*"
			case "generation":
				in.Generation = "../old"
			case "dot-generation":
				in.Generation = "."
			case "parent-generation":
				in.Generation = ".."
			case "hidden-generation":
				in.Generation = ".hidden"
			case "long-generation":
				in.Generation = strings.Repeat("a", 129)
			case "unit-injection":
				in.BrokerUnit = "broker.service\nUser=root"
			case "unresolved":
				template = append(append([]byte(nil), raw...), []byte("@UNKNOWN@")...)
			case "missing-token":
				template = []byte(strings.ReplaceAll(string(raw), "@SERVICE_ACCOUNT@", "hardcoded"))
			}
			if b, e := RenderUnit(template, in); b != nil || e != ErrInput {
				t.Fatal("invalid install rendered")
			}
		})
	}
	in := installFixture()
	first, e := RenderUnit(raw, in)
	if e != nil {
		t.Fatal("first-generation control failed")
	}
	in.Generation = "generation-next"
	second, e := RenderUnit(raw, in)
	if e != nil || bytes.Equal(first, second) || bytes.Contains(second, []byte("generation-current")) {
		t.Fatal("listener inherited old generation")
	}
}
