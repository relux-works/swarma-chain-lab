// Command check-credential-output-boundaries checks the reviewed N1b storage and
// explicit-reveal inventory. This is a source-change guard, not a taint analyzer.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

func rendered(n ast.Node) string {
	var b bytes.Buffer
	_ = format.Node(&b, token.NewFileSet(), n)
	return b.String()
}

var fields = map[string]string{
	// Ephemeral use input and opening draw; Token redacts fmt, JSON and text.
	"experiments/model-proxy/session/session.go:Facts.Token":  "Token",
	"experiments/model-proxy/session/session.go:Facts.Random": "Token",
	// One-time opening return; *Token has the same redacting value methods.
	"experiments/model-proxy/session/session.go:Result.Token":                       "*Token",
	"experiments/model-proxy/types.go:Config.APIKey":                                "UpstreamKey",
	"experiments/rental-gateway/station/station.go:Station.TrackBToken":             "TrackBToken",
	"experiments/rental-gateway/station/trackbadmin.go:trackBMintReply.Token":       "TrackBToken",
	"experiments/rental-gateway/station/trackbadmin.go:decodeTrackBMintReply.Token": "string",
	"experiments/rental-executor/http.go:trackBClaimRequest.Token":                  "TrackBToken",
	"experiments/rental-executor/http.go:decodeTrackBClaim.Token":                   "string",
	"experiments/m5-rehearsal/fixtures/registrar.go.txt:rehearsalRegistrar.APIKey":  "proxy.UpstreamKey",
	"experiments/rental-gateway/station/linuxuser.go:FakeExec.Inputs":               "[]codec.Secret[[]byte]",
	"experiments/model-proxy/credential.go:UpstreamCredential.Value":                "UpstreamKey",
	"experiments/model-proxy/credential.go:staticSource.value":                      "UpstreamKey",
	"experiments/model-proxy/credential.go:FileSource.current":                      "UpstreamKey",
}

// Keep an exact call-site multiset per accessor, including unused accessors.
// Every Reveal* call and non-call selector is inventoried on any receiver.
// Declarations on every receiver type register a key, even without callers.
var reveals = map[string]map[string]int{
	"RevealForOpen": {},
	"Reveal": {
		"experiments/model-proxy/registry.go:newService:r.Bearer.Reveal()":                                         4,
		"experiments/model-proxy/registry.go:newService:c.APIKey.Reveal()":                                         3,
		"experiments/model-proxy/messages.go:Messages.Headers:key.Reveal()":                                        1,
		"experiments/model-proxy/responses.go:Responses.Headers:key.Reveal()":                                      1,
		"experiments/model-proxy/credential.go:UpstreamCredential.valid:c.Value.Reveal()":                          1,
		"experiments/model-proxy/credential.go:FileSource.read:f.current.Reveal()":                                 1,
		"experiments/model-proxy/credential.go:Service.issued:c.Value.Reveal()":                                    1,
		"experiments/model-proxy/credential.go:authenticate:c.Value.Reveal()":                                      1,
		"experiments/model-proxy/tripwire.go:Service.foreignBearer:r.Bearer.Reveal()":                              1,
		"experiments/model-proxy/tripwire.go:Service.foreignLeak:r.Bearer.Reveal()":                                1,
		"experiments/rental-gateway/station/localtest.go:LocalTestDriver.Create:token.Reveal()":                    1,
		"experiments/rental-gateway/station/linuxuser.go:LinuxUserDriver.Create:token.Reveal()":                    1,
		"experiments/rental-gateway/station/trackbadmin.go:TrackBAdminClient.Mint:out.Token.Reveal()":              1,
		"experiments/rental-gateway/gateway/gateway.go:Gateway.startStation:st.TrackBToken.Reveal()":               1,
		"experiments/rental-executor/trackb.go:TrackB.Mint:token.Reveal()":                                         1,
		"experiments/rental-executor/trackb.go:TrackB.Claim:token.Reveal()":                                        2,
		"experiments/rental-executor/http.go:writeTrackBMintReply:token.Reveal()":                                  1,
		"experiments/model-proxy/admin.go:Credential.Valid:c.Bearer.Reveal()":                                      1,
		"experiments/model-proxy/private.go:credentialPrivateValue:s.Bearer.Reveal()":                              1,
		"experiments/model-proxy/private.go:recordPrivateValue:s.Bearer.Reveal()":                                  1,
		"experiments/model-proxy/registry.go:Service.authorize:r.Bearer.Reveal()":                                  1,
		"experiments/model-proxy/types.go:Credential.Equal:c.Bearer.Reveal()":                                      1,
		"experiments/model-proxy/types.go:Credential.Equal:other.Bearer.Reveal()":                                  1,
		"experiments/rental-gateway/gateway/inbound.go:Gateway.stationAuth:slot.ChannelSecretHex.Reveal()":         2,
		"experiments/rental-gateway/gateway/inbound.go:Gateway.stationHello:slot.ChannelSecretHex.Reveal()":        1,
		"experiments/rental-gateway/journal/journal.go:Store.SetChannelCredential:credential.Reveal()":             1,
		"experiments/rental-gateway/journal/private.go:slotPrivateValue:s.ChannelSecretHex.Reveal()":               1,
		"experiments/single-use/payloadbootstrap/codec/codec.go:Valid:b.ChannelSecret.Reveal()":                    1,
		"experiments/single-use/payloadbootstrap/codec/codec.go:Valid:b.ModelBearer.Reveal()":                      2,
		"experiments/single-use/payloadbootstrap/codec/codec.go:privateWire:b.ChannelSecret.Reveal()":              1,
		"experiments/single-use/payloadbootstrap/codec/codec.go:privateWire:b.ModelBearer.Reveal()":                1,
		"experiments/station-lifecycle/broker.go:Broker.Credential:r.Credential.Reveal()":                          2,
		"experiments/station-lifecycle/broker.go:NewBroker:r.Credential.Reveal()":                                  2,
		"experiments/station-lifecycle/broker.go:NewBroker:v.Bootstrap.Reveal()":                                   2,
		"experiments/station-lifecycle/gatewaybind/driver.go:Driver.Create:bootstrap.ChannelSecret.Reveal()":       1,
		"experiments/station-lifecycle/gatewaybind/driver.go:Driver.Create:v.Bootstrap.Reveal()":                   1,
		"experiments/station-lifecycle/gatewaybind/driver.go:Driver.StartSession:bootstrap.ChannelSecret.Reveal()": 1,
		"experiments/station-lifecycle/gatewaybind/driver.go:Driver.StartSession:st.ChannelSecret.Reveal()":        1,
		"experiments/station-lifecycle/gatewaybind/driver.go:Driver.StartSession:v.Bootstrap.Reveal()":             1,
		"experiments/station-lifecycle/gatewaybind/driver.go:New:credential.Bearer.Reveal()":                       1,
		"experiments/station-lifecycle/manager.go:Manager.Apply:c.Slot.Bootstrap.Reveal()":                         1,
		"experiments/station-lifecycle/manager.go:Manager.Apply:s.Bootstrap.Reveal()":                              1,
		"experiments/station-lifecycle/manager.go:Manager.Start:s.Bootstrap.Reveal()":                              2,
		"experiments/station-lifecycle/manager.go:New:v.Bootstrap.Reveal()":                                        2,
		"experiments/station-lifecycle/private.go:brokerRecordPrivateValue:s.Credential.Reveal()":                  1,
		"experiments/station-lifecycle/private.go:slotPrivateValue:s.Bootstrap.Reveal()":                           1,
		"experiments/station-lifecycle/private_bytes.go:PrivateBytes.Reveal:p.value.Reveal()":                      1,
		"experiments/station-lifecycle/slotd/host.go:Host.Start:s.Bootstrap.Reveal()":                              1,
		"experiments/station-lifecycle/slotd/host.go:bound:s.Bootstrap.Reveal()":                                   1,
		"experiments/station-lifecycle/types.go:Range.validateSlot:s.Bootstrap.Reveal()":                           2,
		"experiments/station-payload/client.go:Client.generate:c.bootstrap.ModelBearer.Reveal()":                   1,
		"experiments/station-payload/responses.go:Client.generateResponses:c.bootstrap.ModelBearer.Reveal()":       1,
		"experiments/station-payload/session.go:Client.Run:b.ChannelSecret.Reveal()":                               1,
	},
}

func receiver(f *ast.FuncDecl) string {
	if f.Recv == nil {
		return f.Name.Name
	}
	n := f.Recv.List[0].Type
	if p, ok := n.(*ast.StarExpr); ok {
		n = p.X
	}
	return rendered(n) + "." + f.Name.Name
}
func inventory(path string, raw []byte, gotFields map[string]string, gotReveals map[string]map[string]int) {
	f, e := parser.ParseFile(token.NewFileSet(), path, raw, 0)
	if e != nil {
		panic("source parse refused")
	}
	var scan func(ast.Node, string)
	scan = func(n ast.Node, owner string) {
		// Calls are visited before their selectors; count direct calls once.
		called := map[*ast.SelectorExpr]bool{}
		ast.Inspect(n, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.StructType:
				for _, field := range v.Fields.List {
					for _, name := range field.Names {
						if name.Name == "APIKey" || name.Name == "TrackBToken" || name.Name == "Token" || (owner == "FakeExec" && name.Name == "Inputs") || (path == "experiments/model-proxy/session/session.go" && owner == "Facts" && name.Name == "Random") || (owner == "UpstreamCredential" && name.Name == "Value") || (owner == "staticSource" && name.Name == "value") || (owner == "FileSource" && name.Name == "current") {
							gotFields[path+":"+owner+"."+name.Name] = rendered(field.Type)
						}
					}
				}
			case *ast.CallExpr:
				selector, ok := v.Fun.(*ast.SelectorExpr)
				if !ok || !strings.HasPrefix(selector.Sel.Name, "Reveal") {
					break
				}
				called[selector] = true
				if gotReveals[selector.Sel.Name] == nil {
					gotReveals[selector.Sel.Name] = map[string]int{}
				}
				gotReveals[selector.Sel.Name][path+":"+owner+":"+rendered(v)]++
			case *ast.SelectorExpr:
				if !called[v] && strings.HasPrefix(v.Sel.Name, "Reveal") {
					if gotReveals[v.Sel.Name] == nil {
						gotReveals[v.Sel.Name] = map[string]int{}
					}
					gotReveals[v.Sel.Name][path+":"+owner+":"+rendered(v)]++
				}
			}
			return true
		})
	}
	for _, decl := range f.Decls {
		switch v := decl.(type) {
		case *ast.FuncDecl:
			// Register unused Reveal* accessors on any type, including non-carriers.
			if v.Recv != nil && strings.HasPrefix(v.Name.Name, "Reveal") && gotReveals[v.Name.Name] == nil {
				gotReveals[v.Name.Name] = map[string]int{}
			}
			scan(v, receiver(v))
		case *ast.GenDecl:
			for _, s := range v.Specs {
				switch spec := s.(type) {
				case *ast.TypeSpec:
					scan(spec.Type, spec.Name.Name)
				case *ast.ValueSpec:
					// Includes anonymous carriers and nested function literals.
					scan(spec, "var")
				}
			}
		}
	}
}
func main() {
	// The checker must reject an extra carrier, a raw retained field and a new
	// reveal site. These isolated controls print no credential-bearing source.
	controlFields, controlReveals := map[string]string{}, map[string]map[string]int{}
	inventory("control.go", []byte(`package control;type Carrier struct{TrackBToken string};func expose(c Carrier){_=c.TrackBToken.Reveal()}`), controlFields, controlReveals)
	if len(controlFields) != 1 || len(controlReveals) != 1 || len(controlReveals["Reveal"]) != 1 || reflect.DeepEqual(controlFields, fields) || reflect.DeepEqual(controlReveals, reveals) {
		panic("inventory detector control failed")
	}
	changed := map[string]string{}
	for k, v := range fields {
		changed[k] = v
	}
	changed["experiments/model-proxy/types.go:Config.APIKey"] = "Secret"
	if reflect.DeepEqual(changed, fields) {
		panic("raw carrier detector control failed")
	}
	gotFields, gotReveals := map[string]string{}, map[string]map[string]int{}
	var paths []string
	e := filepath.WalkDir(".", func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if path != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if (strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")) || strings.HasSuffix(path, ".go.txt") {
			paths = append(paths, path)
		}
		return nil
	})
	if e != nil {
		panic("source walk refused")
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, e := os.ReadFile(path)
		if e != nil {
			panic("source read refused")
		}
		inventory(path, raw, gotFields, gotReveals)
	}
	if !reflect.DeepEqual(fields, gotFields) || !reflect.DeepEqual(reveals, gotReveals) {
		fmt.Fprintln(os.Stderr, "credential storage/reveal inventory changed; re-audit required")
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"fields": gotFields, "reveals": gotReveals})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"carrier_fields": gotFields, "explicit_reveals": gotReveals, "controls": 3, "note": "Reviewed source inventory; not an arbitrary-code taint proof"})
}
