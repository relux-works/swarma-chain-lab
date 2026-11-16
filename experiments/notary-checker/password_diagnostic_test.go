package notarycheck

import (
	"context"
	"github.com/relux-works/swarma-chain-lab/experiments/notary-checker/internal/diagnosticcheck"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const diagnosticPassword = "synthetic-diagnostic-password"

func passwordDiagnosticForms(t *testing.T) []diagnosticcheck.Form {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("synthetic-user:"+diagnosticPassword+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	real, err := NewNodeNameReader("http://127.0.0.1:1", path)
	if err != nil {
		t.Fatal(err)
	}
	holder := newRPCPassword([]byte(diagnosticPassword))
	holderCopy := real.password
	reader := NodeNameReader{endpoint: "http://127.0.0.1:1", user: "synthetic-user", password: holder, ctx: context.Background()}
	ctxCopy := real.WithContext(context.Background())
	derefCopy := *real
	derefCtxCopy := *ctxCopy
	var nilReader *NodeNameReader
	var nilHolder *rpcPassword
	pp := &real
	rv := reflect.ValueOf(*real)
	return []diagnosticcheck.Form{
		{Name: "real/pointer", Value: real}, {Name: "real/ctx-copy", Value: ctxCopy}, {Name: "real/deref-copy", Value: derefCopy}, {Name: "real/deref-ctx-copy", Value: derefCtxCopy},
		{Name: "real/double-pointer", Value: pp}, {Name: "holder/copy-from-real", Value: holderCopy}, {Name: "holder/copy-pointer", Value: &holderCopy},
		{Name: "holder/value", Value: holder}, {Name: "reader/value", Value: reader},
		{Name: "zero/holder", Value: rpcPassword{}}, {Name: "zero/holder-pointer", Value: &rpcPassword{}}, {Name: "nil/holder-pointer", Value: nilHolder},
		{Name: "zero/reader", Value: NodeNameReader{}}, {Name: "nil/reader-pointer", Value: nilReader},
		{Name: "wrap/holder-unexported-value", Value: struct{ p rpcPassword }{holder}},
		{Name: "wrap/holder-unexported-pointer", Value: struct{ p *rpcPassword }{&holder}},
		{Name: "wrap/reader-unexported-value", Value: struct{ r NodeNameReader }{*real}},
		{Name: "wrap/reader-unexported-pointer", Value: struct{ r *NodeNameReader }{real}},
		{Name: "wrap/reader-unexported-double-pointer", Value: struct{ r **NodeNameReader }{pp}},
		{Name: "wrap/reader-exported-value", Value: struct{ R NodeNameReader }{*real}},
		{Name: "wrap/namesource-iface", Value: struct{ n NameSource }{real}},
		{Name: "wrap/any-iface", Value: struct{ a any }{*real}},
		{Name: "wrap/nested2", Value: struct {
			o struct{ i struct{ r NodeNameReader } }
		}{struct{ i struct{ r NodeNameReader } }{struct{ r NodeNameReader }{*real}}}},
		{Name: "wrap/array-holder", Value: [1]rpcPassword{holder}}, {Name: "wrap/array-reader", Value: [1]NodeNameReader{*real}},
		{Name: "wrap/slice-reader", Value: []NodeNameReader{*real}}, {Name: "wrap/slice-reader-ptr", Value: []*NodeNameReader{real}},
		{Name: "wrap/slice-any", Value: []any{*real, holder}},
		{Name: "wrap/map-value", Value: map[string]NodeNameReader{"a": *real}}, {Name: "wrap/map-ptr", Value: map[string]*NodeNameReader{"a": real}},
		{Name: "wrap/map-key", Value: map[NodeNameReader]int{*real: 1}}, {Name: "wrap/map-holder-key", Value: map[rpcPassword]int{holder: 1}},
		{Name: "wrap/Input.Names", Value: Input{Names: real}},
		{Name: "reflect/reader", Value: rv}, {Name: "reflect/password-field", Value: rv.FieldByName("password")}, {Name: "reflect/password-pointer", Value: rv.FieldByName("password").Field(0)},
	}
}

// Claim: every populated, copied, zero, nil and container form is safe across
// all 43 sinks; plain inline and slice-pointer controls must leak.
func TestRPCPasswordDiagnostics(t *testing.T) {
	raw := []byte(diagnosticPassword)
	controls := []diagnosticcheck.Form{
		{Name: "plain-inline", Value: struct{ value string }{diagnosticPassword}},
		{Name: "plain-pointer", Value: struct{ value *struct{ password string } }{&struct{ password string }{diagnosticPassword}}},
		{Name: "plain-byte-pointer", Value: struct{ value *[]byte }{&raw}},
	}
	diagnosticcheck.Check(t, passwordDiagnosticForms(t), controls, diagnosticcheck.NewDetector(raw, false))
}

// Claim: actual runtime panic printing does not expose any tested form.
func TestRPCPasswordDiagnosticPanic(t *testing.T) {
	diagnosticcheck.PanicCheck(t, "TestRPCPasswordDiagnosticPanic", passwordDiagnosticForms(t), diagnosticcheck.NewDetector([]byte(diagnosticPassword), false))
}
