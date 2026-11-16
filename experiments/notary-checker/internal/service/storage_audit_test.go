package service

import (
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

// storageViolations walks declared types, including container elements and
// function signatures. Interface payloads and closures need the live battery.
func storageViolations(root reflect.Type) []string {
	var violations []string
	active := map[reflect.Type]bool{}
	reader := reflect.TypeOf(check.NodeNameReader{})
	holder := reflect.TypeOf(signingKey{})
	var walk func(reflect.Type, string, bool)
	walk = func(typ reflect.Type, path string, passwordSlot bool) {
		if typ == holder {
			return // TestSigningKeyStorage independently pins the exact shape.
		}
		pkg := typ.PkgPath()
		if (strings.Contains(pkg, "/btcec/") || strings.Contains(pkg, "/secp256k1/")) && (typ.Name() == "PrivateKey" || typ.Name() == "ModNScalar") {
			violations = append(violations, path+": private scalar outside signingKey")
			return
		}
		if pkg == reader.PkgPath() && typ.Name() == "rpcPassword" {
			if !passwordSlot {
				violations = append(violations, path+": rpcPassword outside NodeNameReader.password")
			}
			return // TestRPCPasswordStorage pins the holder's exact shape.
		}
		if active[typ] {
			return
		}
		active[typ] = true
		defer delete(active, typ)
		switch typ.Kind() {
		case reflect.Pointer, reflect.Array, reflect.Slice, reflect.Chan:
			walk(typ.Elem(), path+"/element", passwordSlot)
		case reflect.Map:
			walk(typ.Key(), path+"/map-key", false)
			walk(typ.Elem(), path+"/map-value", false)
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				walk(f.Type, path+"."+f.Name, typ == reader && f.Name == "password")
			}
		case reflect.Func:
			for i := 0; i < typ.NumIn(); i++ {
				walk(typ.In(i), path+"/argument", false)
			}
			for i := 0; i < typ.NumOut(); i++ {
				walk(typ.Out(i), path+"/result", false)
			}
		}
	}
	walk(root, root.String(), false)
	return violations
}

// Claim: Service and NodeNameReader declare no private scalar outside the
// signing holder and no rpcPassword outside the designated reader field.
func TestServiceStorageTypes(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Service{}), reflect.TypeOf(check.NodeNameReader{})} {
		for _, violation := range storageViolations(typ) {
			t.Error(violation)
		}
	}
}

// Claim: the walk rejects nested and cyclic alternate carriers while accepting
// the designated holder. These type-only controls never contain real secrets.
func TestStorageTypeWalk(t *testing.T) {
	type cycle struct {
		next *cycle
		key  map[string][]*btcec.PrivateKey
	}
	password, ok := reflect.TypeOf(check.NodeNameReader{}).FieldByName("password")
	if !ok {
		t.Fatal("reader password field missing")
	}
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		want string
	}{
		{"key-pointer", reflect.TypeOf((*btcec.PrivateKey)(nil)), "private scalar"},
		{"scalar", reflect.TypeOf(btcec.ModNScalar{}), "private scalar"},
		{"cycle", reflect.TypeOf(cycle{}), "private scalar"},
		{"password-copy", reflect.StructOf([]reflect.StructField{{Name: "Copy", Type: password.Type}}), "rpcPassword"},
		{"holder", reflect.TypeOf(signingKey{}), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := storageViolations(tc.typ)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatal("allowed holder rejected")
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Fatal("alternate carrier was not rejected by the intended rule")
			}
		})
	}
}
