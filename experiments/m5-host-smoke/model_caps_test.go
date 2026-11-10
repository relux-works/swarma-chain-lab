package smoke

import (
	"context"
	"reflect"
	"testing"

	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
)

// Each signed limit must equal the independently supplied expected profile in
// both directions. These mutations remain natively valid, so only exact binding
// can reject them; the unchanged neighbor must remain accepted after every case.
func TestContractModelCapsBinding(t *testing.T) {
	c, v, _ := publicFixture(t)
	if e := checkContract(c, host(), v, v.RenterPubkey); e != nil {
		t.Fatal("positive", e)
	}
	fields := reflect.TypeOf(*v.ModelCaps)
	for i := 0; i < fields.NumField(); i++ {
		name := fields.Field(i).Name
		for _, direction := range []string{"smaller", "larger"} {
			t.Run(name+"-"+direction, func(t *testing.T) {
				caps := *v.ModelCaps
				f := reflect.ValueOf(&caps).Elem().FieldByName(name)
				n := f.Uint()
				if direction == "smaller" {
					n--
				} else {
					n++
				}
				f.SetUint(n)
				bad := v
				bad.ModelCaps = &caps
				if bad.Validate() != nil || *bad.ModelCaps == *v.ModelCaps {
					t.Fatal("plant did not produce a distinct natively valid contract")
				}
				wantCode(t, checkContract(c, host(), bad, v.RenterPubkey), "CONTRACT_BINDING")
				if e := checkContract(c, host(), v, v.RenterPubkey); e != nil {
					t.Fatal("positive neighbor changed", e)
				}
			})
		}
	}
	t.Run("missing", func(t *testing.T) {
		bad := v
		bad.ModelCaps = nil
		if bad.Validate() != nil {
			t.Fatal("legacy missing caps should remain natively valid")
		}
		wantCode(t, checkContract(c, host(), bad, v.RenterPubkey), "CONTRACT_BINDING")
	})
	t.Run("invalid", func(t *testing.T) {
		caps := *v.ModelCaps
		caps.Requests = 0
		bad := v
		bad.ModelCaps = &caps
		wantCode(t, checkContract(c, host(), bad, v.RenterPubkey), "CONTRACT_NATIVE")
	})
}

// Missing/invalid expected caps fail before operator callbacks or network access.
// Native caps validity covers every zero limit, unsafe JSON integer and ordering;
// a nearby valid expected profile still validates independently.
func TestExpectedModelCapsRequired(t *testing.T) {
	c, _, _ := publicFixture(t)
	cases := map[string]*booking.ModelCaps{"missing": nil}
	fields := reflect.TypeOf(*c.ModelCaps)
	for i := 0; i < fields.NumField(); i++ {
		name := fields.Field(i).Name
		for _, n := range []uint64{0, 1 << 53} {
			caps := *c.ModelCaps
			reflect.ValueOf(&caps).Elem().FieldByName(name).SetUint(n)
			suffix := "-zero"
			if n != 0 {
				suffix = "-unsafe-integer"
			}
			cases[name+suffix] = &caps
		}
	}
	caps := *c.ModelCaps
	caps.DefaultMaxOutputTokens = caps.MaxTokens + 1
	cases["default-over-max"] = &caps
	caps2 := *c.ModelCaps
	caps2.MaxTokens = caps2.OutputTokens + 1
	cases["max-over-output"] = &caps2
	for name, caps := range cases {
		t.Run(name, func(t *testing.T) {
			bad := c
			bad.ModelCaps = caps
			calls := 0
			report, e := Run(context.Background(), bad, OperatorFunc(func(context.Context, Request) (Receipt, error) {
				calls++
				return Receipt{}, refuse("TEST_OPERATOR_UNEXPECTED")
			}))
			wantCode(t, e, "CONFIG_MODEL_CAPS")
			if calls != 0 || report.Outcome != "FAIL" || report.Failure != "CONFIG_MODEL_CAPS" || len(report.Client) != 0 || len(report.Operator) != 0 {
				t.Fatal("invalid expected caps reached an effect or lost exact refusal")
			}
			if e := c.validate(host()); e != nil {
				t.Fatal("positive config changed", e)
			}
		})
	}
}
