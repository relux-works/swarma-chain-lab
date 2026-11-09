package signerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func mainConfig(t *testing.T) Config {
	c := config(t)
	c.Profile = "v2"
	c.Policy.Policy.Network, c.Policy.Policy.Genesis = "main", su.MainGenesis
	c.Policy.Policy.FeeRate = 200
	c.Spending = &SpendingCaps{MovedPerTx: 1000000, MovedDay: 10000000, EnrolledHot: 20000000}
	c.Caps = Caps{200000, 4, 12, 6000000, 10000000, 4, 200000, 800000, 2}
	c.PaymentPolicies = map[string]rental.PaymentAdmissionPolicy{"nmc": {MinConfirmations: 1, MaxRateAgeSeconds: 60, Limits: pc.Limits{MaxBlocks: 2016, MaxMempool: 10000, MaxCalls: 10000, MaxBytes: 64 << 20}}}
	return c
}

// Main must explicitly select v2, NMC payment and all spending/rate fields.
// Refusals precede missing dependencies, state creation, credentials or keys.
func TestMainSpendingConfig(t *testing.T) {
	c := mainConfig(t)
	if err := c.validate(); err != nil {
		t.Fatal("complete main profile", err)
	}
	for _, tc := range []struct {
		name, code string
		change     func(*Config)
	}{
		{"missing_caps", "MAIN_PROFILE_REQUIRED", func(c *Config) { c.Spending = nil }},
		{"missing_rate", "MAIN_PROFILE_REQUIRED", func(c *Config) { c.Policy.Policy.FeeRate = 0 }},
		{"legacy", "MAIN_PROFILE_REQUIRED", func(c *Config) { c.Profile = "v1-nmc" }},
		{"missing_daily", "SPENDING_CAP_CONFIG", func(c *Config) { c.Spending.MovedDay = 0 }},
		{"missing_hot", "SPENDING_CAP_CONFIG", func(c *Config) { c.Spending.EnrolledHot = 0 }},
		{"missing_moved", "SPENDING_CAP_CONFIG", func(c *Config) { c.Spending.MovedPerTx = 0 }},
		{"btc", "PAYMENT_POLICY", func(c *Config) { c.PaymentPolicies["btc"] = c.PaymentPolicies["nmc"] }},
		{"ltc", "PAYMENT_POLICY", func(c *Config) { c.PaymentPolicies["ltc"] = c.PaymentPolicies["nmc"] }},
		{"missing_observation_limits", "PAYMENT_POLICY", func(c *Config) { p := c.PaymentPolicies["nmc"]; p.Limits.MaxBytes = 0; c.PaymentPolicies["nmc"] = p }},
		{"excess_depth", "PAYMENT_POLICY", func(c *Config) {
			p := c.PaymentPolicies["nmc"]
			p.MinConfirmations = 2017
			c.PaymentPolicies["nmc"] = p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := mainConfig(t)
			tc.change(&bad)
			bad.StateDir = filepath.Join(dir(t), "must-not-open")
			bad.GrantKeyPath = "/absent-key"
			_, err := Open(bad, nil, nil, nil, nil)
			wantError(t, err, tc.code)
		})
	}
}

// The exact configured transaction ceiling accepts; one extra atom refuses
// before reading records or reaching any external dependency.
func TestMovedTransactionCeiling(t *testing.T) {
	c := mainConfig(t)
	x := &Engine{cfg: c}
	if err := x.capSpending(c.Spending.MovedPerTx, 500, ""); err != nil {
		t.Fatal("exact transaction ceiling", err)
	}
	wantError(t, x.capSpending(c.Spending.MovedPerTx+1, 500, ""), "MOVED_TX_CAP")
}

func spendingSpec(c Config, kind, label string) rental.PlanSpec {
	in := su.PlanInput{Point: su.Point{TxID: hash([]byte(label))}, ValueSat: 2000000, Script: c.Policy.Policy.FundingScript, Role: "funding"}
	s := rental.PlanSpec{Kind: kind, Inputs: []su.PlanInput{in}, ChangeScript: c.Policy.Policy.FundingScript}
	if kind == "refill" {
		s.Count, s.ValueSat = 4, 200000
	}
	if kind == "revoke" {
		s.Inputs[0].ValueSat = 200000
		s.Inputs[0].Role, s.Inputs[0].Script = "seal", c.Policy.Policy.SealScript
		s.Pool = rental.PoolOutput{Point: rental.Point{TxID: in.Point.TxID}, ValueSat: 200000, Script: c.Policy.Policy.SealScript}
	}
	return s
}

// Every template reserves its conserved movement before a signature. Pending
// issue/refill/revoke charges survive restart and UTC rollover; an exact retry
// excludes only itself. Rejection preserves inventory, blobs and ledger bytes.
func TestSpendingReservationRecovery(t *testing.T) {
	c := mainConfig(t)
	x, err := Open(c, preflightIssuer{t: t}, noNode{t}, noBroadcast{t}, noStore{t})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	var total int64
	for _, kind := range []string{"grant-issue", "refill", "revoke"} {
		spec := spendingSpec(c, kind, kind)
		id := hash([]byte(kind))
		r := record{ID: id, Phase: "reserved", Spec: spec}
		if kind != "grant-issue" {
			plan, e := rental.MakePlan(c.Policy, spec, nil, nil, nil, 0)
			if e != nil {
				t.Fatal(e)
			}
			r.Plan, r.Phase = &plan, "prepared"
		}
		moved, e := x.movement(spec)
		if e != nil {
			t.Fatal(e)
		}
		fee, e := x.feeProjection(spec)
		if e != nil {
			t.Fatal(e)
		}
		want := fee
		if kind == "refill" {
			want += 800000
		}
		if moved != want {
			t.Fatal("movement excludes only pinned change", kind, moved, want)
		}
		if e = x.reserve(operation{ID: id, Kind: kind, At: 86399}, r, nil); e != nil {
			t.Fatal(e)
		}
		total += moved
	}
	x.Close()
	x, err = Open(c, preflightIssuer{t: t}, noNode{t}, noBroadcast{t}, noStore{t})
	if err != nil {
		t.Fatal("restart", err)
	}
	// Narrow the checker in memory only to probe its exact boundary. The frozen
	// production config and persisted binding remain unchanged.
	x.cfg.Spending.MovedDay = total
	wantError(t, x.capSpending(1, 86400, ""), "MOVED_DAY_CAP")
	for _, op := range x.state.Operations {
		if err = x.capSpending(op.MovedAtoms, 172800, op.ID); err != nil {
			t.Fatal("exact retry", err)
		}
	}
	beforeState, beforeFiles := encode(x.state), encode(files(t, c.StateDir))
	spec := spendingSpec(c, "refill", "denied")
	plan, _ := rental.MakePlan(c.Policy, spec, nil, nil, nil, 0)
	id := hash([]byte("denied"))
	err = x.reserve(operation{ID: id, Kind: "refill", At: 172800}, record{ID: id, Phase: "prepared", Spec: spec, Plan: &plan}, nil)
	wantError(t, err, "MOVED_DAY_CAP")
	if !bytes.Equal(beforeState, encode(x.state)) || !bytes.Equal(beforeFiles, encode(files(t, c.StateDir))) {
		t.Fatal("denial changed state")
	}
	// A persisted undercharge cannot be repaired by trusting the hash alone.
	corrupt := cloneState(x.state)
	corrupt.Operations[0].MovedAtoms--
	if err = x.store.Write("ledger.json", encode(corrupt)); err != nil {
		t.Fatal(err)
	}
	x.Close()
	_, err = Open(c, preflightIssuer{t: t}, noNode{t}, noBroadcast{t}, noStore{t})
	wantError(t, err, "LEDGER_CORRUPT")
}

// Exposure retains reserved seals and uncertain inputs. A durable accepted
// refill replaces consumed funding with its outputs even before tracking, then
// tracking does not double count. This does not measure out-of-band wallet funds.
func TestEnrolledExposureConservation(t *testing.T) {
	c := mainConfig(t)
	x := opened(t, c, Intent{})
	spec := spendingSpec(c, "refill", "exposure")
	seal := su.PlanInput{Point: su.Point{TxID: hash([]byte("reserved-seal"))}, ValueSat: 200000, Script: c.Policy.Policy.SealScript, Role: "seal"}
	x.state.Inventory = []Inventory{{Input: spec.Inputs[0]}, {Input: seal, Reserved: hash([]byte("old-issuance"))}}
	x.cfg.Spending.EnrolledHot = 2200000
	if err := x.capExposure(x.state.Inventory); err != nil {
		t.Fatal("exact exposure boundary", err)
	}
	before := encode(x.state)
	extra := su.PlanInput{Point: su.Point{TxID: hash([]byte("extra"))}, ValueSat: 1, Script: c.Policy.Policy.FundingScript, Role: "funding"}
	wantError(t, x.Enroll(context.Background(), []su.PlanInput{extra}, 500), "ENROLLED_HOT_CAP")
	if !bytes.Equal(before, encode(x.state)) {
		t.Fatal("hot refusal changed inventory")
	}
	id := hash([]byte("refill-exposure"))
	plan, err := rental.MakePlan(c.Policy, spec, nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := record{ID: id, Phase: "prepared", Spec: spec, Plan: &plan}
	if err = x.reserve(operation{ID: id, Kind: "refill", At: 500}, r, []su.Point{spec.Inputs[0].Point}); err != nil {
		t.Fatal(err)
	}
	x.cfg.Spending.EnrolledHot = 2199999
	wantError(t, x.capExposure(x.state.Inventory), "ENROLLED_HOT_CAP")
	key, err := loadKey(c.FundingKeyPath, c.Policy.Policy.FundingScript)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	raw, txid, err := signPlan(plan, key)
	if err != nil {
		t.Fatal(err)
	}
	r.Phase, r.TxID, r.RawTx = "broadcast", txid, hex.EncodeToString(raw)
	if err = x.save(0, r); err != nil {
		t.Fatal(err)
	}
	x.cfg.Spending.EnrolledHot = 2200000 - plan.FeeSat
	if err = x.capExposure(x.state.Inventory); err != nil {
		t.Fatal("accepted refill conservation", err)
	}
	if err = x.trackOutputs(0, r, 500); err != nil {
		t.Fatal(err)
	}
	if err = x.capExposure(x.state.Inventory); err != nil {
		t.Fatal("tracked outputs double counted", err)
	}
	x.cfg.Spending.EnrolledHot--
	wantError(t, x.capExposure(x.state.Inventory), "ENROLLED_HOT_CAP")
	// A completed transaction expires only at the UTC boundary. Its original
	// input still cannot be selected or enrolled again.
	x.cfg.Spending.MovedDay = x.state.Operations[0].MovedAtoms
	wantError(t, x.capSpending(1, 86399, ""), "MOVED_DAY_CAP")
	if err = x.capSpending(1, 86400, ""); err != nil {
		t.Fatal("UTC completed bucket", err)
	}
}

// A changed change-script/role cannot disguise movement. Valid plans exclude
// precisely their pinned funding change; invalid plans return no amount.
func TestMovementChangeBinding(t *testing.T) {
	c := mainConfig(t)
	plan, err := rental.MakePlan(c.Policy, spendingSpec(c, "refill", "plan"), nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if moved, err := movedByPlan(plan, c.Policy.Policy.FundingScript); err != nil || moved != 800000+plan.FeeSat {
		t.Fatal(moved, err)
	}
	plan.Outputs[len(plan.Outputs)-1].Script = c.Policy.Policy.SealScript
	_, err = movedByPlan(plan, c.Policy.Policy.FundingScript)
	wantError(t, err, "MOVEMENT_CHANGE")
}
