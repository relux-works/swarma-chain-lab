package signerservice

import (
	"context"
	"encoding/json"
	paymentchain "relux.works/swarma-chain-lab/experiments/payment-chain"
	rental "relux.works/swarma-chain-lab/experiments/rental"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type FileConfig struct {
	PaymentRouteFiles   map[string]string `json:"payment_route_files,omitempty"`
	Config              Config            `json:"config"`
	ReadRouteFile       string            `json:"read_route_file"`
	BroadcastRouteFile  string            `json:"broadcast_route_file"`
	BookingOutbox       string            `json:"booking_outbox"`
	OperatorOutbox      string            `json:"operator_outbox,omitempty"`
	StoreURL            string            `json:"store_url"`
	StoreLandlordReader string            `json:"store_landlord_reader"`
	StoreAgentReader    string            `json:"store_agent_reader"`
	IntervalSeconds     int               `json:"interval_seconds"`
	Inventory           []su.PlanInput    `json:"inventory,omitempty"`
}

func readJSON(path string, v any) error {
	b, e := privateRead(path, 65536)
	if e != nil {
		return e
	}
	defer clear(b)
	if strict(b, v) != nil {
		return fail("CONFIG_ENCODING")
	}
	return nil
}

// RunFile loads only explicitly named private files. Mainnet admission is
// rejected before reading either RPC credentials or signing keys.
func RunFile(ctx context.Context, path string, once bool, report func(Result)) error {
	var f FileConfig
	if e := readJSON(path, &f); e != nil {
		return e
	}
	if e := f.Config.validate(); e != nil {
		return e
	}
	if f.Config.Profile != "v1-nmc" && f.Config.Profile != "v2" {
		return fail("ISSUER_PROFILE_UNAVAILABLE")
	}
	if f.IntervalSeconds < 1 || f.IntervalSeconds > 3600 {
		return fail("LOOP_CONFIG")
	}
	var readRoute, writeRoute su.Route
	if e := readJSON(f.ReadRouteFile, &readRoute); e != nil {
		return e
	}
	if e := readJSON(f.BroadcastRouteFile, &writeRoute); e != nil {
		return e
	}
	node, e := su.NewRPC(readRoute)
	if e != nil {
		return e
	}
	broadcaster, e := NewRPCBroadcast(writeRoute, readRoute)
	if e != nil {
		return e
	}
	key, e := loadKey(f.Config.GrantKeyPath, f.Config.Policy.Policy.SealScript)
	if e != nil {
		return e
	}
	defer key.Zero()
	b := key.Serialize()
	signer, e := nostr.PrivKeyFromBytes(b)
	clear(b)
	if e != nil {
		return fail("STORE_SIGNER")
	}
	sink, e := NewS1Store(f.StoreURL, signer, f.StoreLandlordReader, f.StoreAgentReader)
	if e != nil {
		return e
	}
	var issuer Issuer = V1Issuer{Policy: f.Config.Policy, Node: node, KeyPath: f.Config.GrantKeyPath}
	if f.Config.Profile == "v2" {
		nodes := map[string]su.Node{}
		if len(f.Config.PaymentPolicies) < 1 || len(f.Config.PaymentPolicies) > 3 || len(f.PaymentRouteFiles) != len(f.Config.PaymentPolicies) {
			return fail("PAYMENT_ROUTES")
		}
		for coin, path := range f.PaymentRouteFiles {
			if _, e := paymentchain.ParseCoin(coin); e != nil {
				return fail("PAYMENT_ROUTES")
			}
			policy, ok := f.Config.PaymentPolicies[coin]
			if !ok || policy.MinConfirmations < 1 || policy.MaxRateAgeSeconds < 1 {
				return fail("PAYMENT_POLICY")
			}
			var route paymentchain.Route
			if e := readJSON(path, &route); e != nil {
				return e
			}
			rpc, e := paymentchain.NewIssuerRPC(route)
			if e != nil {
				return e
			}
			nodes[coin] = rpc
		}
		issuer = V2Issuer{Policy: rental.IssuerPolicyV2{IssuerPolicy: f.Config.Policy, PaymentPolicies: f.Config.PaymentPolicies}, Identity: node, Payments: nodes, KeyPath: f.Config.GrantKeyPath}
	}
	engine, e := Open(f.Config, issuer, node, broadcaster, sink)
	if e != nil {
		return e
	}
	defer engine.Close()
	// Initial inventory is enrolled only into a pristine ledger. Reconfiguration
	// never replaces old reservations, even when the file lists the same points.
	if len(engine.state.Inventory) == 0 && len(engine.state.Operations) == 0 && len(f.Inventory) > 0 {
		if e = engine.Enroll(ctx, f.Inventory, time.Now().Unix()); e != nil {
			return e
		}
	}
	booking, e := OpenFileSource(f.BookingOutbox)
	if e != nil {
		return e
	}
	sources := Sources{Booking: booking}
	if f.OperatorOutbox != "" {
		sources.Operator, e = OpenFileSource(f.OperatorOutbox)
		if e != nil {
			return e
		}
	}
	if once {
		now := time.Now().Unix()
		if e = engine.Pull(ctx, sources.Booking, BookingSource, now); e != nil {
			return e
		}
		if sources.Operator != nil {
			if e = engine.Pull(ctx, sources.Operator, OperatorSource, now); e != nil {
				return e
			}
		}
		for _, r := range engine.Step(ctx, time.Now().Unix()) {
			if report != nil {
				report(r)
			}
		}
		r, e := engine.Refill(ctx, time.Now().Unix())
		if e != nil {
			r.Reason = e.Error()
		}
		if report != nil {
			report(r)
		}
		return nil
	}
	return engine.Run(ctx, sources, time.Duration(f.IntervalSeconds)*time.Second, report)
}

// EncodeResult deliberately contains no serialized grant, config or route.
func EncodeResult(r Result) []byte { b, _ := json.Marshal(r); return b }
