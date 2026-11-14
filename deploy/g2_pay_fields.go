package deploy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// FieldError identifies a declared parameters member (or "parameters" for a
// document-level error). Path contains schema names only, never input values.
// Reason preserves the parser's existing sentinel through errors.Is.
type FieldError struct {
	Path   string
	Reason error
}

func (e *FieldError) Error() string { return e.Reason.Error() + ": " + e.Path }
func (e *FieldError) Unwrap() error { return e.Reason }

// validateG2PayFields runs the frozen validator's predicates with member
// attribution at the point of refusal. Keep ValidateG2PayParameters and its
// identity-domain implementation unchanged; differential tests pin this
// non-frozen diagnostic implementation to their acceptance and sentinel order.
func validateG2PayFields(p G2PayParameters) error {
	for _, f := range []struct {
		path string
		id   uint32
	}{{"agent_uid", p.AgentUID}, {"service_uid", p.ServiceUID}, {"agent_socket_gid", p.AgentSocketGID}, {"operator_gid", p.OperatorGID}} {
		if G2ReservedID(f.id) {
			return &FieldError{f.path, ErrPolicy}
		}
	}
	c, o := p.G2, p.G2.Canary.Outpoint
	// The first failing predicate wins, in the same order as the frozen
	// identity domain, chain pins, parameters, and operator validation.
	checks := []struct {
		path string
		bad  bool
	}{
		{"service_uid, agent_uid", p.ServiceUID == p.AgentUID},
		{"agent_user", !g2SysusersName.MatchString(p.AgentUser) || p.AgentUser == "root" || p.AgentUser == "nobody" || strings.HasPrefix(p.AgentUser, "swarma-wallet")},
		{"agent_key_file", !g2AbsPath(p.AgentKeyFile)},
		{"node_datadir", !g2AbsPath(p.NodeDataDir)},
		{"agent_key_file, node_datadir", p.AgentKeyFile == p.NodeDataDir},
		{"network", p.Network != "main" && p.Network != "regtest"},
		{"genesis", !g2Pins(p.Network, p.Genesis)},
		{"agent_socket_gid, operator_gid", p.AgentSocketGID == p.OperatorGID},
		{"node_datadir", !g2NodeDatadir(p.NodeDataDir)},
		{"grantee", !xOnlyKey(p.Grantee)},
		{"receipt_pubkey", !xOnlyKey(p.ReceiptPubkey)},
		{"grantee, receipt_pubkey", p.Grantee == p.ReceiptPubkey},
		{"fee_rate_sat_vb", p.FeeRateSatVB < 100 || p.FeeRateSatVB > 1000},
		{"hot_wallet_name", !g2WalletName(p.HotWalletName)},
		{"node_rpc_port", p.NodeRPCPort == 0},
		{"g2.require_terms_version", c.RequireTermsVersion != 2},
		{"g2.allow_single_use", c.AllowSingleUse},
		{"g2.allow_any_recipients", c.AllowAnyRecipients},
		{"g2.max_transfer_sat", c.MaxTransferSat < 1 || c.MaxTransferSat > c.MaxDaySat},
		{"g2.max_day_count", c.MaxDayCount < 1 || c.MaxDayCount > 1000},
		{"g2.max_fee_sat", c.MaxFeeSat < 1 || c.MaxFeeSat > 1000000},
		{"g2.max_float_sat", c.MaxFloatSat < 1 || c.MaxFloatSat > 21000000*100000000},
		{"g2.max_day_sat", c.MaxDaySat > c.MaxFloatSat},
		{"g2.low_float_sat", c.LowFloatSat < 0 || c.LowFloatSat >= c.MaxFloatSat},
		{"g2.canary.outpoint.txid", !digestPin(o.TxID)},
		{"g2.canary.outpoint.vout", o.Vout > 0xffff},
		{"g2.canary.value_sat", c.Canary.ValueSat < 546 || c.Canary.ValueSat > c.MaxFloatSat},
		{"g2.confirmations_k", c.ConfirmationsK < 1 || c.ConfirmationsK > 6},
		{"g2.conflict_blocks_n", c.ConflictBlocksN < c.ConfirmationsK || c.ConflictBlocksN > 144},
		{"g2.read_rate_per_hour", c.ReadRatePerHour < 1 || c.ReadRatePerHour > 3600},
		{"g2.journal_spend_capacity", c.JournalSpendCapacity < c.MaxDayCount+64 || c.JournalSpendCapacity > 1<<20},
	}
	for _, check := range checks {
		if check.bad {
			reason := ErrPolicy
			if check.path == "network" || check.path == "genesis" {
				reason = ErrNetwork
			}
			return &FieldError{check.path, reason}
		}
	}
	return nil
}

// g2PayShapeError names missing/null/mistyped members and literal placeholders
// within the canonical parser. It only walks declared names. Document errors
// without a member-level failure retain parameters scope. It never returns a
// decoder's potentially input-bearing error text.
func g2PayShapeError(raw []byte, reason error) error {
	var fields []string
	var walk func(json.RawMessage, reflect.Type, string)
	walk = func(value json.RawMessage, typ reflect.Type, path string) {
		if len(value) == 0 || bytes.Equal(value, []byte("null")) {
			fields = append(fields, path)
			return
		}
		if typ.Kind() == reflect.Struct {
			var members map[string]json.RawMessage
			if json.Unmarshal(value, &members) != nil || members == nil {
				fields = append(fields, path)
				return
			}
			for i := 0; i < typ.NumField(); i++ {
				member := typ.Field(i)
				name := member.Tag.Get("json")
				child := name
				if path != "parameters" {
					child = path + "." + name
				}
				walk(members[name], member.Type, child)
			}
			return
		}
		if json.Unmarshal(value, reflect.New(typ).Interface()) != nil || bytes.Contains(value, []byte("PLACEHOLDER")) {
			fields = append(fields, path)
		}
	}
	walk(raw, reflect.TypeFor[G2PayParameters](), "parameters")
	if len(fields) == 0 {
		fields = []string{"parameters"}
	}
	return &FieldError{strings.Join(fields, ", "), reason}
}
