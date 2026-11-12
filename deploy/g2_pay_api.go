package deploy

// PX1 FROZEN CONTRACT, stream S5 surface: G2 pay deploy template parameters
// and the T18 different-UID custody check. Implementation lives in g2_pay.go
// (owner S5). See experiments/agent-wallet/PX1-INTERFACES.md.
//
// Placement (Q9): agent-walletd and Cedar's slot run on the same station host
// under separate UIDs; the agent reaches only /run/swarma-wallet/wallet.sock.
// The executor host runs its own mainnet node (txindex, listen=0) with the
// dedicated hot wallet; nothing here funds, starts or spends.

import "context"

// G2PayParameters are the operator inputs of templates/g2-pay/*. Field order
// is the canonical JSON order of the parameters file. Amount values are
// proposals until Ivan sets them (plan §3, Q3).
type G2PayParameters struct {
	Network        string               `json:"network"`          // "main"
	Genesis        string               `json:"genesis"`          // pinned main genesis
	AgentUID       uint32               `json:"agent_uid"`        // Cedar's slot UID (service peer_uid); != service UID
	AgentSocketGID uint32               `json:"agent_socket_gid"` // per-agent socket group (service socket_gid)
	OperatorGID    uint32               `json:"operator_gid"`     // group of /run/swarma-wallet/status.sock
	Grantee        string               `json:"grantee"`          // x-only Cedar action key (pay grant grantee)
	ReceiptPubkey  string               `json:"receipt_pubkey"`   // x-only executor_key; private scalar stays in /etc/swarma/wallet/receipt.key
	FeeRateSatVB   int64                `json:"fee_rate_sat_vb"`  // co-lead: ~110 (relay floor 100), never 200
	HotWalletName  string               `json:"hot_wallet_name"`  // dedicated legacy Core wallet on the own node
	NodeRPCPort    uint16               `json:"node_rpc_port"`    // loopback RPC port of the own node
	G2             G2OperatorParameters `json:"g2"`               // becomes the "g2" member of service.json
}

// G2OperatorParameters is the structural mirror of agent-wallet's
// G2OperatorConfig (same members, same order, golden bytes pinned in both
// modules). deploy never imports agent-wallet.
type G2OperatorParameters struct {
	RequireTermsVersion  int                `json:"require_terms_version"`
	AllowSingleUse       bool               `json:"allow_single_use"`
	AllowAnyRecipients   bool               `json:"allow_any_recipients"`
	MaxTransferSat       int64              `json:"max_transfer_sat"`
	MaxDaySat            int64              `json:"max_day_sat"`
	MaxDayCount          int                `json:"max_day_count"`
	MaxFeeSat            int64              `json:"max_fee_sat"`
	MaxFloatSat          int64              `json:"max_float_sat"`
	LowFloatSat          int64              `json:"low_float_sat"`
	Canary               G2CanaryParameters `json:"canary"`
	ConfirmationsK       int                `json:"confirmations_k"`
	ConflictBlocksN      int                `json:"conflict_blocks_n"`
	ReadRatePerHour      int                `json:"read_rate_per_hour"`
	JournalSpendCapacity int                `json:"journal_spend_capacity"`
}

// G2CanaryParameters mirrors agent-wallet CanaryConfig.
type G2CanaryParameters struct {
	Outpoint G2Outpoint `json:"outpoint"`
	ValueSat int64      `json:"value_sat"`
}

// G2Outpoint mirrors single-use Point.
type G2Outpoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

// Rendered file names, frozen. RenderG2PayTemplates returns exactly these keys.
const (
	G2FileServiceConfig = "service.json"      // public pins + "g2" block (root:swarma-wallet 0640)
	G2FileClientConfig  = "client.json"       // agent client config (no RPC, no coin key)
	G2FileSysusers      = "sysusers.conf"     // provisioning input; root applies it
	G2FileTmpfiles      = "tmpfiles.conf"     // socket/state directories and modes
	G2FileRPCWhitelist  = "namecoin-rpc.conf" // rpcwhitelist lines for w3-observer, w1-wallet, w1-broadcast; rpcwhitelistdefault=0
	G2FileCustodySpec   = "custody-spec.json" // T18 input (CustodySpecV1)
)

// Frozen entry points (implemented in g2_pay.go).
var (
	// ValidateG2PayParameters refuses ErrNetwork or ErrPolicy (existing
	// sentinels) on any pin, UID, key, fee-rate (100..1000) or ceiling error.
	_ func(G2PayParameters) error = ValidateG2PayParameters
	// RenderG2PayTemplates renders the G2File* set; no secret ever appears.
	_ func(G2PayParameters) (map[string][]byte, error) = RenderG2PayTemplates
	// RunCustodyProbe runs T18 as the agent UID (refuses unless
	// os.Getuid() == spec.AgentUID and != spec.ServiceUID).
	_ func(ctx context.Context, spec CustodySpecV1) (CustodyReportV1, error) = RunCustodyProbe
	// VerifyCustodyReport accepts only a report that ran as spec.AgentUID,
	// binds SHA256(canonical spec), contains exactly one probe per target in
	// spec order, and passes every probe.
	_ func(spec CustodySpecV1, report CustodyReportV1) error = VerifyCustodyReport
)

// CustodySpecV1 is the T18 input rendered by RenderG2PayTemplates and read by
// the probe. Every DeniedReads path must exist on the host: a denied probe
// passes only on EACCES/EPERM, never on ENOENT (a missing file proves nothing).
type CustodySpecV1 struct {
	Version       int      `json:"v"` // 1
	AgentUID      uint32   `json:"agent_uid"`
	ServiceUID    uint32   `json:"service_uid"`
	DeniedReads   []string `json:"denied_reads"`   // wallet.json, receipt.key, service/wallet state dirs, node cookie, wallet.dat
	DeniedRPC     []string `json:"denied_rpc"`     // "127.0.0.1:<port>": a credential-less JSON-RPC call must fail (HTTP 401/403 or refused)
	AllowedSocket string   `json:"allowed_socket"` // /run/swarma-wallet/wallet.sock: connect must succeed (positive control)
}

// CustodyProbeV1 is one probe result. Observed is a bounded code: EACCES,
// EPERM, ENOENT, READ_OK, HTTP_401, HTTP_403, HTTP_OK, REFUSED, CONNECTED.
type CustodyProbeV1 struct {
	Kind     string `json:"kind"` // "read" | "rpc" | "socket"
	Target   string `json:"target"`
	Expect   string `json:"expect"` // "denied" | "allowed"
	Observed string `json:"observed"`
	Pass     bool   `json:"pass"`
}

// CustodyReportV1 is the T18 evidence record kept with the launch packet.
type CustodyReportV1 struct {
	Version    int              `json:"v"`
	SpecSHA256 string           `json:"spec_sha256"`
	UID        uint32           `json:"uid"`
	GID        uint32           `json:"gid"`
	Probes     []CustodyProbeV1 `json:"probes"`
	Pass       bool             `json:"pass"`
}
