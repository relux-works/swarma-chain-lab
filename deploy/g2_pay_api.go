package deploy

// PX1 FROZEN CONTRACT, stream S5 surface: G2 pay deploy template parameters
// and the T18 different-UID custody check. Implementation lives in g2_pay.go
// (owner S5). See experiments/agent-wallet/PX1-INTERFACES.md.
//
// Placement (Q9): agent-walletd and Cedar's slot run on the same station host
// under separate UIDs; the agent reaches only /run/swarma-wallet/wallet.sock.
// The executor host runs its own mainnet node (txindex, listen=0) with the
// dedicated hot wallet; nothing here funds, starts or spends.

import (
	"context"
	"os/user"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// G2PayParameters are the operator inputs of templates/g2-pay/*. Field order
// is the canonical JSON order of the parameters file. Amount values are
// proposals until Ivan sets them (plan §3, Q3).
type G2PayParameters struct {
	Network        string               `json:"network"`          // "main"
	Genesis        string               `json:"genesis"`          // pinned main genesis
	AgentUID       uint32               `json:"agent_uid"`        // Cedar's slot UID (service peer_uid); != service UID
	AgentSocketGID uint32               `json:"agent_socket_gid"` // per-agent socket group (service socket_gid)
	OperatorGID    uint32               `json:"operator_gid"`     // group of /run/swarma-wallet/status.sock
	ServiceUID     uint32               `json:"service_uid"`      // swarma-wallet UID (sysusers "u" line, client.json, custody spec); != AgentUID
	AgentUser      string               `json:"agent_user"`       // login name of AgentUID on the applying host (sysusers "m" line); bound by ValidateG2PayIdentity
	AgentKeyFile   string               `json:"agent_key_file"`   // absolute, clean path of the agent action key (client.json)
	NodeDataDir    string               `json:"node_datadir"`     // absolute, clean datadir of the own node (cookie and wallet.dat in the custody spec)
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
	// Freeze amendment 1: it refuses with the error of
	// ValidateG2PayIdentity(p, LookupG2HostAccount) before its own checks, so
	// every render binds agent_user to agent_uid on the host that applies it.
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

// G2AccountLookup resolves a login name to its numeric UID in the account
// database of the host that applies the rendered files. An unknown name is an
// error, never UID 0.
type G2AccountLookup func(name string) (uid uint32, err error)

// Frozen identity helpers (freeze amendment 1, S5 R1), implemented here.
var (
	_ G2AccountLookup                              = LookupG2HostAccount
	_ func(G2PayParameters, G2AccountLookup) error = ValidateG2PayIdentity
)

// LookupG2HostAccount is the production G2AccountLookup: the host account
// database through os/user.
func LookupG2HostAccount(name string) (uint32, error) {
	u, e := user.Lookup(name)
	if e != nil {
		return 0, e
	}
	id, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil {
		return 0, e
	}
	return uint32(id), nil
}

// g2SysusersName is the strict systemd-sysusers user name rule.
var g2SysusersName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,30}$`)

// G2ReservedID reports an ID that no G2 account or group may carry: root (0),
// nobody/nogroup (65534), the 16-bit (uid_t)-1 65535 that systemd-sysusers
// refuses, and the 32-bit (uid_t)-1. The same domain applies to the two UIDs
// and the two GIDs; 65533 and 65536 are valid.
func G2ReservedID(id uint32) bool {
	return id == 0 || id == 65534 || id == 65535 || id == 1<<32-1
}

// g2AbsPath accepts an absolute, clean, non-root path of printable ASCII
// without whitespace, at most 4095 bytes (PATH_MAX - 1).
func g2AbsPath(p string) bool {
	if len(p) < 2 || len(p) > 4095 || p[0] != '/' || path.Clean(p) != p {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// ValidateG2PayIdentity is the frozen identity and path check of the G2 pay
// parameters. It refuses ErrPolicy when:
//   - AgentUID, ServiceUID, AgentSocketGID or OperatorGID is a G2ReservedID;
//   - ServiceUID == AgentUID (Q9);
//   - AgentUser breaks the strict sysusers name rule ([A-Za-z_][A-Za-z0-9_-]*,
//     at most 31 bytes), or is root, nobody or a swarma-wallet* name;
//   - AgentKeyFile or NodeDataDir is not an absolute, clean path (g2AbsPath),
//     or the two are equal;
//   - lookup is nil, lookup(AgentUser) fails, or it returns a UID other than
//     AgentUID: the name is BOUND to agent_uid, so a typo can never make the
//     rendered "m" line create a new account.
func ValidateG2PayIdentity(p G2PayParameters, lookup G2AccountLookup) error {
	for _, id := range []uint32{p.AgentUID, p.ServiceUID, p.AgentSocketGID, p.OperatorGID} {
		if G2ReservedID(id) {
			return ErrPolicy
		}
	}
	if p.ServiceUID == p.AgentUID {
		return ErrPolicy
	}
	if !g2SysusersName.MatchString(p.AgentUser) || p.AgentUser == "root" || p.AgentUser == "nobody" || strings.HasPrefix(p.AgentUser, "swarma-wallet") {
		return ErrPolicy
	}
	if !g2AbsPath(p.AgentKeyFile) || !g2AbsPath(p.NodeDataDir) || p.AgentKeyFile == p.NodeDataDir {
		return ErrPolicy
	}
	if lookup == nil {
		return ErrPolicy
	}
	if uid, e := lookup(p.AgentUser); e != nil || uid != p.AgentUID {
		return ErrPolicy
	}
	return nil
}

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
