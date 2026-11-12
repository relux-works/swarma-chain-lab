package deploy

// PX1 FROZEN CONTRACT, stream S5 surface: G2 pay deploy template parameters
// and the T18 different-UID custody check. Implementation lives in g2_pay.go
// (owner S5). See experiments/agent-wallet/PX1-INTERFACES.md.
//
// Placement (Q9): agent-walletd and Cedar's slot run on the same station host
// under separate UIDs; the agent reaches only G2WalletSocketPath, and the
// operator status socket lives in its own directory (G2StatusSocketDir).
// The executor host runs its own mainnet node (txindex, listen=0) with the
// dedicated hot wallet; nothing here funds, starts or spends.

import (
	"context"
	"errors"
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
	OperatorGID    uint32               `json:"operator_gid"`     // group of G2StatusSocketDir and G2StatusSocketPath
	ServiceUID     uint32               `json:"service_uid"`      // swarma-wallet UID (sysusers "u" line, client.json, custody spec); != AgentUID
	AgentUser      string               `json:"agent_user"`       // name of AgentUID on the target host (G2AgentSysusers "u" and "m" lines); bound by ValidateG2PayIdentity and VerifyG2AgentAccount
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

// Socket placement (freeze amendment 1, A8; the slot AF_UNIX confinement
// design), frozen. The agent-facing runtime directory holds ONLY wallet.sock
// and is the one directory bound into a slot. The operator status socket has
// its own directory, owned by the service UID with group operator_gid, and is
// never bound into a slot. No agent-facing path shares a directory with it.
const (
	G2WalletSocketDir     = "/run/swarma-wallet"
	G2WalletSocketPath    = G2WalletSocketDir + "/wallet.sock"
	G2StatusSocketDir     = "/run/swarma-wallet-status"
	G2StatusSocketPath    = G2StatusSocketDir + "/status.sock"
	G2StatusSocketDirMode = 0o750 // owner service UID, group operator_gid
	G2StatusSocketMode    = 0o660 // group operator_gid
)

// Group names rendered into sysusers.conf, frozen: agent_socket_gid is
// G2AgentSocketGroup (the agent's only G2 group), operator_gid is
// G2OperatorGroup (the operator's only G2 group; never swarma-wallet-peer).
const (
	G2AgentSocketGroup = "swarma-wallet-peer"
	G2OperatorGroup    = "swarma-wallet-status"
)

// Frozen entry points (implemented in g2_pay.go).
var (
	// ValidateG2PayParameters refuses ErrNetwork or ErrPolicy (existing
	// sentinels) on any pin, UID, key, fee-rate (100..1000) or ceiling error.
	// Freeze amendment 1: it refuses with the error of
	// ValidateG2PayIdentityDomain(p) before its own checks. It reads no
	// account database: rendering is a pure function of the parameters. The
	// account binding is checked on the TARGET host by ValidateG2PayIdentity
	// (before systemd-sysusers applies sysusers.conf) and VerifyG2AgentAccount
	// (after it applied, before any G2 service is activated).
	_ func(G2PayParameters) error = ValidateG2PayParameters
	// RenderG2PayTemplates renders the G2File* set; no secret ever appears.
	// sysusers.conf contains G2AgentSysusers(p) verbatim; tmpfiles.conf
	// creates G2StatusSocketDir 0750 with owner swarma-wallet and group
	// G2OperatorGroup.
	_ func(G2PayParameters) (map[string][]byte, error) = RenderG2PayTemplates
	// RunCustodyProbe runs T18 as the agent UID (refuses unless
	// os.Getuid() == spec.AgentUID and != spec.ServiceUID).
	_ func(ctx context.Context, spec CustodySpecV1) (CustodyReportV1, error) = RunCustodyProbe
	// VerifyCustodyReport accepts only a report that ran as spec.AgentUID,
	// binds SHA256(canonical spec), contains exactly one probe per target in
	// spec order, and passes every probe.
	_ func(spec CustodySpecV1, report CustodyReportV1) error = VerifyCustodyReport
)

// ErrG2AccountAbsent marks GENUINE absence in an account database: no entry
// for the name (os/user.UnknownUserError) or for the UID
// (os/user.UnknownUserIdError). Every other lookup error is an outage and is
// never absence.
var ErrG2AccountAbsent = errors.New("g2: account absent")

// G2AccountDB is the account database of the TARGET host, the host that
// applies sysusers.conf and runs the slot. A rendering machine's database is
// no evidence about another host.
type G2AccountDB interface {
	// UserUID returns the UID of name; an error wrapping ErrG2AccountAbsent
	// only when the name has no entry.
	UserUID(name string) (uint32, error)
	// UIDUser returns the name that owns uid; an error wrapping
	// ErrG2AccountAbsent only when the UID has no entry.
	UIDUser(uid uint32) (string, error)
	// UserGroups returns every GID name is a member of, primary included.
	UserGroups(name string) ([]uint32, error)
}

// Frozen identity helpers (freeze amendment 1, S5 R1), implemented here.
var (
	_ G2AccountDB                              = G2HostAccounts{}
	_ func(G2PayParameters) error              = ValidateG2PayIdentityDomain
	_ func(G2PayParameters, G2AccountDB) error = ValidateG2PayIdentity
	_ func(G2PayParameters) (string, error)    = G2AgentSysusers
	_ func(G2PayParameters, G2AccountDB) error = VerifyG2AgentAccount
)

// G2HostAccounts is the production G2AccountDB: the account database of the
// host it runs on, through os/user. Run it on the target host only.
type G2HostAccounts struct{}

// g2AccountErr classifies an os/user error: the two unknown-entry errors wrap
// ErrG2AccountAbsent; every other error is returned unchanged (an outage).
func g2AccountErr(e error) error {
	var name user.UnknownUserError
	var id user.UnknownUserIdError
	if errors.As(e, &name) || errors.As(e, &id) {
		return errors.Join(ErrG2AccountAbsent, e)
	}
	return e
}

// UserUID implements G2AccountDB.
func (G2HostAccounts) UserUID(name string) (uint32, error) {
	u, e := user.Lookup(name)
	if e != nil {
		return 0, g2AccountErr(e)
	}
	id, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil {
		return 0, e
	}
	return uint32(id), nil
}

// UIDUser implements G2AccountDB.
func (G2HostAccounts) UIDUser(uid uint32) (string, error) {
	u, e := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if e != nil {
		return "", g2AccountErr(e)
	}
	return u.Username, nil
}

// UserGroups implements G2AccountDB.
func (G2HostAccounts) UserGroups(name string) ([]uint32, error) {
	u, e := user.Lookup(name)
	if e != nil {
		return nil, g2AccountErr(e)
	}
	ids, e := u.GroupIds()
	if e != nil {
		return nil, e
	}
	out := make([]uint32, 0, len(ids))
	for _, s := range ids {
		id, e := strconv.ParseUint(s, 10, 32)
		if e != nil {
			return nil, e
		}
		out = append(out, uint32(id))
	}
	return out, nil
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

// ValidateG2PayIdentityDomain is the pure identity and path check of the G2
// pay parameters; it reads no account database. It refuses ErrPolicy when:
//   - AgentUID, ServiceUID, AgentSocketGID or OperatorGID is a G2ReservedID;
//   - ServiceUID == AgentUID (Q9);
//   - AgentUser breaks the strict sysusers name rule ([A-Za-z_][A-Za-z0-9_-]*,
//     at most 31 bytes), or is root, nobody or a swarma-wallet* name;
//   - AgentKeyFile or NodeDataDir is not an absolute, clean path (g2AbsPath),
//     or the two are equal.
func ValidateG2PayIdentityDomain(p G2PayParameters) error {
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
	return nil
}

// ValidateG2PayIdentity is the target-host PREFLIGHT, run on the target host
// before systemd-sysusers applies sysusers.conf. It refuses ErrPolicy when
// ValidateG2PayIdentityDomain refuses, db is nil, or the account state is not
// one of the two admitted states:
//   - existing: db.UserUID(agent_user) succeeds and equals agent_uid exactly
//     (another UID refuses: sysusers would keep the existing account);
//   - first install: db.UserUID(agent_user) is ErrG2AccountAbsent AND
//     db.UIDUser(agent_uid) is ErrG2AccountAbsent (no other name owns the
//     UID; on a collision sysusers would substitute another UID).
//
// Any other error of either lookup (an outage) refuses; it is never absence.
// A passing preflight is not proof of the result: VerifyG2AgentAccount is
// still required after the apply.
func ValidateG2PayIdentity(p G2PayParameters, db G2AccountDB) error {
	if e := ValidateG2PayIdentityDomain(p); e != nil {
		return e
	}
	if db == nil {
		return ErrPolicy
	}
	uid, e := db.UserUID(p.AgentUser)
	switch {
	case e == nil:
		if uid != p.AgentUID {
			return ErrPolicy
		}
	case errors.Is(e, ErrG2AccountAbsent):
		if _, e := db.UIDUser(p.AgentUID); !errors.Is(e, ErrG2AccountAbsent) {
			return ErrPolicy
		}
	default:
		return ErrPolicy
	}
	return nil
}

// G2AgentSysusers returns the frozen agent lines of sysusers.conf: an explicit
// numeric user declaration and the agent's only G2 membership,
//
//	u <agent_user> <agent_uid>
//	m <agent_user> swarma-wallet-peer
//
// An "m"-only line is never a UID binding (sysusers would create the name at
// a dynamic UID). The "u" line is a request, not a guarantee: sysusers keeps
// an existing name at its UID and substitutes a free UID on a collision, so
// ValidateG2PayIdentity before and VerifyG2AgentAccount after the apply are
// both required. It refuses with ValidateG2PayIdentityDomain's error.
func G2AgentSysusers(p G2PayParameters) (string, error) {
	if e := ValidateG2PayIdentityDomain(p); e != nil {
		return "", e
	}
	return "u " + p.AgentUser + " " + strconv.FormatUint(uint64(p.AgentUID), 10) + "\n" +
		"m " + p.AgentUser + " " + G2AgentSocketGroup + "\n", nil
}

// VerifyG2AgentAccount is the REQUIRED post-apply check: run on the target
// host after systemd-sysusers applied sysusers.conf and BEFORE any G2 service
// (agent-walletd or the slot) is activated. The apply's exit status proves
// nothing about the UID. It refuses ErrPolicy unless:
//   - ValidateG2PayIdentityDomain(p) passes and db is not nil;
//   - db.UserUID(agent_user) succeeds and equals agent_uid exactly (absent,
//     an outage and a substituted UID all refuse);
//   - db.UserGroups(agent_user) succeeds, contains agent_socket_gid and does
//     not contain operator_gid.
func VerifyG2AgentAccount(p G2PayParameters, db G2AccountDB) error {
	if e := ValidateG2PayIdentityDomain(p); e != nil {
		return e
	}
	if db == nil {
		return ErrPolicy
	}
	if uid, e := db.UserUID(p.AgentUser); e != nil || uid != p.AgentUID {
		return ErrPolicy
	}
	gids, e := db.UserGroups(p.AgentUser)
	if e != nil {
		return ErrPolicy
	}
	socket := false
	for _, g := range gids {
		if g == p.OperatorGID {
			return ErrPolicy
		}
		if g == p.AgentSocketGID {
			socket = true
		}
	}
	if !socket {
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
	DeniedReads   []string `json:"denied_reads"`   // wallet.json, receipt.key, service/wallet state dirs, node cookie, wallet.dat, G2StatusSocketDir (A8)
	DeniedRPC     []string `json:"denied_rpc"`     // "127.0.0.1:<port>": a credential-less JSON-RPC call must fail (HTTP 401/403 or refused)
	AllowedSocket string   `json:"allowed_socket"` // G2WalletSocketPath: connect must succeed (positive control)
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
