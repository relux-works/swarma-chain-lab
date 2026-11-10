package deploy

// Public structural mirrors. Native startup additionally checks cryptographic
// bindings, filesystem custody and live observations. No private file is read.
type mainStore struct {
	Root            string   `json:"root"`
	PublicURL       string   `json:"public_url"`
	Writers         []string `json:"writers"`
	MaxBlobBytes    int64    `json:"max_blob_bytes"`
	MaxBlobs        int      `json:"max_blobs"`
	MaxTotalBytes   int64    `json:"max_total_bytes"`
	MaxReplay       int      `json:"max_replay"`
	MaxReplayPerKey int      `json:"max_replay_per_key"`
	SkewSeconds     int64    `json:"skew_seconds"`
}
type mainRelay struct {
	StateDir                 string   `json:"state_dir"`
	PublicURL                string   `json:"public_url"`
	TrustedProxyIP           string   `json:"trusted_proxy_ip"`
	RequireWriteAuth         bool     `json:"require_write_auth"`
	RequireReadAuth          bool     `json:"require_read_auth"`
	RestrictGiftWrapReads    bool     `json:"restrict_gift_wrap_reads"`
	UnknownPowBits           int      `json:"unknown_pow_bits"`
	KnownPubkeys             []string `json:"known_pubkeys"`
	MaxEventBytes            int      `json:"max_event_bytes"`
	MaxEvents                int      `json:"max_events"`
	MaxStoreBytes            int      `json:"max_store_bytes"`
	RetentionSeconds         int64    `json:"retention_seconds"`
	FutureSeconds            int64    `json:"future_seconds"`
	MaxConnections           int      `json:"max_connections"`
	MaxConnectionsPerIP      int      `json:"max_connections_per_ip"`
	MaxIPs                   int      `json:"max_ips"`
	FramesPerMinute          int      `json:"frames_per_minute"`
	FramesPerIPMinute        int      `json:"frames_per_ip_minute"`
	Subscriptions            int      `json:"subscriptions"`
	Queue                    int      `json:"queue"`
	Backlog                  int      `json:"backlog"`
	ReadTimeoutMilliseconds  int      `json:"read_timeout_milliseconds,omitempty"`
	PingIntervalMilliseconds int      `json:"ping_interval_milliseconds,omitempty"`
}
type mainServeConfig struct {
	Version          int                `json:"version"`
	Mode             string             `json:"mode"`
	AgentKeyFile     string             `json:"agent_key_file"`
	AgentPubkey      string             `json:"agent_pubkey"`
	RelayURL         string             `json:"relay_url"`
	RelayAuth        string             `json:"relay_auth,omitempty"`
	RelayReplayLimit int                `json:"relay_replay_limit,omitempty"`
	JournalDir       string             `json:"journal_dir"`
	StationSocket    string             `json:"station_socket"`
	Screening        string             `json:"screening"`
	Kernel           mainKernelConfig   `json:"kernel"`
	Exchange         mainExchangeConfig `json:"exchange"`
	Station          mainStationConfig  `json:"station"`
	ModelProxy       *gatewayModelProxy `json:"model_proxy,omitempty"`
}
type mainKernelConfig struct {
	ConstructionProfile string `json:"construction_profile"`
	Kind                string `json:"kind"`
	StubVerdict         string `json:"stub_verdict"`
	Network             string `json:"network"`
	Genesis             string `json:"genesis"`
	AgentName           string `json:"agent_name"`
	LandlordName        string `json:"landlord_name"`
	IssuerPubkey        string `json:"issuer_pubkey"`
	SealScript          string `json:"seal_script"`
	StateDir            string `json:"state_dir"`
	RPCHost             string `json:"rpc_host"`
	RPCPort             int    `json:"rpc_port"`
	RPCRouteFile        string `json:"rpc_route_file"`
}
type mainExchangeConfig struct {
	BookingVersion    int      `json:"booking_version"`
	PaymentCoins      []string `json:"payment_coins"`
	StateDir          string   `json:"state_dir"`
	BookingURL        string   `json:"booking_url"`
	PresentationsDir  string   `json:"presentations_dir"`
	PrivacySHA256     string   `json:"privacy_sha256"`
	TemplateSHA256    string   `json:"template_sha256"`
	ProfileSHA256     string   `json:"profile_sha256"`
	PowBits           int      `json:"pow_bits"`
	MaxClients        int      `json:"max_clients"`
	QueueSize         int      `json:"queue_size"`
	Burst             int      `json:"burst"`
	MaxReplay         int      `json:"max_replay"`
	RefillSeconds     int64    `json:"refill_seconds"`
	KnownSeconds      int64    `json:"known_seconds"`
	MessageAgeSeconds int64    `json:"message_age_seconds"`
	PollMilliseconds  int64    `json:"poll_milliseconds"`
	CallMilliseconds  int64    `json:"call_milliseconds"`
}
type mainStationConfig struct {
	Driver    string             `json:"driver"`
	Root      string             `json:"root"`
	StubAgent bool               `json:"stub_agent"`
	Manager   *mainManagerConfig `json:"manager,omitempty"`
}
type mainManagerConfig struct {
	StateDir          string               `json:"state_dir"`
	PayloadID         string               `json:"payload_id"`
	PayloadSHA256     string               `json:"payload_sha256"`
	SlotMin           int                  `json:"slot_min"`
	SlotMax           int                  `json:"slot_max"`
	StartMilliseconds int64                `json:"start_milliseconds"`
	Listen            string               `json:"listen"`
	PayloadListen     string               `json:"payload_listen"`
	TLS               mainGatewayTLSConfig `json:"tls"`
}
type mainGatewayTLSConfig struct {
	CertFile          string `json:"cert_file"`
	KeyFile           string `json:"key_file"`
	CertSHA256        string `json:"cert_sha256"`
	ManagerCAFile     string `json:"manager_ca_file"`
	ManagerCertSHA256 string `json:"manager_cert_sha256"`
}
