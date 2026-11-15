package rental

// IdentityReason names a current identity lifecycle refusal.
type IdentityReason string

func (r IdentityReason) Error() string { return string(r) }

// IdentityExpired means the current on-chain name is expired, never live.
const IdentityExpired IdentityReason = "IDENTITY_EXPIRED"
