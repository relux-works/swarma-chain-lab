package grantcheck

import "github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"

// Exact mappings only. The wrapper never infers a lifecycle transition from
// error text, and unknown future reasons remain a non-retryable refusal.
func mapReceipt(r kernel.Receipt, inbound bool) Verdict {
	code := CodeCheckFailed
	if r.Verdict == kernel.Live {
		if r.Reason == "LIVE" && !r.Closed {
			code = CodeLive
		}
	} else if r.Verdict == kernel.Refused || r.Verdict == kernel.Pending {
		switch r.Reason {
		case "NOT_YET_VALID":
			code = CodeNotYet
		case "EXPIRED":
			code = CodeExpired
		case "SEAL_SPENT":
			code = CodeSealSpent
		case "LANDLORD_KEY_ROTATED":
			code = CodeLandlordRotated
		case "AGENT_LANDLORD_CHANGED":
			code = CodeLandlordChanged
		case "PENDING_LANDLORD_ROTATION", "PENDING_LANDLORD_POINTER", "PENDING_NAME_TRANSITION", "NAME_UNCONFIRMED":
			code = CodeIdentityPending
		case "ISSUANCE_UNCONFIRMED", "SEAL_UNCONFIRMED":
			code = CodeGrantPending
		case "GRANT_POLICY", "GRANTEE_MISMATCH", "SEAL_KEY_BINDING", "AGENT_LANDLORD_MISMATCH", "LANDLORD_KEY_MISMATCH", "UNOBSERVED_ROTATION", "PRIOR_GENERATION_BINDING":
			code = CodeBindingMismatch
		case "PRESENTATION_ID", "ISSUANCE_COMMITMENT", "ISSUANCE_SPENDS_SEAL", "SEAL_BINDING", "SEAL_OUTPUT":
			code = CodeInvalidPresentation
		case "CLOCK_INPUT", "CONSENT_FUTURE":
			code = CodeClockInvalid
		case "NODE_UNAVAILABLE", "RPC_UNAVAILABLE", "RPC_REQUEST", "RPC_RESPONSE", "RPC_REMOTE_ERROR", "NODE_PROJECTION", "TIP_CHANGED", "MEMPOOL_CHANGED", "NAME_CHANGED", "CHAIN_STATE", "GENESIS", "OBSERVATION_BOUND", "OBSERVATION_BYTES", "ACTIVE_BLOCK", "ACTIVE_HEADER", "BLOCK_MEMBERSHIP", "BLOCK_PROJECTION", "BLOCK_TXIDS", "BLOCK_HASH", "TX_CONFIRMATIONS", "RAW_TX_BINDING", "RAW_INPUT_BINDING", "RAW_OUTPUT_BINDING", "MEMPOOL_PROJECTION", "NAME_GENERATION_BINDING":
			code = CodeVerifierUnavailable
		case "PRIVATE_STATE_ROOT", "STATE_OWNER", "STATE_LOCK", "STATE_LOCK_FILE", "STATE_BUSY", "JOURNAL_READ", "JOURNAL_FILE", "JOURNAL_ENCODING", "JOURNAL_WRITE", "JOURNAL_FSYNC", "JOURNAL_COMMIT", "JOURNAL_CORRUPT", "SEAL_INDEX_CORRUPT", "PRESENTATION_CACHE_CORRUPT", "PRESENTATION_CACHE_FULL", "PRESENTATION_ENCODING":
			code = CodeStateUnavailable
		}
	}
	return route(code, inbound, r.Closed)
}
