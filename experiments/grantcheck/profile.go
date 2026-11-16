package grantcheck

import (
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Contract profiles. The caller selects one in Config.ContractProfile; the
// checker never detects a profile from the contract bytes, and a grant whose
// contract belongs to the other profile is refused as terms_invalid.
const (
	// ContractProfilePay is the pay construction: the contract is a canonical
	// rental.PayTermsV2 document. An empty Config.ContractProfile selects it,
	// as before this constant existed.
	ContractProfilePay = "pay"
	// ContractProfileTrust is the trust construction: the contract is a
	// swarma-trust-contract/1 document (LIP-0013 section 2) or a root
	// swarma-trust-contract/2 document at depth 0 (LIP-0014 section 3.1).
	ContractProfileTrust = "trust"
)

// MainGenesis is the hash of the Namecoin mainnet genesis block. Source:
// Namecoin Core, src/kernel/chainparams.cpp (src/chainparams.cpp in older
// releases), class CMainParams:
//
//	assert(consensus.hashGenesisBlock == uint256{"000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"});
//
// TestMainGenesisLiteral checks this constant against the literal hash and
// against the constant the rental kernel pins.
const MainGenesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"

// pinnedNetwork admits exactly the two network and genesis pairs. Neither
// value is derived from the other and there is no default pair.
func pinnedNetwork(network, genesis string) bool {
	return (network == "regtest" && genesis == su.RegtestGenesis) || (network == "main" && genesis == MainGenesis)
}

// resolveBinding returns the contract profile and the network binding of a
// configuration. The trust profile has no default: Network and Genesis must
// both be set to one admitted pair. The pay profile keeps its earlier fixed
// regtest pin when both are absent, so existing pay configurations construct
// the same checker with the same durable binding; when either is set, the
// pair must be an admitted one.
func resolveBinding(config Config) (profile, network, genesis string, ok bool) {
	switch config.ContractProfile {
	case "", ContractProfilePay:
		if config.Network == "" && config.Genesis == "" {
			return ContractProfilePay, "regtest", su.RegtestGenesis, true
		}
		profile = ContractProfilePay
	case ContractProfileTrust:
		profile = ContractProfileTrust
	default:
		return "", "", "", false
	}
	if !pinnedNetwork(config.Network, config.Genesis) {
		return "", "", "", false
	}
	return profile, config.Network, config.Genesis, true
}
