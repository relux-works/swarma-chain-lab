# Supported boundaries and remaining acceptance

The v2 wire, global booking calendar and independently routed grant issuer are
implemented. Independent review and signed delivery remain acceptance steps;
unit or observer tests alone do not establish the complete workflow.

Pinned Litecoin Core 0.21.5.8 supports BIP125-signalling replacement only, with
mempoolreplacement=1 explicitly enabled. Its non-signalling full-RBF limitation
is accepted for this laboratory scope; no patched/substitute daemon is used.
The integration matrix also covers a miner directly including a conflicting
non-signalling transaction, so the original pending payment cannot issue.
BTC/NMC have separate non-signalling full-RBF controls.
Upstream policy: https://github.com/litecoin-project/litecoin/blob/v0.21.5.8/src/validation.cpp#L591-L616

Pruning is enabled with txindex disabled on payment nodes. The small laboratory
chains do not establish availability of already-pruned historical block files;
missing required history must refuse. Pure MWEB serialization is outside the
closed transparent P2WPKH payment profile; unrelated witness/many-input traffic
is exercised, but this is not an exhaustive MWEB validation claim.

Protocol upgrades require a profile change and revalidation. The product/
protocol response is a routing diagnostic, not remote attestation. Production
migration, new mainnet profiles, wallet custody and spending remain outside this
regtest-only module. New v2 roots require new/reserved public branches under the
operator's custody policy; deleting a ledger cannot safely reset its indices.
