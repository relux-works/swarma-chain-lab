module github.com/relux-works/swarma-chain-lab/experiments/grant-v4/vectors

go 1.26.10

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire v0.0.0-20261115082735-f1936aa1117a
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
)

replace github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire => ../wire
