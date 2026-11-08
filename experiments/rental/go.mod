module relux.works/swarma-chain-lab/experiments/rental

go 1.26.0

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	relux.works/swarma-chain-lab/experiments/single-use v0.0.0
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	relux.works/swarma-chain-lab/experiments/sealwatch v0.0.0 // indirect
)

replace relux.works/swarma-chain-lab/experiments/sealwatch => ../sealwatch

replace relux.works/swarma-chain-lab/experiments/single-use => ../single-use
