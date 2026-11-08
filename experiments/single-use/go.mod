module relux.works/swarma-chain-lab/experiments/single-use

go 1.26.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	golang.org/x/crypto v0.55.0
	relux.works/swarma-chain-lab/experiments/sealwatch v0.0.0
)

replace relux.works/swarma-chain-lab/experiments/sealwatch => ../sealwatch
