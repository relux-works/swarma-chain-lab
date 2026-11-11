module github.com/relux-works/swarma-chain-lab/experiments/single-use

go 1.26.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/relux-works/swarma-chain-lab/experiments/sealwatch v0.2.1-0.20261111181054-288d63e191fe
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
)

replace github.com/relux-works/swarma-chain-lab/experiments/sealwatch => ../sealwatch
