module github.com/relux-works/swarma-chain-lab/deploy

go 1.26.0

require github.com/relux-works/swarma-chain-lab/experiments/single-use v0.3.1-0.20261115072539-3bbc2d8ab62e

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/relux-works/swarma-chain-lab/experiments/sealwatch v0.2.1-0.20261115072539-3bbc2d8ab62e // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0
)

replace github.com/relux-works/swarma-chain-lab/experiments/single-use => ../experiments/single-use

replace github.com/relux-works/swarma-chain-lab/experiments/sealwatch => ../experiments/sealwatch
