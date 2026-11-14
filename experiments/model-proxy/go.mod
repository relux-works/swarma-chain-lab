module github.com/relux-works/swarma-chain-lab/experiments/model-proxy

go 1.26.0

require (
	github.com/relux-works/swarma-chain-lab/experiments/single-use v0.3.1-0.20261114144010-ffefc6d423ae
	golang.org/x/sys v0.47.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/relux-works/swarma-chain-lab/experiments/sealwatch v0.2.1-0.20261114144010-ffefc6d423ae // indirect
	golang.org/x/crypto v0.55.0 // indirect
)

replace github.com/relux-works/swarma-chain-lab/experiments/single-use => ../single-use

replace github.com/relux-works/swarma-chain-lab/experiments/sealwatch => ../sealwatch
