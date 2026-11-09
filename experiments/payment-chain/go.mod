module github.com/relux-works/swarma-chain-lab/experiments/payment-chain

go 1.26.0

require (
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcutil v1.1.5
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/relux-works/swarma-chain-lab/experiments/sealwatch v0.1.0
	github.com/relux-works/swarma-chain-lab/experiments/single-use v0.1.0
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/relux-works/swarma-chain-lab/experiments/single-use => ../single-use

replace github.com/relux-works/swarma-chain-lab/experiments/sealwatch => ../sealwatch
