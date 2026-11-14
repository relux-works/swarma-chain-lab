module github.com/relux-works/swarma-chain-lab/experiments/single-use

go 1.26.0

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/relux-works/swarma-chain-lab/experiments/sealwatch v0.2.1-0.20261114144010-ffefc6d423ae
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
)

replace github.com/relux-works/swarma-chain-lab/experiments/sealwatch => ../sealwatch
