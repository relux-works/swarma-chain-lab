module relux.works/swarma-chain-lab/experiments/rental-booking

go 1.26.0

require (
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcutil v1.1.5
)

require github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/gorilla/websocket v1.5.3
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	relux.works/swarma-chain-lab/experiments/sealwatch v0.0.0
	relux.works/swarma-chain-lab/experiments/single-use v0.0.0
)

replace relux.works/swarma-chain-lab/experiments/single-use => ../single-use

replace relux.works/swarma-chain-lab/experiments/sealwatch => ../sealwatch
