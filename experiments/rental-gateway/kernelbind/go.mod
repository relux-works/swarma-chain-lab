module relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind

go 1.26.0

require (
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil v1.1.5
	relux.works/swarma-chain-lab/experiments/rental v0.0.0
	relux.works/swarma-chain-lab/experiments/rental-gateway v0.0.0
	relux.works/swarma-chain-lab/experiments/single-use v0.0.0
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	relux.works/swarma-chain-lab/experiments/payment-chain v0.0.0 // indirect
	relux.works/swarma-chain-lab/experiments/rental-booking v0.0.0
	relux.works/swarma-chain-lab/experiments/sealwatch v0.0.0 // indirect
)

// In-tree siblings: the landed detached kernel and its stack.
replace relux.works/swarma-chain-lab/experiments/rental => ../../rental

replace relux.works/swarma-chain-lab/experiments/single-use => ../../single-use

replace relux.works/swarma-chain-lab/experiments/sealwatch => ../../sealwatch

replace relux.works/swarma-chain-lab/experiments/rental-gateway => ../

replace relux.works/swarma-chain-lab/experiments/payment-chain => ../../payment-chain

replace relux.works/swarma-chain-lab/experiments/rental-booking => ../../rental-booking

replace relux.works/swarma-chain-lab/experiments/station-lifecycle => ../../station-lifecycle

replace relux.works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind => ../../station-lifecycle/gatewaybind

replace relux.works/swarma-chain-lab/experiments/model-proxy => ../../model-proxy
