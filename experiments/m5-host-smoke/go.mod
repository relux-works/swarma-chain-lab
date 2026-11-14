module github.com/relux-works/swarma-chain-lab/experiments/m5-host-smoke

go 1.26.0

require (
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/relux-works/swarma-chain-lab/experiments/rental v0.5.1-0.20261114144010-ffefc6d423ae
	github.com/relux-works/swarma-chain-lab/experiments/single-use v0.3.1-0.20261114144010-ffefc6d423ae
)

require (
	github.com/gorilla/websocket v1.5.3 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/relux-works/swarma-chain-lab/experiments/payment-chain v0.2.1-0.20261114144010-ffefc6d423ae
	github.com/relux-works/swarma-chain-lab/experiments/rental-booking v0.4.1-0.20261114144010-ffefc6d423ae
	github.com/relux-works/swarma-chain-lab/experiments/rental-gateway v0.4.1-0.20261114144010-ffefc6d423ae
	github.com/relux-works/swarma-chain-lab/experiments/sealwatch v0.2.1-0.20261114144010-ffefc6d423ae // indirect
	golang.org/x/crypto v0.55.0 // indirect
)

replace github.com/relux-works/swarma-chain-lab/experiments/rental => ../rental

replace github.com/relux-works/swarma-chain-lab/experiments/single-use => ../single-use

replace github.com/relux-works/swarma-chain-lab/experiments/sealwatch => ../sealwatch

replace github.com/relux-works/swarma-chain-lab/experiments/grant-store => ../grant-store

replace github.com/relux-works/swarma-chain-lab/experiments/rental-gateway => ../rental-gateway

replace github.com/relux-works/swarma-chain-lab/experiments/payment-chain => ../payment-chain

replace github.com/relux-works/swarma-chain-lab/experiments/rental-booking => ../rental-booking

replace github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind => ../rental-gateway/kernelbind

replace github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle => ../station-lifecycle

replace github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind => ../station-lifecycle/gatewaybind

replace github.com/relux-works/swarma-chain-lab/experiments/signer-service => ../signer-service

replace github.com/relux-works/swarma-chain-lab/experiments/model-proxy => ../model-proxy

replace github.com/relux-works/swarma-chain-lab/experiments/station-payload => ../station-payload
