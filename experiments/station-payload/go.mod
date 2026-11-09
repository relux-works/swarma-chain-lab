module github.com/relux-works/swarma-chain-lab/experiments/station-payload

go 1.26.0

require (
	github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle v0.1.0
	github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind v0.1.0
)

require (
	github.com/relux-works/swarma-chain-lab/experiments/single-use v0.1.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/relux-works/swarma-chain-lab/experiments/single-use => ../single-use

replace github.com/relux-works/swarma-chain-lab/experiments/sealwatch => ../sealwatch

replace github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind => ../rental-gateway/kernelbind

replace github.com/relux-works/swarma-chain-lab/experiments/rental => ../rental

replace github.com/relux-works/swarma-chain-lab/experiments/rental-booking => ../rental-booking

replace github.com/relux-works/swarma-chain-lab/experiments/payment-chain => ../payment-chain

replace github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle => ../station-lifecycle

replace github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind => ../station-lifecycle/gatewaybind

replace github.com/relux-works/swarma-chain-lab/experiments/model-proxy => ../model-proxy

require (
	github.com/relux-works/swarma-chain-lab/experiments/model-proxy v0.1.0
	github.com/relux-works/swarma-chain-lab/experiments/rental-gateway v0.1.0
)

replace github.com/relux-works/swarma-chain-lab/experiments/rental-gateway => ../rental-gateway
