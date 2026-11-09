module relux.works/swarma-chain-lab/experiments/station-payload

go 1.26.0

require (
	relux.works/swarma-chain-lab/experiments/station-lifecycle v0.0.0
	relux.works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind v0.0.0
)

require (
	golang.org/x/sys v0.47.0 // indirect
	relux.works/swarma-chain-lab/experiments/single-use v0.0.0 // indirect
)

replace relux.works/swarma-chain-lab/experiments/single-use => ../single-use

replace relux.works/swarma-chain-lab/experiments/sealwatch => ../sealwatch

replace relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind => ../rental-gateway/kernelbind

replace relux.works/swarma-chain-lab/experiments/rental => ../rental

replace relux.works/swarma-chain-lab/experiments/rental-booking => ../rental-booking

replace relux.works/swarma-chain-lab/experiments/payment-chain => ../payment-chain

replace relux.works/swarma-chain-lab/experiments/station-lifecycle => ../station-lifecycle

replace relux.works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind => ../station-lifecycle/gatewaybind

replace relux.works/swarma-chain-lab/experiments/model-proxy => ../model-proxy

require (
	relux.works/swarma-chain-lab/experiments/model-proxy v0.0.0
	relux.works/swarma-chain-lab/experiments/rental-gateway v0.0.0
)

replace relux.works/swarma-chain-lab/experiments/rental-gateway => ../rental-gateway
