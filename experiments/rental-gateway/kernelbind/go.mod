module relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind

go 1.26.0

require (
	relux.works/swarma-chain-lab/experiments/rental v0.0.0
	relux.works/swarma-chain-lab/experiments/rental-gateway v0.0.0
	relux.works/swarma-chain-lab/experiments/sealwatch v0.0.0
	relux.works/swarma-chain-lab/experiments/single-use v0.0.0
)

// Bound when M1 lands at ../../rental; until then this nested module
// intentionally does not resolve, and the gateway uses kernel.Stub.
replace relux.works/swarma-chain-lab/experiments/rental => ../../rental

replace relux.works/swarma-chain-lab/experiments/single-use => ../../single-use

replace relux.works/swarma-chain-lab/experiments/sealwatch => ../../sealwatch

replace relux.works/swarma-chain-lab/experiments/rental-gateway => ../
