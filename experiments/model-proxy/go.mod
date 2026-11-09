module relux.works/swarma-chain-lab/experiments/model-proxy

go 1.26.0

require (
	golang.org/x/sys v0.47.0
	relux.works/swarma-chain-lab/experiments/single-use v0.0.0
)

replace relux.works/swarma-chain-lab/experiments/single-use => ../single-use

replace relux.works/swarma-chain-lab/experiments/sealwatch => ../sealwatch
