package main

import "relux.works/swarma-chain-lab/experiments/rental-gateway/presentationdir"

// Keep the command and integration tests on the same read-only source.
type presentationDirectory = presentationdir.Directory

var errPresentation = presentationdir.ErrSource

func openPresentations(path string) (*presentationDirectory, error) {
	return presentationdir.Open(path)
}
