package chainview

// CheckDepth takes the evidence class's signed minimum and operator floor as
// inputs, never classifies evidence or converts depth between chains. Missing
// blockHeight means pending. The subtraction avoids H-h+1 overflow at MaxInt64.
func CheckDepth(chain, evidenceChain string, tipHeight int64, blockHeight *int64, signedMinimum, operatorFloor int64) Code {
	if chain == "" || chain != evidenceChain || blockHeight == nil ||
		*blockHeight < 0 || *blockHeight > tipHeight || signedMinimum < 0 || operatorFloor < 0 {
		return Confirmations
	}
	minimum := max(signedMinimum, operatorFloor)
	if minimum > 0 && tipHeight-*blockHeight < minimum-1 {
		return Confirmations
	}
	return ""
}
