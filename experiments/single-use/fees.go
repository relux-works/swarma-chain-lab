package singleuse

// ReserveLegacyFee uses an already bounded worst-case signed transaction.
// The last output is its zero-valued change placeholder. Values are integer
// atoms; the returned fee reserves 200 sat/vB and at least 1000 sat change.
func ReserveLegacyFee(tx Transaction, total int64) (size int, fee, change int64, err error) {
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 || tx.Outputs[len(tx.Outputs)-1].Value != 0 || total < 0 || total > 21000000*100000000 {
		return 0, 0, 0, fail("FUNDING_INPUT")
	}
	size = len(tx.Bytes())
	if size > 4096 {
		return 0, 0, 0, fail("PLAN_SIZE_BOUND")
	}
	fee = int64(size) * 200
	var outputs int64
	for _, out := range tx.Outputs {
		if out.Value < 0 || out.Value > 21000000*100000000-outputs {
			return 0, 0, 0, fail("OUTPUT_VALUE")
		}
		outputs += out.Value
	}
	change = total - outputs - fee
	if change < 1000 {
		return 0, 0, 0, fail("FUNDING_OR_DUST_RESERVE")
	}
	return size, fee, change, nil
}
