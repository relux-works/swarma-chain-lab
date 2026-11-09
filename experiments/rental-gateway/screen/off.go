package screen

import "context"

// Off explicitly disables content screening. It never bypasses the gateway's
// prior live-kernel admission. It must be disclosed by the runtime selecting it.
// A future model proxy implements Screener in place of Off.
type Off struct{}

func (Off) Screen(ctx context.Context, _ string) (Decision, error) {
	if e := ctx.Err(); e != nil {
		return Decision{}, e
	}
	return Decision{Allow: true}, nil
}
