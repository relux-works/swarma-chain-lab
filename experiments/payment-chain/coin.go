package paymentchain

// Coin is the adapter's closed string vocabulary. A cast does not validate it;
// parse external input with ParseCoin or call Validate before using a value.
// Signed Terms retain the same JSON string representation.
type Coin string

const (
	CoinNMC Coin = "nmc"
	CoinBTC Coin = "btc"
	CoinLTC Coin = "ltc"
)

func ParseCoin(raw string) (Coin, error) {
	c := Coin(raw)
	if err := c.Validate(); err != nil {
		return "", err
	}
	return c, nil
}

func (c Coin) Validate() error {
	switch c {
	case CoinNMC, CoinBTC, CoinLTC:
		return nil
	default:
		return refuse("COIN_PROFILE")
	}
}

func (c Coin) Profile() (Profile, error) { return ForCoin(string(c)) }
