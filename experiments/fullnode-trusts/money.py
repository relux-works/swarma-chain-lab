"""Consensus-bounded, context-independent monetary conversion.

Namecoin Core nc28.0, a08218ef2d44b81c53d25c399898e59271f4b642,
src/consensus/amount.h: COIN=100000000, MAX_MONEY=21000000*COIN.
This sanity bound changes no operation-specific fee or allocation cap.
"""
from decimal import Decimal, InvalidOperation

MAX_MONEY_SAT = 21000000 * 100000000
_MAX_MONEY_DIGITS = tuple(map(int, str(MAX_MONEY_SAT)))


def satoshis(value):
    """Bound the adjusted exponent before accumulating digits or powers.

    Decimal tuples retain exact trailing-zero representations without making
    a giant integer coefficient. Binary floats and unknown inputs fail closed.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValueError('exact monetary value required')
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        raise ValueError('invalid monetary value') from None
    if not amount.is_finite() or amount < 0:
        raise ValueError('invalid monetary value')
    _, digits, exponent = amount.as_tuple()
    if not any(digits):
        return 0
    exponent += 8
    integer_digits = len(digits) + exponent
    if integer_digits > len(_MAX_MONEY_DIGITS):
        raise ValueError('monetary value exceeds MAX_MONEY')
    if integer_digits == len(_MAX_MONEY_DIGITS):
        prefix = digits[:integer_digits] + (0,) * max(0, exponent)
        if prefix > _MAX_MONEY_DIGITS:
            raise ValueError('monetary value exceeds MAX_MONEY')
    end = len(digits)
    if exponent < 0:
        end += exponent
        if end <= 0 or any(digits[i] for i in range(end, len(digits))):
            raise ValueError('nonintegral monetary value')
        exponent = 0
    coefficient = 0
    for i in range(end):
        coefficient = coefficient * 10 + digits[i]
    return coefficient * 10 ** exponent


def coins(value_sat):
    """Construct an exact NMC Decimal without context-sensitive arithmetic."""
    if type(value_sat) is not int or not 0 <= value_sat <= MAX_MONEY_SAT:
        raise ValueError('integer satoshis within MAX_MONEY required')
    return Decimal(str(value_sat) + 'e-8')


def total_satoshis(values):
    total = 0
    for value in values:
        total += satoshis(value)
        if total > MAX_MONEY_SAT:
            raise ValueError('monetary total exceeds MAX_MONEY')
    return total


def validate_outputs(outputs):
    if not isinstance(outputs, (list, tuple)):
        raise ValueError('output sequence required')
    amounts = []
    for output in outputs:
        if not isinstance(output, dict) or len(output) != 1:
            raise ValueError('output schema')
        address, value = next(iter(output.items()))
        if not isinstance(address, str) or not address:
            raise ValueError('output address')
        if address == 'data':
            if not isinstance(value, str):
                raise ValueError('data output schema')
        else:
            amounts.append(value)
    return total_satoshis(amounts)
