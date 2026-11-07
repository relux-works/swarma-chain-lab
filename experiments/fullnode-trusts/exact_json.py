"""Bounded JSON numeric transport with no Decimal to binary-float conversion."""
import json
from decimal import Decimal
from money import satoshis, coins

def dumps(value):
    def encode(v, depth=0):
        if depth > 64:
            raise ValueError('JSON depth')
        if v is None or type(v) in (str, bool, int):
            return json.dumps(v, ensure_ascii=True, separators=(',', ':'))
        if isinstance(v, Decimal):
            if not v.is_finite() or len(v.as_tuple().digits) > 32 or abs(v.as_tuple().exponent) > 32:
                raise ValueError('decimal transport bound')
            return format(v, 'f')
        if isinstance(v, (list, tuple)):
            return '[' + ','.join(encode(x, depth+1) for x in v) + ']'
        if isinstance(v, dict) and all(type(k) is str for k in v):
            return '{' + ','.join(json.dumps(k)+':'+encode(x, depth+1) for k,x in sorted(v.items())) + '}'
        raise ValueError('unsupported JSON value; binary floats refused')
    return encode(value)
