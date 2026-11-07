"""Fixed companion name-operation bounds. Construction never broadcasts.

These mainnet constants apply only to name_firstupdate/name_update. Regtest
requires its own explicit parameters. Source review and exact raw admission
remain external gates; a constant supplies neither execution authority.
"""
from decimal import Decimal
from transaction import build_signed

MAINNET_COMPANION_NAME_VSIZE_CAP = 1024
MAINNET_COMPANION_NAME_RATE_SAT_VB = 200
MAINNET_COMPANION_NAME_FEE_CAP_SAT = 204800

def build_companion_name_signed(rpc, check_network, role, inputs, outputs, *,
                                name_op, regtest_vsize_cap, regtest_fee_cap_sat):
    if not isinstance(name_op, dict) or name_op.get('op') not in ('name_firstupdate', 'name_update'):
        raise ValueError('companion final name operation required')
    chain = check_network()['chain']
    if chain == 'main':
        cap, fee = MAINNET_COMPANION_NAME_VSIZE_CAP, MAINNET_COMPANION_NAME_FEE_CAP_SAT
    elif chain == 'regtest':
        cap, fee = regtest_vsize_cap, regtest_fee_cap_sat
        if type(cap) is not int or type(fee) is not int or not 1 <= cap <= 1024 or not 1 <= fee <= 204800:
            raise ValueError('explicit bounded regtest parameters required')
    else:
        raise ValueError('unsupported chain')
    return build_signed(rpc, check_network, role, inputs, outputs,
                        rate_sat_vb=MAINNET_COMPANION_NAME_RATE_SAT_VB,
                        vsize_cap=cap, fee_cap=Decimal(fee)/100000000,
                        name_op=name_op)
