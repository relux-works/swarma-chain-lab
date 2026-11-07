"""Shared T1 transaction construction, with explicit source-bound ceilings.

The caller supplies network checking and the existing wallet RPC capability.
This helper never broadcasts and has no mainnet admission switch.
"""
from decimal import Decimal


def build_signed(rpc, check_network, role, inputs, outputs, *, rate_sat_vb,
                 vsize_cap, fee_cap, name_op=None):
    check_network()
    raw = rpc('createrawtransaction', inputs, outputs)
    if name_op:
        raw = rpc('namerawtransaction', raw, 0, name_op)['hex']
    funded = rpc('fundrawtransaction', raw,
                 {'fee_rate': rate_sat_vb, 'lockUnspents': False}, wallet=role)
    if funded['fee'] > fee_cap:
        raise RuntimeError('funded fee exceeds cap before signing')
    signed = rpc('signrawtransactionwithwallet', funded['hex'], wallet=role)
    if not signed['complete']:
        raise RuntimeError('incomplete signature')
    decoded = rpc('decoderawtransaction', signed['hex'])
    if decoded['vsize'] > vsize_cap:
        raise RuntimeError('signed size exceeds ceiling before broadcast')
    fee = sum(Decimal(str(rpc('getrawtransaction', v['txid'], True)['vout'][v['vout']]['value']))
              for v in decoded['vin']) - sum(Decimal(str(v['value'])) for v in decoded['vout'])
    if fee > fee_cap or fee < 0:
        raise RuntimeError('signed fee exceeds cap before broadcast')
    accepted = rpc('testmempoolaccept', [signed['hex']])[0]
    if not accepted['allowed']:
        raise RuntimeError('transaction not relayable; stop without replacement')
    return signed['hex']
