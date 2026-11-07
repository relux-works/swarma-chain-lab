"""Shared T1 transaction construction, with explicit source-bound ceilings.

The caller supplies network checking and the existing wallet RPC capability.
This helper never broadcasts and has no mainnet admission switch.
"""
from decimal import Decimal
from exact_json import satoshis


def build_signed(rpc, check_network, role, inputs, outputs, *, rate_sat_vb,
                 vsize_cap, fee_cap, name_op=None):
    if type(rate_sat_vb) is not int or rate_sat_vb <= 0 or type(vsize_cap) is not int or vsize_cap <= 0:
        raise ValueError('integer fee configuration required')
    cap_sat = satoshis(fee_cap)
    check_network()
    raw = rpc('createrawtransaction', inputs, outputs)
    if name_op:
        raw = rpc('namerawtransaction', raw, 0, name_op)['hex']
    funded = rpc('fundrawtransaction', raw,
                 {'fee_rate': rate_sat_vb, 'lockUnspents': False}, wallet=role)
    if satoshis(funded['fee']) > cap_sat:
        raise RuntimeError('funded fee exceeds cap before signing')
    signed = rpc('signrawtransactionwithwallet', funded['hex'], wallet=role)
    if not signed['complete']:
        raise RuntimeError('incomplete signature')
    decoded = rpc('decoderawtransaction', signed['hex'])
    if decoded['vsize'] > vsize_cap:
        raise RuntimeError('signed size exceeds ceiling before broadcast')
    fee_sat = sum(satoshis(rpc('getrawtransaction', v['txid'], True)['vout'][v['vout']]['value'])
                  for v in decoded['vin']) - sum(satoshis(v['value']) for v in decoded['vout'])
    if fee_sat > cap_sat or fee_sat < 0:
        raise RuntimeError('signed fee exceeds cap before broadcast')
    accepted = rpc('testmempoolaccept', [signed['hex']])[0]
    if not accepted['allowed']:
        raise RuntimeError('transaction not relayable; stop without replacement')
    return signed['hex']
