#!/usr/bin/env python3
"""Offline T1b manifest and synthetic serialization controls; no RPC or keys.

Importing this module starts nothing. The only RPC implementation in this file
is an in-memory test double. Its policy result is NOT a node observation.
"""
import argparse
import hashlib
import json
from decimal import Decimal
from pathlib import Path
from protocol import canon
from transaction import build_signed
from funding import funding_model, T1_FEE_CAPS

SIZES = (80, 100, 200, 520, 1000, 4000, 10000)
RATE_SAT_VB = 200  # fixed reviewed source rate, never an estimator/inclusion quote
STEP_BUDGET_S = 1500  # 60 preparation + 120 relay + 1320 inclusion
SERIES_CAP_S = 7 * STEP_BUDGET_S
T1_CAP_S = 21600
VSIZE_CAPS = {n: n + 220 for n in SIZES}
SAT = Decimal(100000000)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(n):
    if n < 253:
        return bytes([n])
    return b'\xfd' + n.to_bytes(2, 'little')


def payload(n):
    if n not in SIZES:
        raise ValueError('unreviewed payload length')
    # Deliberately synthetic ASCII; exact bytes are emitted, no grants/contact.
    return (b'SYNTHETIC-T1B-OPRETURN-ONLY|' * ((n + 25) // 26))[:n]


def script(data):
    n = len(data)
    prefix = b'\x4c' + bytes([n]) if n <= 255 else b'\x4d' + n.to_bytes(2, 'little')
    return b'\x6a' + prefix + data


def serialize(data, fee_sat):
    """Unspendable legacy sizing fixture, NOT a signed/broadcastable tx.

    Zero prevout, placeholder 107-byte scriptSig, zero-hash P2PKH change script.
    No wallet, address or private/public signing key exists.
    """
    change = 10000000 - fee_sat
    opret = script(data)
    vin = b'\0' * 32 + b'\0' * 4 + compact(107) + b'\0' * 107 + b'\xff' * 4
    change_script = b'\x76\xa9\x14' + b'\0' * 20 + b'\x88\xac'
    output = b'\0' * 8 + compact(len(opret)) + opret
    output += change.to_bytes(8, 'little') + compact(25) + change_script
    return b'\x01\0\0\0\x01' + vin + b'\x02' + output + b'\0' * 4


class SyntheticRPC:
    """Only construction-call controls; never opens a socket or signs bytes."""
    def __init__(self, data, *, allowed=True):
        self.data, self.allowed, self.calls = data, allowed, []
        self.fee_sat = len(serialize(data, 0)) * RATE_SAT_VB
        self.raw = serialize(data, self.fee_sat).hex()

    def __call__(self, method, *params, wallet=''):
        self.calls.append(method)
        if method == 'createrawtransaction':
            if params != ([], [{'data': self.data.hex()}]):
                raise ValueError('unexpected synthetic construction input')
            return self.raw
        if method == 'fundrawtransaction':
            if params[1] != {'fee_rate': RATE_SAT_VB, 'lockUnspents': False}:
                raise ValueError('changed funding abstraction')
            return {'hex': self.raw, 'fee': Decimal(self.fee_sat) / SAT}
        if method == 'signrawtransactionwithwallet':
            return {'hex': self.raw, 'complete': True}  # test double, no signature
        if method == 'decoderawtransaction':
            return {'vsize': len(bytes.fromhex(self.raw)),
                    'vin': [{'txid': '00' * 32, 'vout': 0}],
                    'vout': [{'value': 0}, {'value': Decimal(10000000 - self.fee_sat) / SAT}]}
        if method == 'getrawtransaction':
            return {'vout': [{'value': Decimal('0.10000000')}]}
        if method == 'testmempoolaccept':
            return [{'allowed': self.allowed, 'reject-reason': 'SYNTHETIC_CONTROL'}]
        raise ValueError('unsupported synthetic RPC')


def construct_fixture(n):
    rpc = SyntheticRPC(payload(n))
    raw = build_signed(rpc, lambda: None, 'synthetic', [], [{'data': payload(n).hex()}],
                       rate_sat_vb=RATE_SAT_VB, vsize_cap=VSIZE_CAPS[n],
                       fee_cap=Decimal(VSIZE_CAPS[n] * RATE_SAT_VB) / SAT)
    return bytes.fromhex(raw), rpc


def budget():
    t1 = sum(T1_FEE_CAPS.values())  # existing ten operations, not bootstrap
    t1b = sum(VSIZE_CAPS.values()) * RATE_SAT_VB
    transfer = 230 * RATE_SAT_VB  # bounded funder's fee, now inside total
    fees = t1 + t1b + transfer
    margin = (fees + 9) // 10
    model = funding_model((VSIZE_CAPS[n] * RATE_SAT_VB for n in SIZES),
                          final_reserve_sat=100000, funder_fee_cap_sat=transfer)
    total = model['all_in_required_sat']
    # Render exact satoshis without consulting the caller's Decimal context.
    whole, fraction = divmod(abs(total), 100000000)
    total_nmc = f'{"-" if total < 0 else ""}{whole}.{fraction:08d}'
    return {'unit': 'satoshi_of_NMC', 'assumed_sat_per_vbyte': RATE_SAT_VB,
            'live_estimator_quote': None, 't1_operations': 10, 't1_fee_caps_sat': t1,
            't1b_max_operations': 7, 't1b_vsize_caps': VSIZE_CAPS,
            't1b_fee_caps_sat': t1b, 'funding_transfer_vsize_cap': 230,
            'funding_transfer_fee_cap_sat': transfer, 'all_fee_caps_sat': fees,
            'fee_margin_percent': 10, 'fee_margin_sat': margin,
            'two_names_locked_sat': 2000000, 'two_seals_initially_locked_sat': 200000,
            'final_live_seal_sat': 100000, 'revoked_seal_fee_sat': 50000,
            'revoked_seal_returned_change_sat': 50000,
            'spendable_change_reserve_sat': 100000,
            'cashflow_model': model,
            'recipient_required_sat': model['recipient_required_sat'],
            'all_in_required_sat': total, 'all_in_required_nmc': total_nmc,
            'owner_cap_sat': 100000000, 'headroom_sat': 100000000 - total,
            'status': 'CONDITIONAL_MODEL_NOT_ACTUAL_ESTIMATE',
            'funding_policy': 'new experimental address funded by owner; request recomputed minimum, never fill cap'}


def outcome(row):
    """Pure future observation reducer. Unknown observations never advance.

    Inputs must be bound by the future collector to the exact raw transaction,
    payload, receipt hashes and monotonic times. This is not that collector.
    """
    if row.get('reorg') is True:
        return 'STOP_REORG'
    if row.get('reorg') is not False:
        return 'STOP_REORG_UNKNOWN'
    elapsed = row.get('elapsed_s')
    if type(elapsed) not in (int, float) or not 0 <= elapsed <= STEP_BUDGET_S:
        return 'STOP_STEP_BUDGET'
    def bounded(key, cap):
        value = row.get(key)
        return type(value) in (int, float) and 0 <= value <= cap
    if not bounded('series_elapsed_s', SERIES_CAP_S):
        return 'STOP_SERIES_BUDGET'
    if not bounded('t1_elapsed_s', T1_CAP_S):
        return 'STOP_T1_SIX_HOUR_CAP'
    if not all(bounded(key, cap) for key, cap in
               (('preparation_elapsed_s', 60), ('relay_elapsed_s', 120), ('inclusion_wait_s', 1320))):
        return 'STOP_PHASE_BUDGET_OR_UNKNOWN'
    if row.get('local_allowed') is False:
        return 'STOP_LOCAL_POLICY_REFUSAL'
    if row.get('local_allowed') is not True:
        return 'STOP_LOCAL_POLICY_UNKNOWN'
    if row.get('peer_status') == 'refused':
        return 'STOP_PEER_RELAY_REFUSAL'
    if row.get('peer_status') != 'observed' or not row.get('peer_receipt_sha256'):
        return 'STOP_PEER_RELAY_UNKNOWN'
    if not row.get('inclusion'):
        return 'STOP_NOT_MINED_WITHIN_WAIT'
    inc = row['inclusion']
    required = ('block_hash', 'height', 'header_time_utc', 'observed_at_utc',
                'active_chain_receipt_sha256', 'tx_in_block_receipt_sha256')
    if any(inc.get(k) is None for k in required):
        return 'STOP_INCLUSION_EVIDENCE_MISSING'
    return 'ADVANCE'


def observation_template(n):
    return {'payload_bytes': n, 'payload_sha256': sha(payload(n)),
        'script_bytes': len(script(payload(n))), 'script_sha256': sha(script(payload(n))),
        'source_head': None, 'source_tree': None, 'manifest_sha256': None,
        'meta_marker_receipt_sha256': None, 'independent_review_receipt_sha256': None,
        'spend_go_receipt_sha256': None, 'runtime_admission_receipt_sha256': None,
        'network_genesis': None, 'core_version': None, 'tip_height': None, 'tip_hash': None,
        'policy_snapshot_at_utc': None, 'policy_receipt_sha256': None,
        'estimator_reply_or_error': None, 'signed_raw_sha256': None,
        'mainnet_txid': None, 'signed_vsize': None, 'signed_weight': None,
        'actual_fee_sat': None, 'actual_fee_rate_sat_vb': None,
        'local_allowed': None, 'local_reject_reason': None,
        'local_testmempoolaccept_receipt_sha256': None,
        'broadcast_at_utc': None, 'broadcast_monotonic_ns': None,
        'broadcast_rpc_receipt_sha256': None, 'local_mempool_seen_at_utc': None,
        'peer_status': 'unknown', 'peer_observer_label': None,
        'peer_seen_at_utc': None, 'peer_evidence_kind': None,
        'peer_receipt_sha256': None, 'peer_refusal_reason': None,
        'inclusion': None, 'miner_data': {'coinbase_auxpow_receipt_sha256': None,
            'attribution': 'UNKNOWN', 'limitation': 'labels are not authenticated miner identity'},
        'elapsed_s': None, 'series_elapsed_s': None, 't1_elapsed_s': None,
        'preparation_elapsed_s': None, 'relay_elapsed_s': None, 'inclusion_wait_s': None,
        'reorg': None, 'timeout': None, 'refusal': None, 'rpc_error': None,
        'started_at_utc': None, 'finished_at_utc': None, 'actual_exit': None,
        'status': 'NOT_RUN', 'raw_receipt_bytes_total': 0}


def advance(completed):
    """Only a contiguous successful prefix permits the next size; no retry."""
    if len(completed) > len(SIZES):
        raise ValueError('too many series steps')
    for n, row in zip(SIZES, completed):
        if row.get('payload_bytes') != n:
            raise ValueError('noncontiguous series')
        if outcome(row) != 'ADVANCE':
            return None
    return SIZES[len(completed)] if len(completed) < len(SIZES) else None


def manifest(out):
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    rows = []
    for n in SIZES:
        data, opret = payload(n), script(payload(n))
        raw, rpc = construct_fixture(n)
        stem = f'payload-{n}'
        for suffix, content in (('.bin', data), ('.script', opret), ('.synthetic-tx', raw)):
            with (out / (stem + suffix)).open('xb') as f:
                f.write(content)
        rows.append({'payload_bytes': len(data), 'payload_file': stem + '.bin',
            'payload_sha256': sha(data), 'script_bytes': len(opret), 'script_hex': opret.hex(),
            'script_sha256': sha(opret), 'serialized_output_bytes': 8 + len(compact(len(opret))) + len(opret),
            'synthetic_tx_file': stem + '.synthetic-tx', 'synthetic_tx_sha256': sha(raw),
            'synthetic_tx_vsize': len(raw), 'synthetic_fee_sat': rpc.fee_sat,
            'vsize_cap': VSIZE_CAPS[n], 'fee_cap_sat': VSIZE_CAPS[n] * RATE_SAT_VB,
            'shared_builder_rpc_call_control': rpc.calls,
            'local_testmempoolaccept': 'NOT_RUN', 'peer_acceptance': 'UNKNOWN_NOT_RUN',
            'mainnet_txid': None, 'block_inclusion': None, 'miner_identity': None,
            'actual_fee': None, 'reorg': None, 'timeout': None,
            'status': 'OFFLINE_SYNTHETIC_SERIALIZATION_ONLY'})
    doc = {'format': 't1b-synthetic-payload-manifest-v1', 'grant_format': None,
           'broadcast_authorized': False, 'step_budget_s': STEP_BUDGET_S,
           'series_cap_s': SERIES_CAP_S, 'shared_t1_cap_s': T1_CAP_S,
           'budget': budget(), 'payloads': rows}
    (out / 'payload-manifest.json').write_bytes(canon(doc) + b'\n')
    (out / 'budget.json').write_bytes(canon(budget()) + b'\n')
    (out / 'observation-templates.json').write_bytes(canon([observation_template(n) for n in SIZES]) + b'\n')
    return doc


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute():
        parser.error('absolute private output directory required')
    doc = manifest(args.output)
    print(json.dumps({'status': 'OFFLINE_ONLY', 'payloads': len(doc['payloads']),
                      'budget_nmc': doc['budget']['all_in_required_nmc']}))
