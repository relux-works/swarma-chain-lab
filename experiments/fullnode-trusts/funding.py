"""Pure satoshi accounting for the fixed T1 order; no transport or live quote.

Cash is reusable only after the preceding operation is confirmed and its change
is selectable. Names retain the same principal through firstupdate and anchor.
The fixed B transfer has no return path. This models value, not dust policy,
input selection, signatures, relay or the availability of a fresh fee estimate.
"""

RATE_SAT_VB = 200
ROLE_B_FUNDING_SAT = 1436600
NAME_LOCK_SAT = 1000000
SEAL_SAT = 100000
REVOKE_FEE_SAT = 50000
T1_SIZES = {'fund_B': 230, 'A_name_new': 252, 'B_name_new': 252,
    'A_name_firstupdate': 514, 'B_name_firstupdate': 514,
    'A_seal_funding': 230, 'A_grant_anchor': 534,
    'B_seal_funding': 230, 'B_grant_anchor': 534, 'A_seal_revoke': 196}
T1_FEE_CAPS = {op: size * RATE_SAT_VB for op, size in T1_SIZES.items()}
T1_FEE_CAPS['A_seal_revoke'] = REVOKE_FEE_SAT


def _amount(value):
    if type(value) is not int or value < 0:
        raise ValueError('nonnegative integer satoshis required')
    return value


def cashflow(funding_sat, t1b_fee_caps_sat=()):
    """Replay caps in source order, retaining negative balances as evidence.

Each row is the confirmed, selectable state after that operation. Revoke's
50000 fee is paid from its 100000 seal input, not from ordinary A cash.
"""
    cash = {'A': _amount(funding_sat), 'B': 0}
    names, seals = {'A': 0, 'B': 0}, {'A': 0, 'B': 0}
    rows, fees = [], 0

    def row(op, role, fee, delta):
        nonlocal fees
        fees += fee
        rows.append({'operation': op, 'role': role, 'fee_sat': fee,
            'cash_delta_sat': dict(delta), 'cash_sat': dict(cash),
            'names_locked_sat': dict(names), 'seals_locked_sat': dict(seals),
            'cumulative_fee_sat': fees})

    for op, fee in T1_FEE_CAPS.items():
        role = 'A' if op == 'fund_B' else op[0]
        delta = {'A': 0, 'B': 0}
        if op == 'fund_B':
            delta = {'A': -ROLE_B_FUNDING_SAT - fee, 'B': ROLE_B_FUNDING_SAT}
        elif op == 'A_seal_revoke':
            seals['A'] -= SEAL_SAT
            delta['A'] = SEAL_SAT - fee
        else:
            delta[role] = -fee
            if op.endswith('_name_new'):
                names[role] += NAME_LOCK_SAT
                delta[role] -= NAME_LOCK_SAT
            elif op.endswith('_seal_funding'):
                seals[role] += SEAL_SAT
                delta[role] -= SEAL_SAT
        for who in cash:
            cash[who] += delta[who]
        row(op, role, fee, delta)
    for index, fee in enumerate(t1b_fee_caps_sat):
        fee = _amount(fee)
        cash['A'] -= fee
        row('t1b_' + str(index + 1), 'A', fee, {'A': -fee, 'B': 0})
    return rows


def funding_model(t1b_fee_caps_sat=(), *, final_reserve_sat=0,
                  funder_fee_cap_sat=0):
    """Smallest value funding satisfying every prefix and final policy floor.

10% fee margin and final reserve are explicit unspent policy provisions. They
do not authorize raising any fee cap. The funder pays its own fee separately;
neither that fee nor its margin is transferred to experimental wallet A.
"""
    t1b_fee_caps_sat = tuple(_amount(fee) for fee in t1b_fee_caps_sat)
    final_reserve_sat = _amount(final_reserve_sat)
    funder_fee_cap_sat = _amount(funder_fee_cap_sat)
    zero = cashflow(0, t1b_fee_caps_sat)
    peak = max(-r['cash_sat']['A'] for r in zero)
    peak_at = [r['operation'] for r in zero if -r['cash_sat']['A'] == peak]
    b_remaining = zero[-1]['cash_sat']['B']
    if any(r['cash_sat']['B'] < 0 for r in zero):
        raise ValueError('fixed B transfer cannot cover B operations')
    fees = zero[-1]['cumulative_fee_sat']
    margin = (fees + 9) // 10
    # B's unused funds count toward the aggregate floor, but are never routed
    # back to A to pay A's earlier or later operations.
    a_final_floor = max(0, margin + final_reserve_sat - b_remaining)
    final_requirement = -zero[-1]['cash_sat']['A'] + a_final_floor
    required = max(peak, final_requirement)
    rows = cashflow(required, t1b_fee_caps_sat)
    funder_margin = (funder_fee_cap_sat + 9) // 10
    final_cash = sum(rows[-1]['cash_sat'].values())
    return {'recipient_required_sat': required,
        'fixed_B_transfer_sat': ROLE_B_FUNDING_SAT,
        'B_required_from_fixed_transfer_sat': ROLE_B_FUNDING_SAT - b_remaining,
        'B_final_cash_sat': b_remaining,
        'A_peak_drawdown_sat': peak, 'A_peak_operations': peak_at,
        'A_final_requirement_sat': final_requirement,
        'experimental_fee_caps_sat': fees, 'experimental_fee_margin_sat': margin,
        'final_reserve_sat': final_reserve_sat,
        'final_cash_sat': final_cash,
        'timing_forced_surplus_sat': final_cash - margin - final_reserve_sat,
        'funder_fee_paid_separately_sat': funder_fee_cap_sat,
        'funder_fee_margin_held_separately_sat': funder_margin,
        'all_in_required_sat': required + funder_fee_cap_sat + funder_margin,
        'minimum_kind': 'CONDITIONAL_VALUE_MODEL_UNDER_DECLARED_CAPS_NOT_LIVE_QUOTE',
        'timing_requirement': 'confirmed selectable change before reuse; no B-to-A transfer',
        'live_quote_requirements': 'fresh estimator/policy, exact inputs, signed sizes, dust/change and admission',
        'operations': rows}
