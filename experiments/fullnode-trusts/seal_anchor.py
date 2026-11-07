"""Transport-free certificate anchor/seal plans over the reviewed T1 primitives.

Public planning/inspection only. No certificate wire codec, signer, RPC, wallet,
coin selection, broadcast, ownership proof or consensus validation is provided.
Only ordinary legacy P2PKH templates are supported; other shapes fail closed.
"""
import hashlib
import json
from dataclasses import dataclass
from money import coins

from funding import OWNER_CAP_SAT, NAME_LOCK_SAT, SEAL_SAT
from mainnet import Collector, Intent, Stop, null_data, sat
from protocol import canon

SOURCE_HEAD = 'c3483b343f2509d643c8d309f4bc8099097c6310'
RESERVED_SAT = 87_500_000
RATE_SAT_VB = 200
OPERATIONS = {'seal': 'A_seal_funding', 'anchor': 'A_grant_anchor',
              'revoke': 'A_seal_revoke'}


def require(value, reason):
    if not value:
        raise Stop(reason)


def integer(value, lo, hi, reason):
    require(type(value) is int and lo <= value <= hi, reason)
    return value


def hexbytes(value, size, reason):
    require(isinstance(value, str) and len(value) == size * 2, reason)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise Stop(reason) from None
    require(len(raw) == size and raw.hex() == value, reason)
    return raw


def point(value):
    require(set(value) == {'txid', 'vout', 'script', 'value_sat'}, 'UTXO_SCHEMA')
    hexbytes(value['txid'], 32, 'TXID')
    integer(value['vout'], 0, 0xffffffff, 'VOUT')
    integer(value['value_sat'], 1, OWNER_CAP_SAT, 'INPUT_AMOUNT')
    script = hexbytes(value['script'], 25, 'P2PKH_SCRIPT')
    require(script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac', 'P2PKH_SCRIPT')
    return dict(value)


def issuer_public(value):
    require(set(value) == {'address', 'script'}, 'ISSUER_SCHEMA')
    script = hexbytes(value['script'], 25, 'ISSUER_SCRIPT')
    address = value['address']
    require(isinstance(address, str) and 26 <= len(address) <= 35, 'PUBLIC_ADDRESS')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = 0
    try:
        for ch in address:
            number = number * 58 + alphabet.index(ch)
    except ValueError:
        raise Stop('PUBLIC_ADDRESS') from None
    raw = b'\0' * (len(address) - len(address.lstrip('1')))
    raw += number.to_bytes((number.bit_length() + 7) // 8, 'big')
    require(len(raw) == 25 and raw[0] in (52, 111), 'NAMECOIN_PUBLIC_ADDRESS')
    require(hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:],
            'ADDRESS_CHECKSUM')
    require(script == b'\x76\xa9\x14' + raw[1:21] + b'\x88\xac', 'ADDRESS_SCRIPT_BINDING')
    return dict(value)


def allocation(value, kind, fee):
    """An all-in aggregate ledger, excluding returned change from consumption.

    reserved_sat is the already reserved 0.875 NMC. Other fields must be
    disjoint amounts outside that reservation. A live coordinator must attest
    this ledger from fresh evidence; these public numbers are not authority.
    """
    require(set(value) == {'reserved_sat', 'prior_fee_sat', 'name_count', 'other_locked_sat'},
            'ALLOCATION_SCHEMA')
    require(value['reserved_sat'] == RESERVED_SAT and type(value['reserved_sat']) is int,
            'ACTUAL_RESERVATION_CHANGED')
    prior = integer(value['prior_fee_sat'], 0, OWNER_CAP_SAT, 'PRIOR_FEES')
    names = integer(value['name_count'], 0, 4, 'NAME_COUNT') * NAME_LOCK_SAT
    locked = integer(value['other_locked_sat'], 0, OWNER_CAP_SAT, 'LOCKED_AMOUNT')
    require(kind != 'revoke' or locked >= SEAL_SAT, 'SEAL_NOT_ACCOUNTED')
    before = RESERVED_SAT + prior + names + locked
    require(before <= OWNER_CAP_SAT, 'PREEXISTING_CAP_EXCEEDED')
    delta = SEAL_SAT if kind == 'seal' else -SEAL_SAT if kind == 'revoke' else 0
    after = before + fee + delta
    require(after <= OWNER_CAP_SAT, 'OWNER_CAP_EXCEEDED')
    return {'reserved_sat': RESERVED_SAT, 'names_locked_sat': names,
            'prior_fee_sat': prior, 'other_locked_before_sat': locked,
            'other_locked_after_sat': locked + delta, 'operation_fee_sat': fee,
            'available_before_sat': OWNER_CAP_SAT - before,
            'all_in_after_sat': after, 'remaining_sat': OWNER_CAP_SAT - after}


def time_bounds(value, now, *, preparing=True):
    require(set(value) == {'accepted_epoch', 'deadline_epoch', 'step_started_epoch',
                          'broadcast_tip_height', 'broadcast_tip_hash'}, 'BOUNDS_SCHEMA')
    for field in ('accepted_epoch', 'deadline_epoch', 'step_started_epoch'):
        integer(value[field], 1, 1 << 53, 'IMMUTABLE_TIME')
    integer(now, 1, 1 << 53, 'NOW')
    start, end, step = (value[k] for k in ('accepted_epoch', 'deadline_epoch', 'step_started_epoch'))
    require(0 < end - start <= 21600 and start <= step <= now, 'IMMUTABLE_CLOCK')
    limit = min(end, step + (180 if preparing else 1500))
    require(now < limit, 'EARLIER_DEADLINE')
    integer(value['broadcast_tip_height'], 0, 0x7fffffff - 6, 'TIP_HEIGHT')
    hexbytes(value['broadcast_tip_hash'], 32, 'TIP_HASH')
    return {'preparation_before_epoch': min(end, step + 180),
            'step_before_epoch': min(end, step + 1500),
            'inclusion_before_epoch': min(end, step + 1320),
            'inclusion_max_height': value['broadcast_tip_height'] + 6,
            'broadcast_tip_hash': value['broadcast_tip_hash']}


@dataclass(frozen=True)
class Plan:
    """Immutable local helper record, never a new certificate/request wire."""
    encoded: bytes

    def public(self):
        return json.loads(self.encoded)

    def intent(self):
        p = self.public()
        outputs = ([{'data': p['certificate_sha256']}] if p['kind'] == 'anchor' else
                   [{p['issuer']['address']: coins(p['output_sat'])}])
        u = p['input']
        exact = ({'txid': u['txid'], 'vout': u['vout'], 'script': u['script'],
                  'value': str(coins(u['value_sat']))} if p['kind'] == 'revoke' else None)
        return Intent(OPERATIONS[p['kind']], 'A',
                      ({'txid': u['txid'], 'vout': u['vout']},), tuple(outputs), exact_input=exact)


def prepare(kind, certificate, issuer, utxo, ledger, bounds, *, now, seal=None):
    """Return an exact-input intent plus allowed outputs/change and fee caps.

    Only public bytes and public ledger data enter this function. It never
    invokes the external wallet builder. Funding/anchor use build_signed;
    revoke uses Collector's unchanged no-fundrawtransaction exact-input path.
    """
    require(kind in OPERATIONS, 'OPERATION')
    require(type(certificate) is bytes and 0 < len(certificate) <= 1024 * 1024,
            'CERTIFICATE_BYTES_BOUND')
    issuer, utxo = issuer_public(issuer), point(utxo)
    require(utxo['script'] == issuer['script'], 'ISSUER_INPUT_BINDING')
    seal = point(seal) if seal is not None else None
    if kind in ('anchor', 'revoke'):
        require(seal is not None and seal['script'] == issuer['script'] and
                seal['value_sat'] == SEAL_SAT, 'SEAL_BINDING')
        require((utxo == seal) if kind == 'revoke' else
                (utxo['txid'], utxo['vout']) != (seal['txid'], seal['vout']), 'EXACT_SEAL_OUTPOINT')
    else:
        require(seal is None, 'NEW_SEAL_REQUIRED')
    fee_cap = Collector.fee_cap(OPERATIONS[kind])
    output_sat = SEAL_SAT if kind == 'seal' else SEAL_SAT - fee_cap if kind == 'revoke' else 0
    require(utxo['value_sat'] > output_sat + fee_cap if kind != 'revoke' else
            utxo['value_sat'] == output_sat + fee_cap, 'INSUFFICIENT_EXPLICIT_INPUT')
    # No same-address equal-value change: it would make seal output selection ambiguous.
    if kind == 'seal':
        low = utxo['value_sat'] - output_sat - fee_cap
        high = utxo['value_sat'] - output_sat
        require(not low <= SEAL_SAT <= high, 'AMBIGUOUS_SEAL_CHANGE')
    limits = time_bounds(bounds, now)
    budget = allocation(ledger, kind, fee_cap)
    # The entire selected ordinary coin must fit the unreserved allocation,
    # even if most of it returns as change. Revoke uses an already-counted lock.
    require(kind == 'revoke' or utxo['value_sat'] <= budget['available_before_sat'],
            'INPUT_ALLOCATION_EXCEEDS_OWNER_CAP')
    return Plan(canon({'t1_source_head': SOURCE_HEAD, 'kind': kind,
        'certificate_sha256': hashlib.sha256(certificate).hexdigest(),
        'issuer': issuer, 'input': utxo, 'seal': seal, 'output_sat': output_sat,
        'rate_sat_vb': RATE_SAT_VB, 'vsize_cap': Collector.size_cap(OPERATIONS[kind]),
        'fee_cap_sat': fee_cap, 'ledger': dict(ledger),
        'allocation_at_fee_cap': budget,
        'bounds': dict(bounds), 'limits': limits,
        'spend_authorized': False, 'broadcast_authorized': False}))


def decode_legacy(raw_hex, issuer):
    """Bounded structural inspection, not script/signature/consensus validation.

    Deliberately supports only the one-input ordinary legacy templates here.
    There is no serializer or transaction builder in this adapter.
    """
    require(isinstance(raw_hex, str) and 0 < len(raw_hex) <= 40000, 'RAW_BOUND')
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        raise Stop('RAW_HEX') from None
    require(raw.hex() == raw_hex, 'RAW_CANONICAL_HEX')
    offset = 0

    def read(n):
        nonlocal offset
        require(offset + n <= len(raw), 'TRUNCATED_TRANSACTION')
        out = raw[offset:offset+n]
        offset += n
        return out

    def number(n):
        return int.from_bytes(read(n), 'little')

    def compact(cap):
        first = number(1)
        n = number({253: 2, 254: 4, 255: 8}[first]) if first >= 253 else first
        require(n >= {253: 253, 254: 65536, 255: 1 << 32}.get(first, 0) and n <= cap,
                'COMPACT_SIZE_BOUND')
        return n

    require(number(4) in (1, 2), 'LEGACY_VERSION_ONLY')
    require(compact(1) == 1, 'ONE_LEGACY_INPUT_REQUIRED')
    vin = [{'txid': read(32)[::-1].hex(), 'vout': number(4)}]
    script_sig = read(compact(1650))
    require(bool(script_sig), 'EXTERNAL_SIGNATURE_REQUIRED')
    number(4)  # sequence; binds via the exact raw hash, no replacement capability
    count = compact(3)
    require(count > 0, 'OUTPUT_COUNT')
    outputs = []
    for n in range(count):
        value = number(8)
        require(value <= OWNER_CAP_SAT, 'OUTPUT_AMOUNT_BOUND')
        script = read(compact(10000)).hex()
        sp = {'hex': script}
        if script == issuer['script']:
            sp['address'] = issuer['address']
        outputs.append({'n': n, 'value': coins(value), 'scriptPubKey': sp})
    number(4)
    require(offset == len(raw), 'TRAILING_TRANSACTION_BYTES')
    return {'txid': hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex(),
            'vsize': len(raw), 'weight': 4 * len(raw), 'vin': vin, 'vout': outputs}


class _Evidence:
    """Only the existing inspector's cached public reads; never a transport."""
    def __init__(self, plan, decoded, prevouts):
        self.plan, self.decoded, self.prevouts, self.read = plan, decoded, prevouts, object()

    size_cap = staticmethod(Collector.size_cap)
    fee_cap = staticmethod(Collector.fee_cap)

    def call(self, cap, method, *args):
        if method == 'decoderawtransaction':
            return self.decoded
        if method == 'getrawtransaction':
            # Preserve original failure: getrawtransaction without txindex or
            # supplied public evidence is unavailable, never guessed/retried.
            require(args[0] in self.prevouts, 'GETRAWTRANSACTION_PREVOUT_UNAVAILABLE_TXINDEX_REQUIRED')
            return self.prevouts[args[0]]
        if method == 'gettxout':
            # Cached evidence supplies the value schema only. This is still
            # structural inspection, never a live confirmation/unspent proof.
            require(args[0] in self.prevouts, 'PUBLIC_PREVOUT_UNAVAILABLE')
            outputs = self.prevouts[args[0]]['vout']
            require(type(args[1]) is int and 0 <= args[1] < len(outputs), 'PREVOUT_INDEX')
            return {'confirmations': 1, 'value': outputs[args[1]]['value']}
        raise Stop('OFFLINE_METHOD_DENIED')

    def rpc_for_builder(self, method, address, *, wallet):
        require(method == 'getaddressinfo' and address == self.plan['issuer']['address'] and wallet == 'A',
                'EXPLICIT_CHANGE_REQUIRED')
        return {'ismine': True, 'iswatchonly': False}  # caller ownership declaration only


def inspect(plan, certificate, raw_hex, prevouts, *, now):
    """Bind raw bytes, source output checks and conservation; never admit spend.

    Prevouts are cached public getrawtransaction-shaped evidence. Confirmation,
    spendability, ownership, signatures and relay require fresh external checks.
    """
    p = plan.public()
    rebuilt = prepare(p['kind'], certificate, p['issuer'], p['input'], p['ledger'],
                      p['bounds'], now=now, seal=p['seal'])
    require(rebuilt == plan, 'PLAN_BINDING_CHANGED')
    d = decode_legacy(raw_hex, p['issuer'])
    u = p['input']
    require(d['vin'] == [{'txid': u['txid'], 'vout': u['vout']}], 'EXACT_INPUT_CHANGED')
    require(u['txid'] in prevouts, 'GETRAWTRANSACTION_PREVOUT_UNAVAILABLE_TXINDEX_REQUIRED')
    require(set(prevouts) == {u['txid']}, 'EXACT_PUBLIC_PREVOUT_REQUIRED')
    tx = prevouts[u['txid']]
    require(type(tx.get('vout')) is list and u['vout'] < len(tx['vout']), 'PREVOUT_INDEX')
    prev = tx['vout'][u['vout']]
    require(sat(prev['value']) == u['value_sat'] and
            prev['scriptPubKey']['hex'] == u['script'], 'PREVOUT_BINDING')
    evidence = _Evidence(p, d, prevouts)
    _, fee = Collector.inspect(evidence, raw_hex, plan.intent())
    require(RATE_SAT_VB * d['vsize'] <= fee <= p['fee_cap_sat'], 'FIXED_FEE_BOUND')
    require(all(o['scriptPubKey']['hex'] == p['issuer']['script'] or
                p['kind'] == 'anchor' and o['scriptPubKey']['hex'] ==
                null_data(bytes.fromhex(p['certificate_sha256'])).hex() for o in d['vout']),
            'OUTPUT_SCRIPT_CHANGED')
    ledger = allocation(p['ledger'], p['kind'], fee)
    seal = p['seal']
    if p['kind'] == 'seal':
        candidates = [o for o in d['vout'] if sat(o['value']) == SEAL_SAT and
                      o['scriptPubKey']['hex'] == p['issuer']['script']]
        require(len(candidates) == 1, 'UNIQUE_SEAL_OUTPUT_REQUIRED')
        seal = {'txid': d['txid'], 'vout': candidates[0]['n'],
                'script': p['issuer']['script'], 'value_sat': SEAL_SAT}
    total_out = sum(sat(o['value']) for o in d['vout'])
    require(u['value_sat'] == total_out + fee, 'ECONOMIC_CONSERVATION')
    return {'t1_source_head': SOURCE_HEAD, 'plan_sha256': hashlib.sha256(plan.encoded).hexdigest(),
            'certificate_sha256': p['certificate_sha256'], 'txid': d['txid'],
            'raw_sha256': hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest(),
            'vsize': d['vsize'], 'fee_sat': fee, 'input_sat': u['value_sat'],
            'output_sat': total_out, 'seal': seal, 'allocation': ledger,
            'revoked_outpoint': seal if p['kind'] == 'revoke' else None,
            'status': 'OFFLINE_STRUCTURAL_CHECKS_ONLY',
            'spend_authorized': False, 'broadcast_authorized': False}


def spends_seal(seal, vin):
    """Exact decoded-vin outpoint recognition for the separate mempool watcher.

    Caller must independently establish that vin belongs to the observed tx.
    """
    seal = point(seal)
    return any(v.get('txid') == seal['txid'] and type(v.get('vout')) is int and
               v['vout'] == seal['vout'] for v in vin)
