"""Finite experimental collector, inert until an admitted launcher supplies capabilities.

There is deliberately no CLI, HTTP client, credential loader, node launcher or
wallet creation here. Transport, authenticated admissions, a durable public
journal and a separately admitted remote observer are external capabilities.
The old closed-regtest entrypoint remains mainnet-disabled.
"""
import hashlib
import json
import math
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal

from protocol import GENESIS, READ_METHODS, canon
from transaction import build_signed
from money import satoshis, coins, total_satoshis, validate_outputs
from t1b import SIZES, VSIZE_CAPS, payload, script, budget

SAT = Decimal(100000000)
CAP_SAT = 100000000  # maximum, never a requested funding target
LOOPBACK_OBSERVATION_INTERVAL_S = 0.1
PREPARATION_S = 180
PEER_S = 120
FIXED_FEE_SAT_VB = 200
INCLUSION_BLOCKS = 6
T1_ORDER = ('fund_B', 'A_name_new', 'B_name_new', 'A_name_firstupdate',
            'B_name_firstupdate', 'A_seal_funding', 'A_grant_anchor',
            'B_seal_funding', 'B_grant_anchor', 'A_seal_revoke')
ORDER = T1_ORDER + tuple('opreturn_' + str(n) for n in SIZES)
CORE_MODE = 'T1_CORE_MVP'
SERIES_MODE = 'T1B_SERIES'
T1_SIZES = dict(zip(T1_ORDER, (230, 252, 252, 514, 514, 230, 534, 230, 534, 196)))
OBSERVE = READ_METHODS | frozenset({'decoderawtransaction', 'getnetworkinfo',
    'getmempoolinfo', 'estimatesmartfee', 'testmempoolaccept', 'getblock',
    'getrawmempool'})
BUILD = frozenset({'createrawtransaction', 'namerawtransaction'})
WALLET = frozenset({'fundrawtransaction', 'signrawtransactionwithwallet',
                    'signmessage', 'lockunspent', 'getaddressinfo'})
BROADCAST = frozenset({'sendrawtransaction'})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sat(value):
    return satoshis(value)


def digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def null_data(data):
    # Core's canonical short push for grant hashes; T1b uses >=80 bytes.
    return b'\x6a' + bytes([len(data)]) + data if len(data) <= 75 else script(data)


class Stop(RuntimeError):
    """Terminal refusal. Never retry, rebroadcast, replace or advance."""


class Capability:
    """Allowlist and exact wallet path checked before calling the transport.

    The external launcher must ALSO enforce these separate method sets in Core
    with distinct logins and isolate the signer from observer/collector code.
    A Python object alone is not an OS or Core security boundary. No credential
    material is accepted, introspected or included in journal records here.
    """
    def __init__(self, transport, methods, *, wallet='', destination=None):
        self._transport, self.methods, self.wallet = transport, frozenset(methods), wallet
        # Public destination binding supplied by the admitted launcher, not a
        # guess from an RPC method name. It must pin the actual transport and
        # forbid redirects/proxies to any other destination.
        self._destination = destination

    @property
    def destination(self):
        return self._destination

    def __call__(self, method, *params, wallet=''):
        if method not in self.methods or wallet != self.wallet:
            raise Stop('RPC_CAPABILITY_DENIED')
        return self._transport(method, *params, wallet=wallet)


@dataclass(frozen=True)
class Intent:
    operation: str
    role: str
    inputs: tuple
    outputs: tuple
    name_op: object = None
    # An explicit selected seal input must not be supplemented by coin selection.
    exact_input: object = None


class Collector:
    """Single-use finite run; all external calls must have a <=10 s deadline.

    gates(kind, binding) verifies authenticated, unexpired, one-use admissions
    and returns a public receipt SHA256. The launcher must durably consume run
    admission before entering this class. journal(row) must synchronously store
    each public record, particularly BROADCAST_ATTEMPT, or raise before I/O.
    There is no resume/retry API. An interrupted/ambiguous attempt is terminal.
    """
    def __init__(self, observer, builder, wallets, broadcaster, peer, gates, journal,
                 *, source, admission, clock=time.monotonic, wall=time.time,
                 pause=time.sleep):
        if observer.methods != OBSERVE or builder.methods != BUILD or broadcaster.methods != BROADCAST:
            raise Stop('CAPABILITY_SETS')
        if set(wallets) != {'A', 'B'} or any(w.methods != WALLET or not w.wallet for w in wallets.values()):
            raise Stop('EXPERIMENTAL_WALLETS_REQUIRED')
        if wallets['A'].wallet == wallets['B'].wallet:
            raise Stop('DISTINCT_EXPERIMENTAL_WALLETS_REQUIRED')
        if set(source) != {'head', 'tree'} or not all(isinstance(v, str) and len(v) == 40 for v in source.values()):
            raise Stop('SOURCE_BINDING')
        if observer.destination != '127.0.0.1' or observer.wallet:
            raise Stop('OWN_LOOPBACK_OBSERVER_REQUIRED')
        self.read, self.build, self.wallets, self.broadcast = observer, builder, wallets, broadcaster
        self.peer, self.gates, self.journal = peer, gates, journal
        self.source, self.clock, self.wall, self.pause = dict(source), clock, wall, pause
        self.stopped, self.index, self.calls, self.receipt_bytes, self.response_bytes = False, 0, 0, 0, 0
        self.fees, self.rows, self.anchors, self.used_raw = 0, [], [], set()
        self.tip, self.step_start, self.series_start = None, None, None
        self.last_observation = None
        self._rpc_lock = threading.Lock()
        self.phase_deadline, self.phase_reason = None, None
        self.after_broadcast = None
        self.broadcast_window = None
        self.started = admission.get('started_monotonic')
        self.deadline_wall = admission.get('deadline_utc_epoch')
        self.deadline = admission.get('deadline_monotonic')
        nums = (self.started, self.deadline, self.deadline_wall)
        if any(type(v) not in (int, float) or not math.isfinite(v) for v in nums):
            raise Stop('IMMUTABLE_CLOCK_REQUIRED')
        if not 0 < self.deadline - self.started <= 21600 or self.started > self.clock():
            raise Stop('SIX_HOUR_BOUND')
        if self.deadline_wall - self.wall() > self.deadline - self.clock() + 1:
            raise Stop('CLOCK_BINDING')
        self.funding_sat = admission.get('requested_funding_sat')
        # This source still uses the conditional ceilings. A changed fixed rate,
        # shape or funding model needs a new reviewed source/admission.
        required = admission.get('recomputed_required_sat')
        if (type(self.funding_sat) is not int or type(required) is not int or
            self.funding_sat != required or not 2200000 < required <= budget()['all_in_required_sat'] <= CAP_SAT):
            raise Stop('FUNDING_BOUND')
        if not isinstance(admission.get('funding_address'), str) or not admission['funding_address']:
            raise Stop('NEW_FUNDED_ADDRESS_REQUIRED')
        self._gate('runtime', {'source': self.source, 'admission': admission,
                              'operations': ORDER, 'cap_sat': CAP_SAT})
        self._gate('fresh_whole_review', self.source)
        self._gate('spend_GO', {'source': self.source, 'cap_sat': CAP_SAT,
                              'new_Ivan_funded_experimental_address': admission.get('funding_address'),
                              'requested_funding_sat': self.funding_sat})
        # Attests new isolated wallets, no owner wallet/key, no existing wallet
        # mount, Core whitelists, transport timeouts, durable journal and no resume.
        self._gate('capability_custody', {'source': self.source,
                   'wallet_roles': {r: w.wallet for r, w in wallets.items()},
                   'method_sets': [sorted(x) for x in (OBSERVE, BUILD, WALLET, BROADCAST)],
                   'observer_destination': observer.destination,
                   'observer_transport': 'own T1 node; literal IPv4 loopback; no redirects or proxy',
                   'loopback_observation_interval_s': LOOPBACK_OBSERVATION_INTERVAL_S,
                   'public_observation_interval_s': 10})
        self.network()

    def _gate(self, kind, binding):
        exact = canon(json_safe(binding))
        request = json.loads(exact)
        receipt = self.gates(kind, request)
        if canon(request) != exact:
            raise Stop('ADMISSION_BINDING_MUTATED')
        if not digest(receipt):
            raise Stop('ADMISSION_REFUSED_' + kind)
        self.record({'event': 'ADMISSION', 'kind': kind, 'binding': request, 'receipt_sha256': receipt})
        return receipt

    def record(self, row):
        row = dict(row, observed_at_utc=datetime.fromtimestamp(self.wall(), timezone.utc).isoformat(),
                   monotonic=self.clock())
        size = len(canon(row))
        if self.receipt_bytes + size > 24 * 1024 * 1024:
            self.stopped = True
            raise Stop('EXPORT_BYTES_BOUND')
        self.journal(row)  # durable public-only sink; exceptions prevent next I/O
        self.receipt_bytes += size

    def bounds(self):
        if self.stopped:
            raise Stop('TERMINAL_NO_RETRY')
        now = self.clock()
        if now >= self.deadline or self.wall() >= self.deadline_wall or now < self.started:
            raise Stop('IMMUTABLE_DEADLINE')
        if self.step_start is not None and now - self.step_start >= 1500:
            raise Stop('STEP_DEADLINE')
        if self.series_start is not None and now - self.series_start >= 10500:
            raise Stop('SERIES_DEADLINE')
        if self.phase_deadline is not None and now >= self.phase_deadline:
            raise Stop(self.phase_reason)

    def begin_t1b(self):
        """Reserve the full series once, before T1b gates or preparation.

        The admitted UTC and monotonic bounds never move. Re-entry cannot
        refresh either the original run clock or this series reservation.
        """
        if self.stopped:
            raise Stop('TERMINAL_NO_RETRY')
        if self.series_start is None:
            if min(self.deadline - self.clock(), self.deadline_wall - self.wall()) < 10500:
                self.stopped = True
                self.record({'event': 'STOP', 'reason': 'STOP_INSUFFICIENT_SHARED_TIME',
                             'remaining_monotonic_s': self.deadline - self.clock(),
                             'remaining_utc_s': self.deadline_wall - self.wall(),
                             'required_s': 10500, 'rebroadcast': False})
                raise Stop('STOP_INSUFFICIENT_SHARED_TIME')
            self.bounds()
            self.series_start = self.clock()
        self.bounds()

    def observation_slot(self, cap, method):
        """Destination-bound dispatch spacing, in every phase.

        Only the admitted own-node observer at literal 127.0.0.1 gets 10/s.
        Every other observation, including remote-peer polls and identical
        read methods on another capability, retains a ten-second wait since
        the preceding observation. All observations update that shared clock,
        so neighboring loopback reads cannot accelerate a public request.
        Construction/sign/send remain outside this read-only exception.
        """
        interval = (LOOPBACK_OBSERVATION_INTERVAL_S if cap is self.read and cap.destination == '127.0.0.1'
                    and method in OBSERVE else 10)
        self.bounds()
        if self.last_observation is not None:
            wait = max(0, self.last_observation + interval - self.clock())
            if wait:
                self.pause(wait)
        self.bounds()  # never dispatch after waiting through any phase bound
        if self.last_observation is not None and self.clock() < self.last_observation + interval:
            raise Stop('OBSERVATION_CLOCK_OR_SLEEP')
        self.last_observation = self.clock()

    def require_preparation_capacity(self, intent):
        # The actual path has THREE network passes: entry, shared builder
        # (or exact-input branch), and after exact-raw admission. Each retains
        # every anchor. Count the other required observer reads as well.
        # For a funded transaction the helper reads decode/prevouts/policy;
        # inspect reads decode/prevouts/UTXOs; policy and final acceptance add
        # four reads. At least one input is mandatory. Retain one reserved
        # policy-read slot in this conservative capacity bound, although the
        # fixed-rate policy no longer calls an estimator. Exact-input skips
        # the helper's reads but retains the same reserved slot.
        inputs = max(1, len(intent.inputs))
        minimum_calls = 3 * (4 + len(self.anchors)) + (7 if intent.exact_input else 7 + 3 * inputs)
        minimum_span = (minimum_calls - 1) * LOOPBACK_OBSERVATION_INTERVAL_S
        if minimum_span >= PREPARATION_S:
            self.record({'event': 'CONTRACT_CONSTRAINT', 'phase': 'preparation',
                'minimum_observation_calls': minimum_calls,
                'minimum_span_s': minimum_span, 'phase_limit_s': PREPARATION_S,
                'rpc_interval_s': LOOPBACK_OBSERVATION_INTERVAL_S, 'destination': '127.0.0.1',
                'anchors_retained': len(self.anchors),
                'resolution': 'mandatory observations exceed preparation budget'})
            raise Stop('STOP_OBSERVATION_PREPARATION_CONTRACT')

    def call(self, cap, method, *params, wallet=''):
        if not self._rpc_lock.acquire(blocking=False):
            raise Stop('RPC_IN_FLIGHT')
        try:
            return self._call(cap, method, *params, wallet=wallet)
        finally:
            self._rpc_lock.release()

    def _call(self, cap, method, *params, wallet=''):
        self.bounds()
        if method in OBSERVE or method == 'remote_peer_observation':
            self.observation_slot(cap, method)
        self.calls += 1
        if self.calls > 2100:
            raise Stop('RPC_COUNT_BOUND')
        begin = self.clock()
        try:
            result = cap(method, *params, wallet=wallet)
        except Exception:
            # Transport exception text can contain credentials; never export it.
            self.record({'event': 'RPC_ERROR', 'method': method, 'status': 'UNAVAILABLE',
                         'elapsed_s': self.clock() - begin})
            raise Stop('RPC_UNAVAILABLE_' + method) from None
        size = len(canon(json_safe(result)))
        self.response_bytes += size
        if size > 8 * 1024 * 1024 or self.response_bytes > 64 * 1024 * 1024:
            raise Stop('RPC_RESPONSE_BOUND')
        self.record({'event': 'RPC', 'method': method, 'response_sha256': sha(canon(json_safe(result))),
                     'response_bytes': size, 'elapsed_s': self.clock() - begin})
        if method == 'testmempoolaccept':
            self.record({'event': 'LOCAL_POLICY_RESULT', 'result': json_safe(result)})
        if self.clock() - begin > 10:
            raise Stop('RPC_TIME_BOUND')
        self.bounds()
        return result

    def observe_peer(self, binding):
        # Same scheduler, in-flight lock, count, response/elapsed bounds and
        # error sanitization as every local observational RPC.
        return self.call(lambda method, wallet='': self.peer(binding),
                         'remote_peer_observation')

    def network(self):
        info = self.call(self.read, 'getblockchaininfo')
        if info.get('chain') != 'main' or info.get('initialblockdownload') is not False:
            raise Stop('MAINNET_NOT_READY')
        if self.call(self.read, 'getblockhash', 0) != GENESIS['main']:
            raise Stop('WRONG_GENESIS')
        height, block = info.get('blocks'), info.get('bestblockhash')
        if type(height) is not int or info.get('headers') != height or not digest(block):
            raise Stop('TIP_NOT_READY')
        if self.tip is not None:
            old_height, old_hash = self.tip
            if height < old_height or self.call(self.read, 'getblockhash', old_height) != old_hash:
                raise Stop('REORG')
        for h, b in self.anchors:
            if self.call(self.read, 'getblockhash', h) != b:
                raise Stop('REORG')
        if self.call(self.read, 'getblockhash', height) != block:
            raise Stop('TIP_CHANGED_DURING_READ')
        self.tip = height, block
        self.check_broadcast_window()
        return info

    def check_broadcast_window(self):
        """Six active-chain successors of the last pre-send observed tip.

        Poll counts and elapsed time never manufacture blocks. The baseline
        stays fixed; network() refuses a rollback or changed ancestor first.
        A skipped poll may find a later tip: only exact inclusion at or before
        the original sixth successor qualifies, never a widened window.
        """
        if self.broadcast_window is None:
            return
        start_height, start_hash, txid, raw = self.broadcast_window
        if self.call(self.read, 'getblockhash', start_height) != start_hash:
            raise Stop('REORG')
        blocks = self.tip[0] - start_height
        if blocks < 0:
            raise Stop('REORG')
        if blocks >= INCLUSION_BLOCKS:
            tx = self.call(self.read, 'getrawtransaction', txid, True)
            if tx.get('confirmations', 0) < 0:
                raise Stop('REORG')
            if tx.get('confirmations', 0) < 1:
                raise Stop('SIX_BLOCK_INCLUSION_STOP')
            block_hash = tx.get('blockhash')
            header = self.call(self.read, 'getblockheader', block_hash)
            height = header.get('height')
            if type(height) is not int or not start_height < height <= start_height + INCLUSION_BLOCKS:
                raise Stop('SIX_BLOCK_INCLUSION_STOP')
            if self.call(self.read, 'getblockhash', height) != block_hash:
                raise Stop('REORG')
            exact = self.call(self.read, 'getrawtransaction', txid, False, block_hash)
            block = self.call(self.read, 'getblock', block_hash, 2)
            if exact != raw or not any(x.get('txid') == txid for x in block['tx']):
                raise Stop('EXACT_INCLUSION_MISMATCH')
            self.record({'event': 'SIX_BLOCK_WINDOW', 'broadcast_tip_height': start_height,
                         'broadcast_tip_hash': start_hash, 'observed_tip_height': self.tip[0],
                         'limit_height': start_height + INCLUSION_BLOCKS,
                         'inclusion_height': height, 'txid': txid})

    def rpc_for_builder(self, method, *params, wallet=''):
        if method in OBSERVE:
            if wallet:
                raise Stop('OBSERVER_WALLET_DENIED')
            return self.call(self.read, method, *params)
        if method in BUILD:
            if wallet:
                raise Stop('BUILDER_WALLET_DENIED')
            return self.call(self.build, method, *params)
        if method in WALLET and wallet in self.wallets:
            cap = self.wallets[wallet]
            return self.call(cap, method, *params, wallet=cap.wallet)
        raise Stop('BUILDER_CAPABILITY_DENIED')

    def policy(self):
        info = self.call(self.read, 'getnetworkinfo')
        pool = self.call(self.read, 'getmempoolinfo')
        # Fixed reviewed source rate; estimator availability is irrelevant.
        # RPC policy rates are NMC/kvB: 200 sat/vB = .002 NMC/kvB.
        rates = (info.get('relayfee'), pool.get('mempoolminfee'))
        if any(x is None or not Decimal(str(x)).is_finite() or not 0 < Decimal(str(x)) <= Decimal('.002') for x in rates):
            raise Stop('FRESH_FEE_MODEL_REQUIRED')
        result = {'network': json_safe(info), 'mempool': json_safe(pool),
                  'fee_source': 'FIXED_REVIEWED_SOURCE', 'rate_sat_vb': FIXED_FEE_SAT_VB,
                  'estimator_quote': None, 'inclusion_quote': None}
        self.record({'event': 'POLICY', 'snapshot': result,
                     'limitation': 'RPC does not expose every datacarrier/standardness option'})
        return result

    def inspect(self, raw, intent):
        data = bytes.fromhex(raw)
        if not data or len(data) > 20000 or raw != data.hex():
            raise Stop('RAW_BOUND_OR_NONCANONICAL_HEX')
        d = self.call(self.read, 'decoderawtransaction', raw)
        if not digest(d.get('txid')) or type(d.get('vsize')) is not int or type(d.get('weight')) is not int:
            raise Stop('DECODE_SCHEMA')
        if not 0 < d['vsize'] <= self.size_cap(intent.operation) or d['weight'] > 4 * d['vsize']:
            raise Stop('SIGNED_SIZE_BOUND')
        vin, outputs = d['vin'], d['vout']
        if not 1 <= len(vin) <= 2 or len({(v['txid'], v['vout']) for v in vin}) != len(vin):
            raise Stop('INPUT_SHAPE')
        # Original templates use <=2 inputs for name transitions and one
        # ordinary input otherwise. Changed shapes require fresh review.
        if len(vin) > (2 if intent.name_op and intent.name_op['op'] != 'name_new' else 1):
            raise Stop('INPUT_TEMPLATE_CHANGED')
        points = {(v['txid'], v['vout']) for v in vin}
        if any((v['txid'], v['vout']) not in points for v in intent.inputs):
            raise Stop('REQUIRED_INPUT_MISSING')
        if intent.exact_input and points != {(intent.exact_input['txid'], intent.exact_input['vout'])}:
            raise Stop('SEAL_INPUT_CHANGED')
        input_values = []
        for v in vin:
            prev = self.call(self.read, 'getrawtransaction', v['txid'], True)['vout'][v['vout']]
            value_sat = sat(prev['value'])
            input_values.append(prev['value'])
            coin = self.call(self.read, 'gettxout', v['txid'], v['vout'], True)
            if (not isinstance(coin, dict) or type(coin.get('confirmations')) is not int
                    or coin['confirmations'] < 1):
                raise Stop('CONFIRMED_UNSPENT_INPUT_REQUIRED')
            try:
                coin_value_sat = sat(coin.get('value'))
            except ValueError:
                raise Stop('PREVOUT_VALUE_SCHEMA') from None
            if coin_value_sat != value_sat:
                raise Stop('PREVOUT_VALUE_MISMATCH')
        total_in = total_satoshis(input_values)
        fee = total_in - total_satoshis(v['value'] for v in outputs)
        if not 0 <= fee <= self.fee_cap(intent.operation):
            raise Stop('SIGNED_FEE_BOUND')
        if len(outputs) != len(intent.outputs) + (0 if intent.exact_input else 1):
            raise Stop('OUTPUT_TEMPLATE_CHANGED')
        # fundrawtransaction must preserve explicit output positions. The
        # shared helper's legacy options do not pin changePosition, so we
        # validate by a unique matching output instead of assuming its index.
        matched = set()
        for expected in intent.outputs:
            key, value = next(iter(expected.items()))
            candidates = []
            for i, out in enumerate(outputs):
                sp = out['scriptPubKey']
                if key == 'data':
                    match = sat(out['value']) == 0 and sp.get('hex') == null_data(bytes.fromhex(value)).hex()
                else:
                    match = sp.get('address') == key and sat(out['value']) == sat(value)
                if match and i not in matched:
                    candidates.append(i)
            if len(candidates) != 1:
                raise Stop('EXPLICIT_OUTPUT_CHANGED')
            matched.add(candidates[0])
        for i, out in enumerate(outputs):
            if i not in matched:
                address = out['scriptPubKey'].get('address')
                if not address or sat(out['value']) <= 0:
                    raise Stop('CHANGE_OUTPUT_SCHEMA')
                ownership = self.rpc_for_builder('getaddressinfo', address, wallet=intent.role)
                if ownership.get('ismine') is not True or ownership.get('iswatchonly') is not False:
                    raise Stop('CHANGE_NOT_EXPERIMENTAL_WALLET')
        names = [v['scriptPubKey']['nameOp'] for v in outputs if 'nameOp' in v['scriptPubKey']]
        if intent.name_op:
            if len(names) != 1 or any(names[0].get(k) != v for k, v in intent.name_op.items() if k != 'rand'):
                # name_new decodes commitment, not plaintext name; checked below.
                if intent.name_op['op'] != 'name_new' or len(names) != 1:
                    raise Stop('NAME_VALUES_CHANGED')
                commitment = hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(intent.name_op['rand']) + intent.name_op['name'].encode()).digest()).hexdigest()
                if names[0].get('op') != 'name_new' or names[0].get('hash') != commitment:
                    raise Stop('NAME_COMMITMENT_CHANGED')
            if intent.name_op['op'] == 'name_firstupdate' and names[0].get('rand') != intent.name_op['rand']:
                raise Stop('NAME_NONCE_CHANGED')
        elif names:
            raise Stop('UNEXPECTED_NAME_OPERATION')
        return d, fee

    @staticmethod
    def size_cap(operation):
        return T1_SIZES[operation] if operation in T1_SIZES else VSIZE_CAPS[int(operation.split('_')[1])]

    @classmethod
    def fee_cap(cls, operation):
        return 50000 if operation == 'A_seal_revoke' else cls.size_cap(operation) * 200

    def run_next(self, intent):
        try:
            return self._run_next(intent)
        except Exception as error:
            self.stopped = True
            reason = str(error) if isinstance(error, Stop) else 'UNAVAILABLE_OR_MALFORMED'
            self.record({'event': 'STOP', 'reason': reason, 'operation': intent.operation,
                         'rebroadcast': False, 'replacement': False})
            raise Stop(reason) from None

    def _run_next(self, intent):
        if intent.operation.startswith('opreturn_'):
            self.begin_t1b()
        self.bounds()
        if self.index >= len(ORDER) or intent.operation != ORDER[self.index] or intent.role not in self.wallets:
            raise Stop('OPERATION_ORDER')
        # Policy is derived from the checked operation, never a caller's mode
        # override. In particular, T1b cannot inherit the core UNKNOWN policy.
        mode = CORE_MODE if intent.operation in T1_ORDER else SERIES_MODE
        if mode == SERIES_MODE and self.peer is None:
            raise Stop('PEER_OBSERVER_REQUIRED')
        role = 'A' if intent.operation == 'fund_B' or intent.operation.startswith('opreturn_') else intent.operation[0]
        if intent.role != role:
            raise Stop('OPERATION_ROLE')
        self.step_start = self.clock()
        self.phase_deadline, self.phase_reason = self.step_start + PREPARATION_S, 'PREPARATION_DEADLINE'
        if intent.operation.startswith('opreturn_'):
            n = int(intent.operation.split('_')[1])
            if intent.inputs or intent.name_op or intent.outputs != ({'data': payload(n).hex()},):
                raise Stop('EXACT_T1B_PAYLOAD')
        self.require_preparation_capacity(intent)
        self.network()
        policy = self.policy()
        if intent.exact_input:
            # Seal revoke returns its single input less exactly 50000 sat.
            validate_outputs(intent.outputs)
            self.network()
            raw = self.rpc_for_builder('createrawtransaction', list(intent.inputs), list(intent.outputs))
            signed = self.rpc_for_builder('signrawtransactionwithwallet', raw, wallet=intent.role)
            if signed.get('complete') is not True:
                raise Stop('INCOMPLETE_SIGNATURE')
            raw = signed['hex']
        else:
            raw = build_signed(self.rpc_for_builder, self.network, intent.role,
                list(intent.inputs), list(intent.outputs), rate_sat_vb=FIXED_FEE_SAT_VB,
                vsize_cap=self.size_cap(intent.operation),
                fee_cap=coins(self.fee_cap(intent.operation)), name_op=intent.name_op)
        decoded, fee = self.inspect(raw, intent)
        if self.clock() - self.step_start >= PREPARATION_S:
            raise Stop('PREPARATION_DEADLINE')
        if self.fees + fee > budget()['t1_fee_caps_sat'] + budget()['t1b_fee_caps_sat']:
            raise Stop('TOTAL_FEE_BOUND')
        descriptor = {'source': self.source, 'operation': intent.operation, 'mode': mode, 'raw_hex': raw,
                      'raw_sha256': sha(bytes.fromhex(raw)), 'decoded': json_safe(decoded),
                      'fee_sat': fee, 'policy': policy, 'network_genesis': GENESIS['main']}
        marker = self._gate('Meta_each_exact_raw_transaction', descriptor)
        # Admission time consumes the same preparation/step/shared clocks.
        self.bounds()
        if self.clock() - self.step_start >= PREPARATION_S:
            raise Stop('PREPARATION_DEADLINE')
        self.network()
        accepted = self.call(self.read, 'testmempoolaccept', [raw])
        self.record({'event': 'LOCAL_POLICY', 'operation': intent.operation, 'result': json_safe(accepted)})
        if len(accepted) != 1 or accepted[0].get('allowed') is not True:
            raise Stop('LOCAL_POLICY_REFUSAL_OR_UNKNOWN')
        self.bounds()
        if self.clock() - self.step_start >= PREPARATION_S:
            raise Stop('PREPARATION_DEADLINE')
        raw_hash, txid = descriptor['raw_sha256'], decoded['txid']
        if raw_hash in self.used_raw:
            raise Stop('NO_REBROADCAST')
        self.used_raw.add(raw_hash)  # before ambiguous RPC, never after success
        # Baseline from the final native pre-send tip observation above.
        # Blocks racing that read/send may shorten, never extend this window.
        self.broadcast_window = (*self.tip, txid, raw)
        self.record({'event': 'BROADCAST_ATTEMPT', 'descriptor': descriptor, 'Meta_receipt_sha256': marker,
                     'broadcast_tip_height': self.tip[0], 'broadcast_tip_hash': self.tip[1],
                     'inclusion_limit_height': self.tip[0] + INCLUSION_BLOCKS})
        started, started_wall = self.clock(), self.wall()
        actual = self.call(self.broadcast, 'sendrawtransaction', raw, Decimal('.00300000'))
        if actual != txid:
            raise Stop('BROADCAST_TXID_MISMATCH')
        self.fees += fee
        peer_deadline = min(self.step_start + PREPARATION_S + PEER_S, started + PEER_S)
        self.phase_deadline, self.phase_reason = peer_deadline, 'PEER_DEADLINE_UNKNOWN'
        pool = self.call(self.read, 'getrawmempool')
        if txid not in pool:
            raise Stop('LOCAL_MEMPOOL_NOT_OBSERVED')
        self.record({'event': 'LOCAL_MEMPOOL', 'txid': txid,
                     'limitation': 'local presence does not prove remote peer acceptance'})
        if intent.operation == 'A_seal_revoke':
            if self.after_broadcast is None:
                raise Stop('REVOCATION_MEMPOOL_CONTROL_REQUIRED')
            self.after_broadcast(intent, txid)
        # Local presence never proves remote relay. Core may await a block
        # with UNKNOWN relay; T1b still requires remote_mempool evidence.
        peer_receipt = None
        block_receipt, block_evidence = None, None
        for _ in range(25 if self.peer is not None else 0):
            self.network()
            if self.clock() >= peer_deadline:
                break
            evidence = self.observe_peer({'txid': txid, 'raw_sha256': raw_hash,
                                          'deadline_monotonic': peer_deadline})
            self.bounds()
            if self.clock() >= peer_deadline:
                raise Stop('PEER_DEADLINE_UNKNOWN')
            if evidence.get('status') == 'refused':
                raise Stop('PEER_REFUSAL')
            if evidence.get('status') == 'observed':
                if evidence.get('txid') != txid or evidence.get('raw_sha256') != raw_hash:
                    raise Stop('PEER_BINDING')
                kind = evidence.get('evidence_kind')
                if (kind not in ('remote_mempool', 'remote_block') or
                    (mode == SERIES_MODE and kind != 'remote_mempool') or
                    not evidence.get('observer_label')):
                    raise Stop('PEER_EVIDENCE_KIND')
                observed = datetime.fromisoformat(evidence['observed_at_utc'])
                if observed.utcoffset() is None or observed.utcoffset().total_seconds() != 0:
                    raise Stop('PEER_EVIDENCE_TIME')
                if not started_wall <= observed.timestamp() <= self.wall():
                    raise Stop('PEER_EVIDENCE_TIME')
                # Authenticated external observer receipt, not local inv/getdata.
                if kind == 'remote_block' and (not digest(evidence.get('block_hash')) or
                                              type(evidence.get('height')) is not int):
                    raise Stop('PEER_BLOCK_BINDING')
                receipt = self._gate('remote_peer_evidence', {'source': self.source,
                    'operation': intent.operation, 'mode': mode,
                    'broadcast_utc_epoch': started_wall, 'evidence': evidence})
                self.bounds()
                if self.clock() >= peer_deadline:
                    raise Stop('PEER_DEADLINE_UNKNOWN')
                if kind == 'remote_mempool':
                    peer_receipt = receipt
                    self.record({'event': 'PEER_OBSERVED', 'evidence': evidence})
                else:
                    block_receipt, block_evidence = receipt, evidence
                    self.record({'event': 'PEER_BLOCK_OBSERVED', 'evidence': evidence,
                                 'receipt_sha256': receipt})
                break
            if mode == CORE_MODE and evidence.get('status') in ('pending', 'unknown', 'absent'):
                # Explicit absence needs no 120-second peer wait. This is not
                # acceptance of evidence; inclusion must still validate below.
                if set(evidence) != {'status'}:
                    raise Stop('PEER_ABSENCE_SCHEMA')
                break
            if evidence.get('status') != 'pending':
                raise Stop('PEER_UNKNOWN')
            self.pause(min(10, max(0, peer_deadline - self.clock())))
        if peer_receipt is None:
            if mode == SERIES_MODE:
                raise Stop('PEER_DEADLINE_UNKNOWN')
            self.record({'event': 'REMOTE_MEMPOOL_UNKNOWN', 'status': 'UNKNOWN',
                         'operation': intent.operation, 'mode': mode, 'txid': txid,
                         'raw_sha256': raw_hash, 'observer_absent': self.peer is None})
        # Core's missing receipt must not start a fresh inclusion allowance.
        inclusion_deadline = min(self.step_start + 1500,
                                 (started if mode == CORE_MODE else self.clock()) + 1320)
        self.phase_deadline, self.phase_reason = inclusion_deadline, 'INCLUSION_DEADLINE'
        for _ in range(265):
            self.network()
            if self.clock() >= inclusion_deadline:
                break
            tx = self.call(self.read, 'getrawtransaction', txid, True)
            if tx.get('confirmations', 0) < 0:
                raise Stop('REORG')
            if tx.get('confirmations', 0) >= 1:
                if intent.operation == 'A_seal_revoke' and tx['confirmations'] != 1:
                    raise Stop('ONE_BLOCK_BOUNDARY_NOT_OBSERVED')
                block_hash = tx.get('blockhash')
                header = self.call(self.read, 'getblockheader', block_hash)
                height = header['height']
                if not self.broadcast_window[0] < height <= self.broadcast_window[0] + INCLUSION_BLOCKS:
                    raise Stop('SIX_BLOCK_INCLUSION_STOP')
                if self.call(self.read, 'getblockhash', height) != block_hash:
                    raise Stop('REORG')
                exact = self.call(self.read, 'getrawtransaction', txid, False, block_hash)
                block = self.call(self.read, 'getblock', block_hash, 2)
                if exact != raw or not any(x.get('txid') == txid for x in block['tx']):
                    raise Stop('EXACT_INCLUSION_MISMATCH')
                if block_evidence is not None and (block_evidence['block_hash'] != block_hash or
                                                    block_evidence['height'] != height):
                    raise Stop('PEER_BLOCK_BINDING')
                self.anchors.append((height, block_hash))
                self.network()
                self.bounds()
                if self.clock() >= inclusion_deadline:
                    raise Stop('INCLUSION_DEADLINE')
                row = {'operation': intent.operation, 'mode': mode, 'txid': txid, 'raw_sha256': raw_hash,
                       'fee_sat': fee, 'vsize': decoded['vsize'], 'weight': decoded['weight'],
                       'height': height, 'block_hash': block_hash, 'header': json_safe(header),
                       'coinbase': json_safe(block['tx'][0]), 'auxpow': json_safe(block.get('auxpow')),
                       'miner_attribution': 'UNKNOWN: coinbase/AuxPoW labels are not authenticated identity',
                       'peer_receipt_sha256': peer_receipt,
                       'remote_mempool_status': 'OBSERVED' if peer_receipt else 'UNKNOWN',
                       'block_receipt_sha256': block_receipt, 'broadcast_monotonic': started,
                       'broadcast_at_utc': datetime.fromtimestamp(started_wall, timezone.utc).isoformat(),
                       'inclusion_monotonic': self.clock(), 'status': 'INCLUDED_ACTIVE_AT_OBSERVATION'}
                self.record({'event': 'INCLUSION', 'result': row})
                self.rows.append(row)
                self.index += 1
                self.broadcast_window = None
                self.step_start = None
                self.phase_deadline, self.phase_reason = None, None
                return row
            self.pause(min(10, max(0, inclusion_deadline - self.clock())))
        raise Stop('INCLUSION_DEADLINE')


def json_safe(value):
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value
