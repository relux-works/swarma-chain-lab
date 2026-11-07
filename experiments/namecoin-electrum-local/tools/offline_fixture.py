"""In-process upstream tests with synthetic data. No sockets or chain data."""
import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import electrumx
from electrumx.lib.coins import Namecoin, Coin
from electrumx.lib.hash import double_sha256
from electrumx.lib.script import Script, OpCodes
from electrumx.server.env import Env
from electrumx.server.session import NameIndexAuxPoWElectrumX
from electrumx.server.storage import db_class

CHECKS = []
def check(label, condition):
    if not condition:
        raise AssertionError(label)
    CHECKS.append(label)

class FixtureSession(NameIndexAuxPoWElectrumX):
    """Avoid transport construction; only backing data and accounting are synthetic."""
    def __init__(self, history=()):
        self.coin = Namecoin
        self.env = SimpleNamespace(coin=Namecoin, drop_client=None)
        self.sv_seen = False
        self.sv_negotiated = asyncio.Event()
        self.logger = logging.getLogger('fixture')
        self.history = list(history)
        self.calls = []
    def bump_cost(self, cost):
        pass
    async def phandle_scripthash_get_history(self, scripthash):
        self.calls.append(('history', scripthash))
        return [dict(x) for x in self.history]
    async def phandle_transaction_get(self, txid, verbose=False):
        self.calls.append(('tx', txid))
        return '00'  # Deliberately not a valid transaction or proof.
    async def phandle_transaction_merkle(self, txid, height):
        self.calls.append(('merkle', txid, height))
        return {'block_height': height, 'merkle': [], 'pos': 0}
    async def phandle_block_header(self, height, cp_height=0):
        self.calls.append(('header', height, cp_height))
        return {'header': '00' * 80, 'branch': [], 'root': '00' * 32}

async def protocol_checks(scripthash):
    for version in ('1.4.1', '1.4.3'):
        s = FixtureSession()
        reply = await s.phandle_server_version('offline-fixture', version)
        check('negotiate-' + version, reply[1] == version)
        has_proof = 'blockchain.name.get_value_proof' in s.request_handlers
        check('proof-gate-' + version, has_proof == (version == '1.4.3'))
        check('legacy-history-' + version, 'blockchain.scripthash.get_history' in s.request_handlers)
    updates = [{'tx_hash': f'{i:064x}', 'height': h}
               for i, h in enumerate((100, 200, 300), start=1)]
    s = FixtureSession(updates)
    s.set_request_handlers((1, 4, 3))
    # The production bundler is called; its data providers are synthetic.
    result = await s.request_handlers['blockchain.name.get_value_proof'](scripthash, 200)
    check('proof-checkpoint-cutoff', [x['height'] for x in result[scripthash]] == [300, 200])
    check('proof-checkpoint-header', s.calls[-1] == ('header', 200, 200))
    check('proof-result-shape', all('tx' in x and 'tx_merkle' in x and 'tx_hash' not in x for x in result[scripthash]))
    s = FixtureSession([{'tx_hash': '11'*32, 'height': 1}, {'tx_hash': '22'*32, 'height': 40002}])
    result = await s.phandle_name_get_value_proof(scripthash, 0)
    check('proof-expiration-gap-cutoff', len(result[scripthash]) == 1)
    s = FixtureSession()
    result = await s.phandle_name_get_value_proof(scripthash, 0)
    check('empty-history-shape-only', result == {scripthash: []})


def main():
    check('pinned-upstream-version', electrumx.__version__ == '2.0.1')
    check('explicit-namecoin-class', Coin.lookup_coin_class('Namecoin', 'mainnet') is Namecoin)
    name = b'd/offline-fixture'
    owner = bytes.fromhex('76a914' + '11'*20 + '88ac')
    push = Script.push_data
    update = bytes([Namecoin.OP_NAME_UPDATE]) + push(name) + push(b'{"test":1}') + bytes([OpCodes.OP_2DROP, OpCodes.OP_DROP]) + owner
    first = bytes([Namecoin.OP_NAME_FIRSTUPDATE]) + push(name) + push(b'not-a-real-salt') + push(b'{}') + bytes([OpCodes.OP_2DROP, OpCodes.OP_2DROP]) + owner
    index_script = bytes([Namecoin.OP_NAME_UPDATE]) + push(name) + b'\x00\x6d\x75\x6a'
    check('canonical-name-index-script', Namecoin.build_name_index_script(name) == index_script)
    for label, script in [('firstupdate', first), ('update', update)]:
        normalized, suffix = Namecoin.split_name_script(script)
        check(label + '-normalizes-name', normalized == index_script)
        check(label + '-preserves-owner-suffix', suffix == owner)
        check(label + '-address-index', Namecoin.hashX_from_script(script) == Namecoin.hashX_from_script(owner))
        check(label + '-name-index', Namecoin.name_hashX_from_script(script) == hashlib.sha256(index_script).digest()[:11])
    check('ordinary-output-no-name-index', Namecoin.name_hashX_from_script(owner) is None)
    check('distinct-name-separate-index', Namecoin.build_name_index_script(b'd/another') != index_script)
    # Structurally parseable AuxPoW only: no valid work/chain/consensus is asserted.
    base = (0x101).to_bytes(4, 'little') + bytes(76)
    parent_tx = bytes.fromhex('0100000001') + bytes(32) + bytes.fromhex('ffffffff00ffffffff0100000000000000000000000000')
    aux = parent_tx + bytes(32) + b'\x00' + bytes(4) + b'\x00' + bytes(4) + bytes(80)
    header = base + aux
    check('auxpow-variable-header-parsing', Namecoin.block_header(header + b'\x00', 1) == header)
    check('auxpow-hash-excludes-extension', Namecoin.header_hash_rev(header) == double_sha256(base))
    check('auxpow-checkpoint-truncation', NameIndexAuxPoWElectrumX.truncate_auxpow_single(SimpleNamespace(coin=Namecoin), header.hex()) == base.hex())
    scripthash = hashlib.sha256(index_script).digest()[::-1].hex()
    asyncio.run(protocol_checks(scripthash))
    config = {}
    for line in Path(__file__).resolve().parent.parent.joinpath('config/preparation.env').read_text().splitlines():
        if line and not line.startswith('#'):
            key, value = line.split('=', 1); config[key] = value
    config.update(DB_DIRECTORY=os.path.join(os.environ['TMPDIR'], 'synthetic-index'), DAEMON_URL='http://synthetic:synthetic@127.0.0.1:1/')
    with patch.dict(os.environ, config, clear=False):
        env = Env()
    check('config-namecoin-mainnet', env.coin is Namecoin)
    check('config-no-listeners', not env.services and not env.report_services)
    check('config-no-peer-discovery', env.peer_discovery == Env.PD_OFF and not env.peer_announce)
    check('config-auxpow-message-limit', env.max_send == 10000000)
    backend = db_class('leveldb')
    dbpath = os.path.join(os.environ['TMPDIR'], 'tiny-fixture-db')
    db = backend(dbpath, for_sync=False)
    with db.write_batch() as batch:
        batch.put(b'synthetic-only', b'fixture-value')
    db.close()
    db = backend(dbpath, for_sync=False)
    check('native-db-reopen', db.get(b'synthetic-only') == b'fixture-value')
    db.close()
    print(json.dumps({'scope': 'SYNTHETIC_IN_PROCESS_ONLY', 'passed': len(CHECKS), 'checks': CHECKS,
                      'scripthash': scripthash, 'live_rpc': False, 'listener': False,
                      'valid_consensus_proof_tested': False, 'full_index_tested': False}, indent=2))

if __name__ == '__main__':
    main()
