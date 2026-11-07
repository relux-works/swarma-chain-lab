"""Synthetic in-process protocol/DB boundary tests. No listener or real chain.

Runs against either the exact upstream source or its separately applied patch.
The expected values come from individual generated headers, not the slicer.
"""
import asyncio
import hashlib
import json
from types import SimpleNamespace
from aiorpcx import RPCError
from electrumx.lib.coins import Namecoin, Bitcoin
from electrumx.lib.merkle import Merkle
from electrumx.server.db import DB
from electrumx.server.db_util import pack_dyn_header_offset
from electrumx.server.session import ElectrumX, NameIndexAuxPoWElectrumX

RESULTS = []

class MemoryFile:
    def __init__(self, data):
        self.data = data
    def read(self, offset, size):
        return self.data[offset:offset + size]


def make_headers(coin, size=2200):
    result = []
    for height in range(size):
        # Unique base bytes distinguish slices even when lengths happen to match.
        base = (1).to_bytes(4, 'little') + hashlib.sha256(str(height).encode()).digest() * 2 + bytes(12)
        if coin is Namecoin and height % 3:
            base = (0x101).to_bytes(4, 'little') + base[4:]
            # Structurally parseable AuxPoW with variable parent coinbase scripts.
            script = b'x' * (height % 61)
            tx = (bytes.fromhex('0100000001') + bytes(32) + bytes.fromhex('ffffffff')
                  + bytes([len(script)]) + script + bytes.fromhex('ffffffff0100000000000000000000000000'))
            base += tx + bytes(32) + b'\x00' + bytes(4) + b'\x00' + bytes(4) + bytes(80)
        result.append(base)
    return result


def make_db(coin, headers, damage=None):
    db = DB.__new__(DB)
    db.coin, db.db_height = coin, len(headers) - 1
    offsets = [0]
    for header in headers:
        offsets.append(offsets[-1] + len(header))
    db.headers_file = MemoryFile(b''.join(headers))
    db.headers_offsets_file = MemoryFile(b''.join(pack_dyn_header_offset(x) for x in offsets))
    # Use the pinned production DB's dynamic/static offset implementations.
    db.header_offset = db.dynamic_header_offset if coin is Namecoin else coin.static_header_offset
    db.header_len = db.dynamic_header_len if coin is Namecoin else coin.static_header_len
    hashes = [coin.header_hash_rev(h) for h in headers]
    async def branch_and_root(length, height):
        return Merkle().branch_and_root(hashes[:length], height)
    db.header_branch_and_root = branch_and_root
    if damage:
        original = db.read_headers
        async def damaged(start, count):
            data, actual = await original(start, count)
            if damage == 'short': return data[:-1], actual
            if damage == 'extra': return data + b'x', actual
            if damage == 'count-more': return data, actual + 1
            if damage == 'count-less': return data, actual - 1
            if damage == 'empty-extra': return b'x', 0
            raise AssertionError(damage)
        db.read_headers = damaged
    return db

class SessionState:
    def __init__(self, coin, headers, protocol, damage=None):
        self.coin = coin
        self.db = make_db(coin, headers, damage)
        self.session_mgr = SimpleNamespace(raw_header=self.db.raw_header)
        self.protocol_tuple = protocol
        self.costs = []
    def bump_cost(self, value):
        self.costs.append(value)

class NMCSession(SessionState, NameIndexAuxPoWElectrumX):
    pass
class BTCSession(SessionState, ElectrumX):
    pass


def record(label, ok, detail=None):
    RESULTS.append({'case': label, 'pass': bool(ok), **({'detail': detail} if detail else {})})

async def valid_case(coin, headers, version, start, count, cp):
    label = f'{coin.__name__}/{version}/start={start}/count={count}/cp={cp}'
    session = (NMCSession if coin is Namecoin else BTCSession)(coin, headers, version)
    try:
        reply = await session.phandle_block_headers(start, count, cp)
        selected = headers[start:start + min(count, session.MAX_CHUNK_SIZE)]
        truncate = coin is Namecoin and version >= (1, 4, 1) and cp != 0
        expected = [h[:80] if truncate else h for h in selected]
        assert reply['count'] == len(expected), 'returned count'
        assert reply['max'] == 2016, 'max field'
        if version >= (1, 6):
            assert 'hex' not in reply and reply['headers'] == [h.hex() for h in expected], 'array boundaries'
            assert len(reply['headers']) == reply['count'], 'array/count agreement'
        else:
            assert 'headers' not in reply and reply['hex'] == b''.join(expected).hex(), 'concatenated bytes'
        if cp and selected:
            proof = await session._merkle_proof(cp, start + len(selected) - 1)
            assert all(reply[k] == proof[k] for k in ('branch','root')), 'checkpoint proof'
        else:
            assert 'branch' not in reply and 'root' not in reply, 'no proof for zero count/checkpoint'
        assert len(session.costs) == 1, 'cost charged once'
        assert session.costs[0] == count / 50 + bool(cp and selected), 'existing cost semantics'
        record(label, True)
    except Exception as exc:
        record(label, False, type(exc).__name__ + ': ' + str(exc))

async def main():
    for coin in (Namecoin, Bitcoin):
        headers = make_headers(coin)
        record(coin.__name__ + '/source-header-mode', coin.STATIC_BLOCK_HEADERS == (coin is Bitcoin))
        if coin is Namecoin:
            record('Namecoin/structural-AuxPoW-boundaries', all(coin.block_header(h + b'\x00', i) == h for i,h in enumerate(headers[:110])))
        for version in ((1,4,0), (1,4,1), (1,4,3), (1,6)):
            cases = [(0,2,0), (0,2,1), (1,3,0), (1,3,3), (100,2,0),
                     (100,2,101), (100,2,102), (100,1,100), (100,1,2199),
                     (2198,8,2199), (2200,2,0), (2200,2,2199),
                     (100,0,0), (2200,0,2199), (1,2017,2016),
                     (1,10**9,2016)]
            for start,count,cp in cases:
                await valid_case(coin,headers,version,start,count,cp)
            # Production checkpoint validation, including first/last/above-tip.
            for cp in (99,100,2200):
                s = (NMCSession if coin is Namecoin else BTCSession)(coin,headers,version)
                try:
                    await s.phandle_block_headers(100,2,cp)
                except RPCError:
                    record(f'{coin.__name__}/{version}/invalid-checkpoint={cp}', True)
                else:
                    record(f'{coin.__name__}/{version}/invalid-checkpoint={cp}', False)
            for args in ((-1,2,0),(100,-1,0),(100,2,-1),('bad',2,0),(100,None,0)):
                s = (NMCSession if coin is Namecoin else BTCSession)(coin,headers,version)
                try:
                    await s.phandle_block_headers(*args)
                except RPCError:
                    record(f'{coin.__name__}/{version}/invalid-arguments={args}', True)
                else:
                    record(f'{coin.__name__}/{version}/invalid-arguments={args}', False)
        # Single-header truncation is an independent unchanged control.
        for version in ((1,4,0),(1,4,1),(1,6)):
            for cp in (0,100,2199):
                s = (NMCSession if coin is Namecoin else BTCSession)(coin,headers,version)
                r = await s.phandle_block_header(100,cp)
                data = r if cp == 0 else r['header']
                expected = headers[100][:80] if coin is Namecoin and version >= (1,4,1) and cp else headers[100]
                record(f'{coin.__name__}/{version}/single/cp={cp}', data == expected.hex())
        # Arrays must not claim success with short, extra, or count-mismatched DB bytes.
        # Legacy cp=0 concatenation deliberately remains outside the patch scope.
        for damage in ('short','extra','count-more','count-less','empty-extra'):
            for version,cp in (((1,6),0),((1,4,1),2199)):
                if coin is Bitcoin and version < (1,6): continue
                s = (NMCSession if coin is Namecoin else BTCSession)(coin,headers,version,damage)
                try:
                    await s.phandle_block_headers(100,2,cp)
                except DB.DBError:
                    record(f'{coin.__name__}/{version}/{damage}/cp={cp}',True)
                else:
                    record(f'{coin.__name__}/{version}/{damage}/cp={cp}',False,'accepted inconsistent DB buffer')
    failures = [r for r in RESULTS if not r['pass']]
    print(json.dumps({'scope':'SYNTHETIC_HEADERS_REAL_PINNED_DB_AND_PROTOCOL_METHODS',
                      'total':len(RESULTS),'passed':len(RESULTS)-len(failures),'failed':len(failures),
                      'consensus_valid_chain':False,'listeners':False,'cases':RESULTS},indent=2),flush=True)
    raise SystemExit(bool(failures))

if __name__ == '__main__':
    asyncio.run(main())
