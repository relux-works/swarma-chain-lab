"""Regression reproducer for the pinned upstream variable-header array path.

All bytes and storage are synthetic. No consensus-valid header is claimed.
The assertion expresses the required correct response, so the affected upstream
version exits nonzero. Keep that failure as a qualification blocker.
"""
import asyncio
import json
from types import SimpleNamespace
from electrumx.lib.coins import Namecoin
from electrumx.server.session import NameIndexAuxPoWElectrumX

class SyntheticHeaderDB:
    # Dynamic offsets, just like DB.dynamic_header_offset's absolute offsets.
    lengths = [80] * 100 + [160, 240]
    async def read_headers(self, start_height, count):
        assert (start_height, count) == (100, 2)
        return b'A' * 160 + b'B' * 240, 2
    def header_offset(self, height):
        return sum(self.lengths[:height])

class HeaderSession(NameIndexAuxPoWElectrumX):
    def __init__(self):
        self.coin = Namecoin
        self.db = SyntheticHeaderDB()
        self.protocol_tuple = (1, 4, 1)
    def bump_cost(self, cost):
        pass
    async def _merkle_proof(self, cp_height, height):
        return {'branch': [], 'root': '00' * 32}

async def main():
    session = HeaderSession()
    result = await session.phandle_block_headers(100, 2, 101)
    expected = (b'A' * 80 + b'B' * 80).hex()
    actual = result['hex']
    print(json.dumps({'scope': 'SYNTHETIC_UPSTREAM_REGRESSION', 'protocol': '1.4.1',
                      'requested_start': 100, 'requested_count': 2, 'cp_height': 101,
                      'returned_count_field': result['count'],
                      'expected_truncated_bytes': len(expected)//2,
                      'actual_truncated_bytes': len(actual)//2,
                      'expected_header_markers': ['A', 'B'],
                      'actual_80_byte_markers': [chr(bytes.fromhex(actual)[i]) for i in range(0,len(actual)//2,80)],
                      'live_data': False}, indent=2), flush=True)
    assert actual == expected, 'checkpoint-covered variable headers must retain each requested header boundary'

if __name__ == '__main__':
    asyncio.run(main())
