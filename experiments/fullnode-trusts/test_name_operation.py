import json
import unittest
from decimal import Decimal
from unittest.mock import patch
import name_operation as names
from exact_json import dumps, satoshis
from funding import T1_SIZES, T1_FEE_CAPS
from transaction import build_signed

class NameBounds(unittest.TestCase):
    def test_exact_chain_binding_without_transport(self):
        for op in ('name_firstupdate', 'name_update'):
            for chain, cap, fee in [('main',1024,204800),('regtest',801,160200)]:
                with patch.object(names,'build_signed',return_value='fixture') as build:
                    self.assertEqual(names.build_companion_name_signed(None,lambda:{'chain':chain},'fixture',[],[],name_op={'op':op},regtest_vsize_cap=801,regtest_fee_cap_sat=160200),'fixture')
                    self.assertEqual(build.call_args.kwargs['vsize_cap'],cap)
                    self.assertEqual(satoshis(build.call_args.kwargs['fee_cap']),fee)
                    self.assertEqual(build.call_args.kwargs['rate_sat_vb'],200)
        self.assertEqual([T1_SIZES[k] for k in ('fund_B','A_name_new','A_grant_anchor')],[230,252,534])
        self.assertEqual(T1_FEE_CAPS['A_name_firstupdate'],102800)

    def test_no_broader_operation_or_network(self):
        for op in ('name_new','anchor','fund_B',None):
            with self.assertRaises(ValueError):
                names.build_companion_name_signed(None,lambda:{'chain':'main'},'',[],[],name_op={'op':op},regtest_vsize_cap=1024,regtest_fee_cap_sat=204800)
        for cap, fee in [(True,204800),(1025,204800),(1024,204801),(1024,200.0)]:
            with self.assertRaises(ValueError):
                names.build_companion_name_signed(None,lambda:{'chain':'regtest'},'',[],[],name_op={'op':'name_update'},regtest_vsize_cap=cap,regtest_fee_cap_sat=fee)

    def test_exact_decimal_wire(self):
        amount=Decimal('0.00204800')
        self.assertEqual(dumps({'amount':amount}),'{"amount":0.00204800}')
        self.assertEqual(json.loads(dumps({'amount':amount}),parse_float=Decimal)['amount'],amount)
        for amount in (Decimal('0.00000001'),Decimal('20999999.99999999')):
            self.assertEqual(satoshis(json.loads(dumps(amount),parse_float=Decimal)),satoshis(amount))
        for amount in (0.002048,Decimal('0.000000001'),True,Decimal('NaN')):
            with self.assertRaises(ValueError): satoshis(amount)
        with self.assertRaises(ValueError):dumps({'amount':0.002048})

    def test_signed_fee_and_size_boundaries(self):
        def attempt(size, funded, fee):
            calls=[]
            def rpc(method,*args,**kwargs):
                calls.append(method)
                if method=='createrawtransaction':return '00'
                if method=='namerawtransaction':return {'hex':'00'}
                if method=='fundrawtransaction':return {'hex':'00','fee':Decimal(funded)/100000000}
                if method=='signrawtransactionwithwallet':return {'hex':'00','complete':True}
                if method=='decoderawtransaction':return {'vsize':size,'vin':[{'txid':'00'*32,'vout':0}],'vout':[{'value':Decimal(1000000-fee)/100000000}]}
                if method=='getrawtransaction':return {'vout':[{'value':Decimal('0.01')}]}
                if method=='testmempoolaccept':return [{'allowed':True}]
                raise AssertionError(method)
            result=names.build_companion_name_signed(rpc,lambda:{'chain':'main'},'fixture',[],[],name_op={'op':'name_update'},regtest_vsize_cap=1,regtest_fee_cap_sat=1)
            return result,calls
        self.assertEqual(attempt(1024,204800,204800)[0],'00')
        for args in [(1025,204800,204800),(1024,204801,204800),(1024,204800,204801),(1024,0,-1)]:
            with self.assertRaises(RuntimeError):attempt(*args)

if __name__=='__main__': unittest.main()
