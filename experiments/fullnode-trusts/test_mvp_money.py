"""Causal monetary controls on the live MVP builder/anchor route; no chain."""
import copy, hashlib, json, sys, unittest
from decimal import Decimal, Inexact, Rounded, localcontext
import exact_json as money
import seal_anchor as a
import mainnet
import name_operation
from transaction import build_signed


def issuer():
    payload=bytes([111])+b'\x11'*20
    raw=payload+hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n=int.from_bytes(raw,'big'); out=''
    while n:
        n,r=divmod(n,58);out='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[r]+out
    return {'address':out,'script':'76a914'+'11'*20+'88ac'}


def fixture():
    who=issuer();txid='00'*32
    point={'txid':txid,'vout':0,'script':who['script'],'value_sat':1234567}
    ledger={'reserved_sat':87500000,'prior_fee_sat':1000000,'name_count':2,'other_locked_sat':0}
    bounds={'accepted_epoch':1000,'deadline_epoch':3000,'step_started_epoch':1100,'broadcast_tip_height':1,'broadcast_tip_hash':'ab'*32}
    script=bytes.fromhex(who['script'])
    raw=(b'\x02\0\0\0'+b'\x01'+bytes(32)+bytes(4)+b'\x01\x51'+b'\xff'*4+b'\x02'+
         (100000).to_bytes(8,'little')+bytes([len(script)])+script+
         (1088567).to_bytes(8,'little')+bytes([len(script)])+script+bytes(4)).hex()
    prev={txid:{'vout':[{'value':Decimal('0.01234567'),'scriptPubKey':{'hex':who['script']}}]}}
    return who,point,ledger,bounds,raw,prev


class MonetaryRoute(unittest.TestCase):
    def test_confirmed_coin_money_refused_before_admission_and_retry(self):
        import test_mainnet as controls
        bads = [None, [], {}, {'confirmations': 1},
                {'confirmations': True, 'value': Decimal('.1')}]
        bads += [{'confirmations': 12, 'value': v} for v in
                 (None, True, 0.1, Decimal('NaN'), Decimal('1e1000000000'),
                  Decimal('1e-1000000000'), Decimal('21000000.00000001'),
                  Decimal('0.10000000000000000000000000001'), Decimal('.2'))]
        for bad in bads:
            with self.subTest(coin=str(bad)):
                h = controls.Tests(); h.setup_control()
                original = h.rpc
                def transport(method, *args, **kw):
                    value = original(method, *args, **kw)
                    return bad if method == 'gettxout' else value
                h.c.read._transport = transport
                with self.assertRaises(mainnet.Stop): h.c.run_next(h.intent())
                self.assertTrue(h.c.stopped)
                self.assertEqual(h.sends(), [])
                self.assertFalse(any(kind == 'Meta_each_exact_raw_transaction' for kind, _ in h.gates))
                calls = h.c.calls
                with self.assertRaisesRegex(mainnet.Stop, 'TERMINAL_NO_RETRY'):
                    h.c.run_next(h.intent())
                self.assertEqual(h.c.calls, calls)
        neighbor = controls.Tests(); neighbor.setup_control()
        self.assertEqual(neighbor.c.run_next(neighbor.intent())['fee_sat'], 56800)
        self.assertEqual(len(neighbor.sends()), 1)

    def test_live_anchor_intent_decode_and_conservation_under_contexts(self):
        who,point,ledger,bounds,raw,prev=fixture()
        for precision in (1,6,28,100):
            with self.subTest(precision=precision),localcontext() as ctx:
                ctx.prec=precision;ctx.traps[Inexact]=ctx.traps[Rounded]=True
                plan=a.prepare('seal',b'public fixture',who,point,ledger,bounds,now=1101)
                self.assertEqual(money.satoshis(plan.intent().outputs[0][who['address']]),100000)
                result=a.inspect(plan,b'public fixture',raw,prev,now=1101)
                self.assertEqual((result['fee_sat'],result['input_sat'],result['output_sat']),(46000,1234567,1188567))
                self.assertEqual(result['input_sat'],result['output_sat']+result['fee_sat'])
                self.assertFalse(result['spend_authorized'])

    def test_anchor_prevout_unknown_and_fractional_values_refused(self):
        who,point,ledger,bounds,raw,prev=fixture()
        plan=a.prepare('seal',b'public fixture',who,point,ledger,bounds,now=1101)
        for value in (None,True,0.01234567,Decimal('NaN'),Decimal('sNaN'),Decimal('Infinity'),
                      Decimal('0.0123456700000000000000000000001'),Decimal('21000000.00000001'),
                      Decimal('1e1000000000'),Decimal('1e-1000000000')):
            with self.subTest(value=str(value)):
                bad=copy.deepcopy(prev);bad[point['txid']]['vout'][0]['value']=value
                with self.assertRaises((ValueError,mainnet.Stop)):
                    a.inspect(plan,b'public fixture',raw,bad,now=1101)

    def test_consensus_bounds_and_exact_neighbors(self):
        for precision in (1,6,28):
            with localcontext() as ctx:
                ctx.prec=precision;ctx.traps[Inexact]=ctx.traps[Rounded]=True
                for value,expected in [('0.09999999',9999999),('0.1',10000000),('0.10000001',10000001),
                                       ('20999999.99999999',2099999999999999),('21000000',2100000000000000),
                                       ('0e1000000000',0),('1.'+'0'*100000,100000000)]:
                    self.assertEqual(money.satoshis(Decimal(value)),expected)
                    self.assertEqual(mainnet.sat(Decimal(value)),expected)
                for value in ('1e1000000000','1e-1000000000','21000000.00000001','0.10000000000000000000000000001'):
                    for convert in (money.satoshis,mainnet.sat):
                        with self.assertRaises(ValueError):convert(Decimal(value))

    def test_builder_stops_before_exact_raw_admission_for_bad_money(self):
        bads=(None,True,0.1,Decimal('NaN'),Decimal('Infinity'),Decimal('-1'),Decimal('1e1000000000'),
              Decimal('1e-1000000000'),Decimal('21000000.00000001'),Decimal('0.10000000000000000000000000001'))
        for field in ('fee_cap','requested_output','funded_fee','prevout','signed_output'):
            for value in bads:
                calls=[]
                def rpc(method,*args,**kw):
                    calls.append(method)
                    if method=='createrawtransaction':return '00'
                    if method=='fundrawtransaction':return {'hex':'00','fee':value if field=='funded_fee' else Decimal('.00046')}
                    if method=='signrawtransactionwithwallet':return {'hex':'00','complete':True}
                    if method=='decoderawtransaction':return {'vsize':200,'vin':[{'txid':'00'*32,'vout':0}], 'vout':[{'value':value if field=='signed_output' else Decimal('.09954')}]}
                    if method=='getrawtransaction':return {'vout':[{'value':value if field=='prevout' else Decimal('.1')}]}
                    if method=='testmempoolaccept':return [{'allowed':True}]
                    raise AssertionError(method)
                with self.subTest(field=field,value=str(value)):
                    with self.assertRaises((ValueError,RuntimeError)):
                        build_signed(rpc,lambda:None,'fixture',[],[{'fixture':value if field=='requested_output' else Decimal('.09954')}],
                                     rate_sat_vb=200,vsize_cap=230,fee_cap=value if field=='fee_cap' else Decimal('.00046'))
                    self.assertNotIn('testmempoolaccept',calls)
                    self.assertNotIn('sendrawtransaction',calls)
                    if field in ('fee_cap','requested_output'):self.assertEqual(calls,[])

    def test_numeric_wire_and_named_caps_ignore_decimal_context(self):
        from unittest.mock import patch
        for precision in (1,6,28):
            with localcontext() as ctx:
                ctx.prec=precision;ctx.traps[Inexact]=ctx.traps[Rounded]=True
                value=Decimal('20999999.99999999')
                wire=money.dumps({'value':value})
                self.assertEqual(wire,'{"value":20999999.99999999}')
                self.assertEqual(json.loads(wire,parse_float=Decimal)['value'],value)
                for op in ('name_firstupdate','name_update'):
                    with patch.object(name_operation,'build_signed',return_value='fixture') as call:
                        name_operation.build_companion_name_signed(None,lambda:{'chain':'main'},'fixture',[],[],name_op={'op':op},regtest_vsize_cap=1,regtest_fee_cap_sat=1)
                        self.assertEqual((call.call_args.kwargs['vsize_cap'],call.call_args.kwargs['rate_sat_vb'],money.satoshis(call.call_args.kwargs['fee_cap'])),(1024,200,204800))
        for value in (0.1,Decimal('NaN'),Decimal('1e1000000000')):
            with self.assertRaises(ValueError):money.dumps({'value':value})

if __name__=='__main__':unittest.main(verbosity=2)
