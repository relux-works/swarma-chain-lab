"""Synthetic symbols only. Valid signatures/consensus are stub premises.
Execute only selected verifier functions, never node/runtime entrypoints.
Usage inside offline namespace: python3 -B /source/offline-counterexamples.py /source/lab.py
"""
import ast,copy,hashlib,json,sys,time
from decimal import Decimal
from pathlib import Path

def run(path):
    text=Path(path).read_text();module=ast.parse(text)
    names={'canon','H','identity','txdata','pushes','verify_current','verify_at_tip','name_transition_error'}
    ns={'json':json,'hashlib':hashlib,'time':time,'Decimal':Decimal}
    exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]),str(path),'exec'),ns)
    fixed='name_transition_error' in ns
    state={'genesis':'public-synthetic-genesis'}
    for role in ['A','N']:
        state[role]={'name':'d/public-'+role,'address':'public-'+role+'-address','pubkey':'public-'+role+'-key','identity_txid':'identity-'+role}
    ns['STATE']=state;H=ns['H'];identity=ns['identity'];canon=ns['canon']
    state['policy']={'trusted_notary_identity_hashes':[H(identity('N'))]}
    rows={}
    for mode in ['separate','cosigned']:
        g={'chain_genesis':state['genesis'],'issuer':identity('A'),'not_before_height':1,'expires_height':100,'seal':{'txid':'seal-A','vout':0,'script':'script-A','value':'.02'}}
        issue={'txid':'issuance','height':10,'blockhash':'block10'}
        anchor={'txid':'attestation','height':11,'blockhash':'block11'} if mode=='separate' else copy.deepcopy(issue)
        s={'notary':identity('N'),'chain_genesis':state['genesis'],'grant_hash':H(g),'expires_height':100,'notary_seal':{'txid':'seal-N','vout':0,'script':'script-N','value':'.02'}}
        if mode=='separate':s['source_issuance']=copy.deepcopy(issue)
        f={'grant':g,'statement':s,'grant_signature':'synthetic-assumed-valid-A','notary_signature':'synthetic-assumed-valid-N','issuance':issue,'anchor':anchor,'mode':mode}
        def op(role,operation,value):return {'n':0,'value':'.01','scriptPubKey':{'nameOp':{'op':operation,'name':state[role]['name'],'value':canon(value).decode()},'address':state[role]['address'],'hex':'synthetic-name-script'}}
        txs={}
        for role in ['A','N']:
            txs['identity-'+role]={'confirmations':20,'vout':[op(role,'name_firstupdate',{'pubkey':state[role]['pubkey']})]}
            txs['seal-'+role]={'confirmations':20,'vout':[{'value':'.02','scriptPubKey':{'address':state[role]['address'],'hex':'script-'+role}}]}
        txs['issuance']={'confirmations':11,'blockhash':'block10','vin':[{'txid':'identity-A','vout':0}],'vout':[op('A','name_update',{'grant':H(g)} if mode=='separate' else {'grant':H(g),'mode':'cosigned'})]}
        if mode=='separate':txs['attestation']={'confirmations':10,'blockhash':'block11','vin':[{'txid':'identity-N','vout':0}],'vout':[op('N','name_update',{'attestation':H(s)})]}
        else:
            f['multisig']={'script':'aa','address':'synthetic-ms','funding':{'txid':'ms-funding','vout':0}}
            txs['ms-funding']={'confirmations':15,'vout':[{'scriptPubKey':{'address':'synthetic-ms'}}]}
            txs['issuance']['vin'].append({'txid':'ms-funding','vout':0,'scriptSig':{'hex':'000101010101aa'}})
            txs['issuance']['vout'].append({'scriptPubKey':{'hex':'6a40'+H(g)+H(s)}})
        original=copy.deepcopy(txs)
        trigger={'index':None,'changed':False,'calls':[],'owner':False,'spent':None,'seal_depth':20,'height':20}
        def rpc(method,*args,**kwargs):
            trigger['calls'].append([method,*args])
            if method=='getbestblockhash':result='new-tip' if trigger['changed'] else 'fixed-tip'
            elif method=='getblockcount':result=trigger['height']
            elif method=='getblockhash':result='block'+str(args[0])
            elif method=='name_show':result={'expired':False,'address': 'changed-owner' if trigger['owner'] else next(state[r]['address'] for r in ['A','N'] if state[r]['name']==args[0])}
            elif method=='getrawtransaction':result=copy.deepcopy(txs[args[0]])
            elif method=='verifymessage':result=True
            elif method=='createmultisig':result={'redeemScript':'aa','address':'synthetic-ms'}
            elif method=='gettxout':result=None if args[0]==trigger['spent'] else {'confirmations':txs[args[0]].get('confirmations',0)}
            else:raise AssertionError(method)
            if trigger['index']==len(trigger['calls']):trigger['changed']=True
            if trigger.get('identity_race') and method=='getrawtransaction' and args[0]=='identity-N':trigger['changed']=True;trigger['owner']=True
            return result
        ns['rpc']=rpc;verify=ns['verify_current']
        def reset():
            txs.clear();txs.update(copy.deepcopy(original));trigger.update(index=None,changed=False,calls=[],owner=False,spent=None,seal_depth=20,height=20,identity_race=False)
        def check(label,expected,reason=None,kwargs=None):
            got=verify(f,**(kwargs or {}));okay=got['status']==expected and (reason is None or got.get('reason')==reason)
            rows[mode+'/'+label]={'observed':got,'expected':expected,'expected_reason':reason,'pass':okay}
            assert okay,(label,got,expected,reason)
        reset();check('positive','ACCEPT');baseline_calls=len(trigger['calls'])
        targets=[('issuance','A','ISSUANCE')] + ([('attestation','N','ATTESTATION')] if mode=='separate' else [])
        for tx,role,prefix in targets:
            for field,bad,suffix in [('name','d/public-unrelated','NAME'),('address','public-unrelated-owner','OWNER')]:
                reset();sp=txs[tx]['vout'][0]['scriptPubKey'];(sp['nameOp'] if field=='name' else sp)[field]=bad
                check(tx+'_wrong_'+field,'REJECT' if fixed else 'ACCEPT',prefix+'_NAME_'+suffix if fixed else None)
            reset();txs[tx]['vin'][0]={'txid':'seal-'+role,'vout':0}
            check(tx+'_ordinary_input','REJECT' if fixed else 'ACCEPT',prefix+'_NAME_PREDECESSOR_COUNT' if fixed else None)
            reset();txs[tx]['vin'][0]={'txid':'identity-'+('N' if role=='A' else 'A'),'vout':0}
            check(tx+'_unrelated_named_input','REJECT' if fixed else 'ACCEPT',prefix+'_NAME_PREDECESSOR_NAME' if fixed else None)
            for variant in ['owner','generation','duplicate','multihop']:
                reset();mid=copy.deepcopy(txs['identity-'+role]);mid['vout'][0]['scriptPubKey']['nameOp']['op']='name_update';mid['vin']=[{'txid':'identity-'+role,'vout':0}];txs['middle']=mid;txs[tx]['vin'][0]={'txid':'middle','vout':0}
                if variant=='owner':mid['vout'][0]['scriptPubKey']['address']='outsider'
                if variant=='generation':mid['vout'][0]['scriptPubKey']['nameOp']['op']='name_firstupdate'
                if variant=='duplicate':txs[tx]['vin'].append({'txid':'identity-'+role,'vout':0})
                check(tx+'_predecessor_'+variant,'REJECT' if fixed and variant!='multihop' else 'ACCEPT')
            reset();txs[tx]['vout'].append(copy.deepcopy(txs[tx]['vout'][0]))
            check(tx+'_duplicate_name_operation','REJECT' if fixed else 'ACCEPT',prefix+'_NAME_OP_COUNT' if fixed else None)
        reset();trigger['identity_race']=True
        check('name_owner_changed_before_old_snapshot','UNAVAILABLE' if fixed else 'ACCEPT','CHAIN_CHANGED_DURING_VERIFICATION' if fixed else None)
        for role in ['A','N']:
            reset();txs['seal-'+role]['confirmations']=0
            check('unconfirmed_'+role+'_seal','REJECT' if fixed else 'ACCEPT','SEAL_CONFIRMATIONS' if fixed else None)
        if fixed:
            for role in ['A','N']:
                reset();txs['seal-'+role]['confirmations']=0
                check('unconfirmed_'+role+'_seal_minconf0','REJECT','SEAL_CONFIRMATIONS',{'minconf':0})
            for index in range(1,baseline_calls):
                reset();trigger['index']=index;check('tip_change_after_rpc_'+str(index),'UNAVAILABLE','CHAIN_CHANGED_DURING_VERIFICATION')
            reset();trigger['owner']=True;trigger['index']=3;check('tip_change_overrides_early_reject','UNAVAILABLE','CHAIN_CHANGED_DURING_VERIFICATION')
            reset();trigger['spent']='seal-A';check('grant_revoked','REJECT','GRANT_REVOKED')
            reset();trigger['spent']='seal-N';check('notary_withdrawn','REJECT','NOTARY_WITHDRAWN')
            reset();trigger['height']=100;check('expired','REJECT','EXPIRED_OR_PREMATURE')
            reset();check('offline','UNAVAILABLE','PROOF_UNAVAILABLE',{'online':False})
            reset();check('cached_offline','UNAVAILABLE','CURRENT_CHAIN_VIEW_UNAVAILABLE',{'online':False,'cached':{'observed_unix':int(time.time())}})
            reset();check('stale_age','UNAVAILABLE','STALE_PROOF',{'cached':{'observed_unix':int(time.time())-31}})
            reset();check('stale_tip','UNAVAILABLE','STALE_CHAIN_TIP',{'cached':{'observed_unix':int(time.time()),'height':19,'tip':'old'}})
    return {'source_sha256':hashlib.sha256(text.encode()).hexdigest(),'fixed':fixed,'scope':'symbolic pure offline control flow; signature and consensus validity assumed; no runtime keys','cases':rows,'passed':sum(x['pass'] for x in rows.values()),'count':len(rows)}

if __name__=='__main__':print(json.dumps(run(sys.argv[1]),indent=2))
