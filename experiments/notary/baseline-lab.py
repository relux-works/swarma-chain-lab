"""Synthetic, bounded Namecoin notary protocol comparison; public allowlist only."""
import base64,copy,hashlib,http.client,json,os,subprocess,time,traceback
from pathlib import Path
from decimal import Decimal
P=Path('/public'); W=Path('/private'); D=W/'node'; PORT=18596
CALLS=[]; TXS=[]; CASES={}; EVENTS=[]; SECRETS=[]; STATE={}
def canon(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def H(x): return hashlib.sha256(canon(x)).hexdigest()
def out(name,x): (P/name).write_text(json.dumps(x,indent=2,default=str)+'\n')
def rpc(method,*args,wallet='A'):
    t=time.monotonic(); cookie=(D/'regtest/.cookie').read_text().strip()
    c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=15)
    c.request('POST','/wallet/'+wallet if wallet else '/',json.dumps({'jsonrpc':'1.0','id':1,'method':method,'params':args},default=lambda x:float(x) if isinstance(x,Decimal) else str(x)),{'Authorization':'Basic '+base64.b64encode(cookie.encode()).decode(),'Content-Type':'application/json'})
    r=json.loads(c.getresponse().read(),parse_float=Decimal); c.close()
    row={'method':method,'wallet_role':wallet or 'node','elapsed_ms':round(1000*(time.monotonic()-t),3),'success':r.get('error') is None}
    if r.get('error'):row['rpc_code']=r['error']['code']
    CALLS.append(row)
    if r.get('error'):raise RuntimeError('RPC '+method+' code '+str(r['error']['code']))
    return r['result']
def mine(n=1):return rpc('generatetoaddress',n,STATE['miner'],wallet='')
def txdata(txid):return rpc('getrawtransaction',txid,True,wallet='')
def measure(label,txid):
    d=txdata(txid); bh=d.get('blockhash'); row={'label':label,'txid':txid,'bytes':d['size'],'vbytes':d['vsize'],'blockhash':bh,'height':rpc('getblockheader',bh,wallet='')['height'] if bh else None,'confirmations':d.get('confirmations',0)}
    vin=sum(Decimal(str(txdata(v['txid'])['vout'][v['vout']]['value'])) for v in d['vin'] if 'txid' in v)
    row['fee_nmc']=str(vin-sum(Decimal(str(v['value'])) for v in d['vout']));TXS.append(row);return row

def point(txid,address):
    d=txdata(txid); v=next(v for v in d['vout'] if v['scriptPubKey'].get('address')==address)
    return {'txid':txid,'vout':v['n'],'script':v['scriptPubKey']['hex'],'value':str(v['value'])}
def fund(label,address,amount=Decimal('.02'),wallet='A'):
    tx=rpc('sendtoaddress',address,amount,wallet=wallet);mine();measure(label,tx);return point(tx,address)
def name_update(role,value,data=None,extra=None):
    name=STATE[role]['name']; info=rpc('name_show',name,wallet='')
    fee=next(u for u in rpc('listunspent',wallet=role) if u['spendable'] and u['amount']>1)
    change=rpc('getrawchangeaddress',wallet=role)
    ins=[{'txid':info['txid'],'vout':info['vout']},{'txid':fee['txid'],'vout':fee['vout']}]
    outs=[{STATE[role]['address']:Decimal('.01')},{change:fee['amount']-Decimal('.002')}]
    if data:outs.append({'data':data})
    raw=rpc('createrawtransaction',ins,outs,wallet='')
    raw=rpc('namerawtransaction',raw,0,{'op':'name_update','name':name,'value':value},wallet='')['hex']
    s=rpc('signrawtransactionwithwallet',raw,wallet=role);assert s['complete']
    tx=rpc('sendrawtransaction',s['hex'],wallet='');mine();measure(role+'_name_update',tx);return tx

def seal(role,label):return fund(label,STATE[role]['address'],wallet=role)
def spend(role,point_,label):
    raw=rpc('createrawtransaction',[{'txid':point_['txid'],'vout':point_['vout']}],[{rpc('getnewaddress','','legacy',wallet=role):Decimal(point_['value'])-Decimal('.001')}],wallet='')
    s=rpc('signrawtransactionwithwallet',raw,wallet=role);assert s['complete']
    tx=rpc('sendrawtransaction',s['hex'],wallet='');mine();measure(label,tx);return tx

def identity(role):
    d=STATE[role]
    return {k:d[k] for k in ['name','address','pubkey','identity_txid']}
def grant(label,seal_):
    return {'version':'synthetic-notarized-grant-v1','chain_genesis':STATE['genesis'],'issuer':identity('A'),'grantee':STATE['B']['address'],'seal':seal_,'action':'read','resource':'synthetic/item','nonce':label,'not_before_height':rpc('getblockcount',wallet=''),'expires_height':rpc('getblockcount',wallet='')+100,'delegation':False,'transfer':False}
def signed_grant(g):return rpc('signmessage',STATE['A']['address'],'notary-lab/grant-v1:'+H(g),wallet='A')
def assertion(g,ns,mode,issuance=None):
    a={'version':'synthetic-notary-statement-v1','chain_genesis':STATE['genesis'],'grant_hash':H(g),'notary':identity('N'),'notary_seal':ns,'mode':mode,'meaning':'I attest the exact grant bytes; my own seal controls continuing endorsement only','expires_height':g['expires_height']}
    if issuance:a['source_issuance']={k:issuance[k] for k in ['txid','blockhash','height']}
    return a

def proof(f):
    tip=rpc('getbestblockhash',wallet='');height=rpc('getblockcount',wallet='')
    return {'tip':tip,'height':height,'observed_unix':int(time.time()),'source':'single local fully validating regtest node','grant_unspent':rpc('gettxout',f['grant']['seal']['txid'],f['grant']['seal']['vout'],True,wallet='') is not None,'notary_unspent':rpc('gettxout',f['statement']['notary_seal']['txid'],f['statement']['notary_seal']['vout'],True,wallet='') is not None}

# Policy verifier is deliberately a trusted-node verifier, not an SPV client.
# Every ACCEPT refreshes chain status. Cached proofs alone cannot prove liveness.
def verify(f,**kwargs):
    try:return verify_current(f,**kwargs)
    except (OSError,RuntimeError,http.client.HTTPException) as e:return {'status':'UNAVAILABLE','reason':'RPC_PROOF_PROVIDER_UNAVAILABLE','failure_class':type(e).__name__}

def verify_current(f,trusted=True,cached=None,online=True,max_age=30,minconf=1):
    def reject(why):return {'status':'REJECT','reason':why}
    def unknown(why):return {'status':'UNAVAILABLE','reason':why}
    g=f['grant'];s=f['statement'];n=s['notary'];pol=STATE['policy']
    if not trusted or H(n) not in pol['trusted_notary_identity_hashes']:return reject('UNTRUSTED_NOTARY')
    if cached:
        if int(time.time())-cached['observed_unix']>max_age:return unknown('STALE_PROOF')
        if not online:return unknown('CURRENT_CHAIN_VIEW_UNAVAILABLE')
        if cached['height']!=rpc('getblockcount',wallet='') or cached['tip']!=rpc('getbestblockhash',wallet=''):return unknown('STALE_CHAIN_TIP')
    if not online:return unknown('PROOF_UNAVAILABLE')
    if g['chain_genesis']!=STATE['genesis'] or s['chain_genesis']!=STATE['genesis']:return reject('CHAIN_BINDING')
    if s['grant_hash']!=H(g):return reject('GRANT_HASH')
    if g['issuer']!=identity('A'):return reject('ISSUER_PIN')
    if not rpc('verifymessage',g['issuer']['address'],f['grant_signature'],'notary-lab/grant-v1:'+H(g),wallet=''):return reject('ISSUER_SIGNATURE')
    for role,ident in [('A',g['issuer']),('N',n)]:
        current=rpc('name_show',ident['name'],wallet='')
        if current.get('expired') or current['address']!=ident['address']:return reject('CURRENT_NAME_BINDING')
        idtx=txdata(ident['identity_txid'])
        if idtx.get('confirmations',0)<minconf:return reject('IDENTITY_CONFIRMATIONS')
        identity_outputs=[v for v in idtx['vout'] if v['scriptPubKey'].get('nameOp',{}).get('name')==ident['name'] and v['scriptPubKey'].get('address')==ident['address']]
        if len(identity_outputs)!=1 or json.loads(identity_outputs[0]['scriptPubKey']['nameOp']['value']).get('pubkey')!=ident['pubkey']:return reject('IDENTITY_SOURCE_BINDING')
    start_tip=rpc('getbestblockhash',wallet='');height=rpc('getblockcount',wallet='')
    if not g['not_before_height']<=height<g['expires_height'] or height>=s['expires_height']:return reject('EXPIRED_OR_PREMATURE')
    source=f['issuance']; anchor=f['anchor']
    for r in [source,anchor]:
        if rpc('getblockhash',r['height'],wallet='')!=r['blockhash']:return reject('ANCHOR_REORGED')
        d=txdata(r['txid'])
        if d.get('blockhash')!=r['blockhash'] or d.get('confirmations',0)<minconf:return reject('ANCHOR_CONFIRMATIONS')
    if f['mode']=='separate':
        if s['source_issuance']!={k:source[k] for k in ['txid','blockhash','height']}:return reject('SOURCE_BLOCK_BINDING')
        if not rpc('verifymessage',n['address'],f['notary_signature'],'notary-lab/attestation-v1:'+H(s),wallet=''):return reject('NOTARY_SIGNATURE')
        ad=txdata(anchor['txid']); av=next(v for v in ad['vout'] if v['scriptPubKey'].get('nameOp',{}).get('op')=='name_update')
        if av['scriptPubKey']['nameOp']['value']!=canon({'attestation':H(s)}).decode():return reject('ATTESTATION_ANCHOR')
        sd=txdata(source['txid']);sv=next(v for v in sd['vout'] if v['scriptPubKey'].get('nameOp',{}).get('op')=='name_update')
        if sv['scriptPubKey']['nameOp']['value']!=canon({'grant':H(g)}).decode():return reject('ISSUANCE_COMMITMENT')
    else:
        d=txdata(source['txid']);expected='6a40'+H(g)+H(s)
        if not any(v['scriptPubKey']['hex']==expected for v in d['vout']):return reject('COSIGNED_COMMITMENT')
        ms=f['multisig'];computed=rpc('createmultisig',2,[g['issuer']['pubkey'],n['pubkey']],'legacy',wallet='')
        if ms['script']!=computed['redeemScript'] or ms['address']!=computed['address']:return reject('COSIGNER_BINDING')
        prev=txdata(ms['funding']['txid'])['vout'][ms['funding']['vout']]
        if prev['scriptPubKey'].get('address')!=ms['address']:return reject('COSIGNER_PREVOUT')
        if not any(v.get('txid')==ms['funding']['txid'] and v['vout']==ms['funding']['vout'] for v in d['vin']):return reject('COSIGNED_INPUT')
        vin=next(v for v in d['vin'] if v.get('txid')==ms['funding']['txid'] and v['vout']==ms['funding']['vout'])
        ps=pushes(vin['scriptSig']['hex'])
        if len(ps)!=4 or ps[0]!=b'' or ps[-1].hex()!=ms['script'] or any(not v or v[-1]!=1 for v in ps[1:3]):return reject('COSIGNATURE_SIGHASH_POLICY')
        # Full-node validation proves both signatures against the bound 2-of-2 prevout.
    for pt,owner,reason in [(g['seal'],g['issuer']['address'],'GRANT_SEAL_OWNERSHIP'),(s['notary_seal'],n['address'],'NOTARY_SEAL_OWNERSHIP')]:
        prev=txdata(pt['txid'])['vout'][pt['vout']]
        if prev['scriptPubKey'].get('address')!=owner or prev['scriptPubKey']['hex']!=pt['script'] or Decimal(str(prev['value']))!=Decimal(pt['value']):return reject(reason)
    if not rpc('gettxout',g['seal']['txid'],g['seal']['vout'],True,wallet=''):return reject('GRANT_REVOKED')
    if not rpc('gettxout',s['notary_seal']['txid'],s['notary_seal']['vout'],True,wallet=''):return reject('NOTARY_WITHDRAWN')
    if rpc('getbestblockhash',wallet='')!=start_tip:return unknown('CHAIN_CHANGED_DURING_VERIFICATION')
    return {'status':'ACCEPT','reason':'CURRENT_TRUSTED_NODE_POLICY','height':height,'tip':rpc('getbestblockhash',wallet=''),'min_confirmations':minconf}

def case(label,observed,status,reason=None):
    CASES[label]={'observed':observed,'expected_status':status,'expected_reason':reason,'pass':observed['status']==status and (reason is None or observed.get('reason')==reason)}
    out('cases.json',CASES)
    assert CASES[label]['pass'],label+' '+str(observed)

def setup():
    STATE['genesis']=rpc('getblockhash',0,wallet='')
    for role in ['A','B','N']:
        rpc('createwallet',role,False,False,'',False,False,wallet='')
        addr=rpc('getnewaddress','','legacy',wallet=role)
        STATE[role]={'address':addr,'pubkey':rpc('getaddressinfo',addr,wallet=role)['pubkey'],'name':'d/synthetic-notary-'+role.lower()}
    STATE['miner']=STATE['A']['address'];mine(120)
    for role in ['N','B']:fund('fund_'+role,STATE[role]['address'],Decimal(10))
    pending={}
    for role in ['A','B','N']:pending[role]=rpc('name_new',STATE[role]['name'],wallet=role)
    mine(12)
    for role in ['A','B','N']:
        q=pending[role];value=canon({'v':1,'role':role,'pubkey':STATE[role]['pubkey']}).decode()
        tx=rpc('name_firstupdate',STATE[role]['name'],q[1],q[0],value,{'destAddress':STATE[role]['address']},wallet=role);mine();measure(role+'_identity',tx);STATE[role]['identity_txid']=tx
    STATE['policy']={'trusted_notary_identity_hashes':[H(identity('N'))],'issuer':identity('A'),'chain_genesis':STATE['genesis'],'min_confirmations':1,'max_cached_proof_age_seconds':30,'requires_current_chain_tip':True,'mempool_spends':True,'withdrawal_effect':'endorsement only','trust_model':'single locally controlled fully validating node; no global oracle; not SPV'}

def separate():
    gs=seal('A','separate_grant_seal');ns=seal('N','separate_notary_seal')
    g=grant('separate',gs);sig=signed_grant(g)
    tx=name_update('A',canon({'grant':H(g)}).decode());issuance=measure('separate_issuance',tx)
    s=assertion(g,ns,'separate',issuance);nsig=rpc('signmessage',STATE['N']['address'],'notary-lab/attestation-v1:'+H(s),wallet='N')
    tx=name_update('N',canon({'attestation':H(s)}).decode());anchor=measure('separate_attestation_anchor',tx)
    f={'mode':'separate','grant':g,'grant_signature':sig,'statement':s,'notary_signature':nsig,'issuance':issuance,'anchor':anchor};out('separate-fixture.json',f)
    return f

def pushes(script):
    b=bytes.fromhex(script);i=0;out_=[]
    while i<len(b):
        n=b[i];i+=1
        if n==0:out_.append(b'');continue
        if n==76:n=b[i];i+=1
        elif n==77:n=int.from_bytes(b[i:i+2],'little');i+=2
        elif n>78:raise AssertionError('non-push scriptSig')
        out_.append(b[i:i+n]);i+=n
    return out_

def cosigned():
    gs=seal('A','cosigned_grant_seal');ns=seal('N','cosigned_notary_seal')
    g=grant('cosigned',gs);sig=signed_grant(g);s=assertion(g,ns,'cosigned')
    ms=rpc('createmultisig',2,[STATE['A']['pubkey'],STATE['N']['pubkey']],'legacy',wallet='')
    for role in ['A','N']:rpc('importaddress',ms['redeemScript'],'',False,True,wallet=role)
    funding=fund('2of2_issuance_funding',ms['address'],Decimal('.1'))
    info=rpc('name_show',STATE['A']['name'],wallet='')
    raw=rpc('createrawtransaction',[{'txid':info['txid'],'vout':info['vout']},{'txid':funding['txid'],'vout':funding['vout']}],[{STATE['A']['address']:Decimal('.01')},{rpc('getrawchangeaddress',wallet='A'):Decimal('.098')},{'data':H(g)+H(s)}],wallet='')
    raw=rpc('namerawtransaction',raw,0,{'op':'name_update','name':STATE['A']['name'],'value':canon({'grant':H(g),'mode':'cosigned'}).decode()},wallet='')['hex']
    a=rpc('signrawtransactionwithwallet',raw,[], 'ALL',wallet='A');n=rpc('signrawtransactionwithwallet',raw,[], 'ALL',wallet='N')
    assert not a['complete'] and not n['complete']
    for role,q in [('A',a),('N',n)]:
        v=rpc('testmempoolaccept',[q['hex']],wallet='')[0]
        case('cosigned_missing_'+('N' if role=='A' else 'A'),{'status':'REJECT' if not v['allowed'] else 'ACCEPT','reason':'CONSENSUS_OR_POLICY_SCRIPT_REJECT','allowed':v['allowed'],'reject_reason':v.get('reject-reason'),'signing_complete':q['complete']},'REJECT')
    both=rpc('signrawtransactionwithwallet',a['hex'],[],'ALL',wallet='N');assert both['complete']
    decoded=rpc('decoderawtransaction',both['hex'],wallet='');parts=pushes(decoded['vin'][1]['scriptSig']['hex']);assert parts[0]==b'' and parts[-1].hex()==ms['redeemScript'] and len(parts)==4
    assert all(x[-1]==1 for x in parts[1:3]);EVENTS.append({'label':'actual_cosignatures','signatures':2,'sighash_bytes':[x[-1] for x in parts[1:3]],'meaning':'SIGHASH_ALL; no ANYONECANPAY','unsigned_transaction_hash':hashlib.sha256(bytes.fromhex(raw)).hexdigest()})
    tx=rpc('sendrawtransaction',both['hex'],wallet='');mine();issuance=measure('cosigned_issuance',tx)
    f={'mode':'cosigned','grant':g,'grant_signature':sig,'statement':s,'issuance':issuance,'anchor':issuance,'multisig':{'address':ms['address'],'script':ms['redeemScript'],'funding':funding}}
    out('cosigned-fixture.json',f);return f

def controls(f):
    mode=f['mode'];case(mode+'_valid',verify(f),'ACCEPT')
    case(mode+'_untrusted',verify(f,trusted=False),'REJECT','UNTRUSTED_NOTARY')
    p=proof(f);case(mode+'_unavailable',verify(f,online=False),'UNAVAILABLE','PROOF_UNAVAILABLE')
    case(mode+'_cached_offline',verify(f,cached=p,online=False),'UNAVAILABLE','CURRENT_CHAIN_VIEW_UNAVAILABLE')
    stale=copy.deepcopy(p);stale['observed_unix']-=31;case(mode+'_stale_age',verify(f,cached=stale),'UNAVAILABLE','STALE_PROOF')
    mine();case(mode+'_stale_tip',verify(f,cached=p),'UNAVAILABLE','STALE_CHAIN_TIP')
    bad=copy.deepcopy(f);bad['statement']['chain_genesis']='00'*32;case(mode+'_wrong_chain',verify(bad),'REJECT','CHAIN_BINDING')
    bad=copy.deepcopy(f);bad['grant']['resource']='synthetic/tampered';case(mode+'_tampered',verify(bad),'REJECT','GRANT_HASH')
    if mode=='separate':
        bad=copy.deepcopy(f);bad['notary_signature']=f['grant_signature'];case(mode+'_missing_notary_signature',verify(bad),'REJECT','NOTARY_SIGNATURE')
    need=rpc('getblockcount',wallet='')-max(f['issuance']['height'],f['anchor']['height'])+2
    case(mode+'_insufficient_confirmations',verify(f,minconf=need),'REJECT','ANCHOR_CONFIRMATIONS')
    out(mode+'-fresh-proof.json',proof(f))

def reorg_attestation(f):
    # Run before any later blocks: invalidate the separate N anchor only.
    bh=f['anchor']['blockhash'];rpc('invalidateblock',bh,wallet='')
    oldminer=STATE['miner'];STATE['miner']=rpc('getnewaddress','','legacy',wallet='A');mine();STATE['miner']=oldminer
    case('separate_attestation_reorg',verify(f),'REJECT','ANCHOR_REORGED')
    EVENTS.append({'label':'attestation_reorg','source_issuance_still_active':rpc('getblockhash',f['issuance']['height'],wallet='')==f['issuance']['blockhash'],'orphaned_attestation_block':bh,'replacement_tip':rpc('getbestblockhash',wallet='')})
    # The identical transaction may re-mine; an old block-bound proof still fails.
    oldtx=f['anchor']['txid'];rpc('reconsiderblock',bh,wallet='');mine()
    d=txdata(oldtx);newbh=d['blockhash'];f['anchor']={'txid':oldtx,'blockhash':newbh,'height':rpc('getblockheader',newbh,wallet='')['height']}
    case('separate_refreshed_after_reorg',verify(f),'ACCEPT')
    out('separate-fixture-current.json',f)

def source_reorg(f):
    mode=f['mode'];old=f['issuance']['blockhash'];rpc('invalidateblock',old,wallet='')
    oldminer=STATE['miner'];STATE['miner']=rpc('getnewaddress','','legacy',wallet='A');mine(2);STATE['miner']=oldminer
    case(mode+'_source_issuance_reorg',verify(f),'REJECT','ANCHOR_REORGED')
    for k in ['issuance','anchor']:
        tx=f[k]['txid'];d=txdata(tx);bh=d['blockhash'];f[k]={'txid':tx,'blockhash':bh,'height':rpc('getblockheader',bh,wallet='')['height']}
    if mode=='separate':
        case('separate_old_statement_after_source_reorg',verify(f),'REJECT','SOURCE_BLOCK_BINDING')
        f['statement']=assertion(f['grant'],f['statement']['notary_seal'],'separate',f['issuance'])
        f['notary_signature']=rpc('signmessage',STATE['N']['address'],'notary-lab/attestation-v1:'+H(f['statement']),wallet='N')
        tx=name_update('N',canon({'attestation':H(f['statement'])}).decode());f['anchor']=measure('separate_reissued_attestation_after_source_reorg',tx)
    case(mode+'_refreshed_after_source_reorg',verify(f),'ACCEPT')
    out(mode+'-fixture-current.json',f)

def notary_seal_owner_control(f):
    bad=copy.deepcopy(f);bad['statement']['notary_seal']=bad['grant']['seal']
    bad['notary_signature']=rpc('signmessage',STATE['N']['address'],'notary-lab/attestation-v1:'+H(bad['statement']),wallet='N')
    tx=name_update('N',canon({'attestation':H(bad['statement'])}).decode());bad['anchor']=measure('N_anchors_wrong_owner_seal_control',tx)
    case('separate_valid_N_signature_wrong_seal_owner',verify(bad),'REJECT','NOTARY_SEAL_OWNERSHIP')

def withdraw(f):
    mode=f['mode'];cached=proof(f);tx=spend('N',f['statement']['notary_seal'],mode+'_N_withdrawal')
    case(mode+'_withdrawn',verify(f),'REJECT','NOTARY_WITHDRAWN')
    case(mode+'_withdrawn_old_proof',verify(f,cached=cached),'UNAVAILABLE','STALE_CHAIN_TIP')
    g=f['grant'];EVENTS.append({'label':mode+'_withdrawal_does_not_revoke_grant','grant_seal_unspent':rpc('gettxout',g['seal']['txid'],g['seal']['vout'],True,wallet='') is not None,'issuance_confirmations':txdata(f['issuance']['txid'])['confirmations'],'withdrawal_txid':tx})
    # Reorg withdrawal without mining: mempool-inclusive policy keeps refusing.
    bh=rpc('getbestblockhash',wallet='');rpc('invalidateblock',bh,wallet='')
    EVENTS.append({'label':mode+'_withdrawal_reorg','chain_only_seal_unspent':rpc('gettxout',f['statement']['notary_seal']['txid'],f['statement']['notary_seal']['vout'],False,wallet='') is not None,'mempool_inclusive_seal_unspent':rpc('gettxout',f['statement']['notary_seal']['txid'],f['statement']['notary_seal']['vout'],True,wallet='') is not None,'withdrawal_in_mempool':tx in rpc('getrawmempool',wallet='')})
    case(mode+'_withdrawal_reorg_mempool',verify(f),'REJECT','NOTARY_WITHDRAWN')
    rpc('reconsiderblock',bh,wallet='')
    spend('A',g['seal'],mode+'_A_grant_revocation');case(mode+'_grant_revoked',verify(f),'REJECT','GRANT_REVOKED')

def main():
    assert os.getuid()==1002
    D.mkdir(mode=0o700);p=subprocess.Popen(['/runtime/namecoind','-regtest','-datadir='+str(D),'-server=1','-listen=0','-dnsseed=0','-discover=0','-connect=0','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1','-rpcport='+str(PORT),'-txindex=1','-fallbackfee=0.002','-deprecatedrpc=create_bdb','-dbcache=32','-par=1','-maxmempool=16','-printtoconsole=0'],stdout=subprocess.DEVNULL,stderr=open(W/'node.stderr','wb'))
    status='FAILED'
    try:
        for _ in range(100):
            if p.poll() is not None:raise RuntimeError('node early exit')
            try:rpc('getblockchaininfo',wallet='');break
            except (FileNotFoundError,ConnectionError,OSError):time.sleep(.1)
        else:raise RuntimeError('node readiness timeout')
        out('boundary.json',{'uid':os.getuid(),'interfaces':[line.split(':')[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]],'network_namespace':os.readlink('/proc/self/ns/net'),'agent_home_visible':any(Path('/home').iterdir()),'private_mode':oct(W.stat().st_mode&0o777),'rpc_port':PORT,'version':rpc('getnetworkinfo',wallet='')['subversion'],'chain':rpc('getblockchaininfo',wallet='')['chain'],'connections':rpc('getconnectioncount',wallet='')})
        setup();out('policy.json',STATE['policy']);f=separate();reorg_attestation(f);source_reorg(f);controls(f);notary_seal_owner_control(f);c=cosigned();source_reorg(c);controls(c);withdraw(f);withdraw(c)
        out('identities.json',{r:identity(r) for r in ['A','B','N']});out('final-chain.json',{'height':rpc('getblockcount',wallet=''),'tip':rpc('getbestblockhash',wallet=''),'genesis':STATE['genesis'],'connections':rpc('getconnectioncount',wallet='')})
        rpc('stop',wallet='');p.wait(timeout=20)
        case('separate_actual_rpc_provider_stopped',verify(f),'UNAVAILABLE','RPC_PROOF_PROVIDER_UNAVAILABLE')
        case('cosigned_actual_rpc_provider_stopped',verify(c),'UNAVAILABLE','RPC_PROOF_PROVIDER_UNAVAILABLE')
        status='PASS'
    except Exception as e:
        out('failure.json',{'type':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()})
    finally:
        try:rpc('stop',wallet='')
        except Exception:pass
        try:p.wait(timeout=20)
        except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=5)
        out('runtime.json',{'status':status,'cases':len(CASES),'passed':sum(x['pass'] for x in CASES.values()),'transactions':TXS,'events':EVENTS,'rpc_calls':CALLS,'node_exit':p.returncode,'private_keys_exported':False})
    return 0 if status=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
