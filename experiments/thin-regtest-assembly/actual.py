"""Closed regtest composition. Never imports host credentials or owner keys.

The supervisor brokers public reads. Private actor files are only mounted into
that actor's restricted root; this is filesystem custody, not distinct OS UIDs.
"""
import base64, ctypes, datetime, hashlib, json, os, pathlib, resource, select
import signal, subprocess, sys, time, traceback, tempfile
from decimal import Decimal

sys.path.insert(0, '/src/experiments/fullnode-trusts')
import seal_anchor as adapter
from transaction import build_signed
from name_operation import build_companion_name_signed
from funding import T1_SIZES
from exact_json import dumps as exact_dumps, satoshis, coins

P=pathlib.Path
PUBLIC=P('/private/public')
OUT=P('/output/check-evidence')
records=[]; children=[]; reads=[]; rpc_count=0; started=time.monotonic()
accept=json.loads(P('/output/receipt/acceptance.json').read_text())
deadline=datetime.datetime.fromisoformat(accept['deadline']).timestamp()-120
accepted=int(datetime.datetime.fromisoformat(accept['at']).timestamp())
H=lambda b:hashlib.sha256(b).hexdigest()
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(name,value):
 (PUBLIC/name).write_text(json.dumps(value,separators=(',',':'),sort_keys=True))
 os.chmod(PUBLIC/name,0o600)
def birth(pid): return P('/proc/'+str(pid)+'/stat').read_text().split(') ',1)[1].split()[19]
def preexec(role):
 def enter():
  os.setsid()
  os.chdir('/actors/'+role+'/private')
  libc=ctypes.CDLL(None,use_errno=True)
  class Header(ctypes.Structure): _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
  class Data(ctypes.Structure): _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
  assert libc.prctl(38,1,0,0,0)==0
  assert libc.prctl(4,0,0,0,0)==0
  # Host LSM refuses chroot even inside this user namespace. Landlock gives
  # each actor a kernel-enforced allowlist over its separate mounted subtree.
  abi=libc.syscall(444,0,0,1);assert abi>=3,'Landlock ABI >=3 required'
  class Ruleset(ctypes.Structure): _fields_=[('handled_access_fs',ctypes.c_uint64)]
  class Beneath(ctypes.Structure): _fields_=[('allowed_access',ctypes.c_uint64),('parent_fd',ctypes.c_int)]
  all_fs=(1<<16)-1;read_fs=(1<<0)|(1<<2)|(1<<3)
  rs=libc.syscall(444,ctypes.byref(Ruleset(all_fs)),8,0);assert rs>=0
  for path,access in [('/usr',read_fs),('/actors/'+role+'/bin',read_fs),('/actors/'+role+'/private',all_fs),('/private/public',read_fs),('/dev',(1<<1)|(1<<2)|(1<<3))]:
   fd=os.open(path,os.O_PATH|os.O_CLOEXEC)
   rule=Beneath(access,fd);assert libc.syscall(445,rs,1,ctypes.byref(rule),0)==0
   os.close(fd)
  assert libc.syscall(446,rs,0)==0
  os.close(rs)
  assert libc.capset(ctypes.byref(Header(0x20080522,0)),(Data*2)())==0
  resource.setrlimit(resource.RLIMIT_CPU,(180,180))
  resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
  resource.setrlimit(resource.RLIMIT_FSIZE,(24<<20,24<<20))
 return enter
def actor(role,args,**kw):
 assert time.time()<deadline and time.monotonic()-started<600,'original deadline or wall budget'
 root=P('/private/actors')/role/'private'
 for d in ['home','tmp','cache']:
  (root/d).mkdir(mode=0o700,exist_ok=True);os.chmod(root/d,0o700)
 actor_root='/actors/'+role+'/private'
 env={'HOME':actor_root+'/home','TMPDIR':actor_root+'/tmp','XDG_CACHE_HOME':actor_root+'/cache','PATH':'/usr/bin','LC_ALL':'C.UTF-8'}
 args=[a.replace('/bin/','/actors/'+role+'/bin/',1) if a.startswith('/bin/') else a.replace('/private/','/actors/'+role+'/private/',1) if a.startswith('/private/') else a.replace('/public/','/private/public/',1) if a.startswith('/public/') else a for a in args]
 args=[a.replace('=/private/','='+actor_root+'/') for a in args]
 p=subprocess.Popen(args,env=env,preexec_fn=preexec(role),**kw)
 item={'role':role,'pid':p.pid,'birth':birth(p.pid),'start':stamp()};children.append((p,item))
 return p,item
def finish(p,item):
 item['exit']=p.returncode;item['end']=stamp()
def run(role,args,limit=1<<20):
 # Disk-backed capped child output avoids an unbounded communicate buffer.
 with tempfile.TemporaryFile(dir='/private/tmp') as stdout,tempfile.TemporaryFile(dir='/private/tmp') as stderr:
  p,item=actor(role,args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
  try:p.wait(timeout=15)
  except BaseException:
   if p.poll() is None and birth(p.pid)==item['birth']:os.killpg(p.pid,signal.SIGKILL)
   p.wait(timeout=3);finish(p,item);raise
  finish(p,item)
  assert stdout.tell()<=limit and stderr.tell()<=8192,'actor output bound'
  stdout.seek(0);stderr.seek(0)
  out=stdout.read(limit+1);err=stderr.read(8193)
 if p.returncode:
  # Inputs and diagnostic outputs stay private unless a known public RPC error.
  (P('/private')/'last-error').write_bytes(err)
  raise RuntimeError('actor '+role+' command '+args[0]+' '+args[1]+' exit '+str(p.returncode)+' diagnostic_sha256='+H(err))
 return out,err
def rpc(method,*args,wallet=None):
 global rpc_count
 rpc_count+=1;assert rpc_count<=1800,'RPC call budget'
 argv=['/bin/namecoin-cli','-conf=/private/node.conf','-regtest']
 if wallet:argv+=['-rpcwallet='+wallet]
 argv+=[method]
 for a in args:
  argv.append(a if isinstance(a,str) else exact_dumps(a))
 out,_=run('node',argv,8<<20)
 if not out.strip():return None
 try:return json.loads(out,parse_float=Decimal)
 except json.JSONDecodeError:return out.decode().strip()
def network():
 info=rpc('getblockchaininfo')
 assert info['chain']=='regtest' and rpc('getblockhash',0)=='0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206','REGTEST_REQUIRED'
 return info
def mutation(method,*args,wallet=None):network();return rpc(method,*args,wallet=wallet)
def mine(n=1):return mutation('generatetoaddress',n,mine_address,wallet='funder')
def point(txid,address=None,named=False):
 tx=rpc('getrawtransaction',txid,True)
 rows=[o for o in tx['vout'] if (address is None or o['scriptPubKey'].get('address')==address) and ('nameOp' in o['scriptPubKey'])==named]
 assert len(rows)==1,(txid,len(rows))
 o=rows[0];return {'txid':txid,'vout':o['n'],'script':o['scriptPubKey']['hex'],'value_sat':satoshis(o['value'])}
def public_tx(txid):
 return rpc('getrawtransaction',txid,True)
def normalize(v):
 if isinstance(v,Decimal):return str(v)
 if isinstance(v,dict):return {k:normalize(x) for k,x in v.items()}
 if isinstance(v,(list,tuple)):return [normalize(x) for x in v]
 return v
def builder(role,address,inputs,outputs,*,name_op=None,cap=None,fee_cap=None):
 def broker(method,*args,wallet=None):
  if method=='fundrawtransaction':
   options=dict(args[1]);options.update({'changeAddress':address,'add_inputs':bool(name_op),'changePosition':len(outputs)})
   return mutation(method,args[0],options,wallet=role)
  if method in ['createrawtransaction','namerawtransaction','signrawtransactionwithwallet']:
   return mutation(method,*args,wallet=role if method=='signrawtransactionwithwallet' else None)
  return rpc(method,*args,wallet=role if wallet else None)
 # Final name operations use their separate named constant/helper route.
 if name_op and name_op['op'] in ('name_firstupdate','name_update'):
  assert cap is None and fee_cap is None
  return build_companion_name_signed(broker,network,role,inputs,outputs,name_op=name_op,regtest_vsize_cap=1024,regtest_fee_cap_sat=204800)
 if name_op:
  assert name_op['op']=='name_new' and cap is None and fee_cap is None
  cap=T1_SIZES['A_name_new'];fee_cap=cap*200
 assert type(cap) is int and type(fee_cap) is int
 return build_signed(broker,network,role,inputs,outputs,rate_sat_vb=200,vsize_cap=cap,fee_cap=coins(fee_cap),name_op=name_op)
def send(raw):
 decoded=rpc('decoderawtransaction',raw)
 txid=mutation('sendrawtransaction',raw)
 assert txid==decoded['txid']
 return txid
def ordinary(role,script):
 rows=rpc('listunspent',1,9999999,[],True,{},wallet=role)
 choices=[u for u in rows if u['scriptPubKey']==script and 250000<satoshis(u['amount'])<10000000 and u.get('spendable')]
 assert choices,'no explicitly allocated selectable UTXO'
 u=max(choices,key=lambda u:u['amount'])
 return {'txid':u['txid'],'vout':u['vout'],'script':u['scriptPubKey'],'value_sat':satoshis(u['amount'])}
def reg_stage(label,**data):
 records.append({'stage':label,'at':stamp(),**normalize(data)})
 (OUT/'actual-stages.json').write_text(json.dumps(records,indent=2)+'\n')
 print(label,flush=True)
def bridge(mode,policy,binding,request='request.json'):
 observation=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
 save('bridge.json',{'Mode':mode,'Policy':policy,'Binding':binding,'Certificate':'/private/public/certificate.json','Request':'/private/public/'+request,'At':observation})
 p,item=actor('verifier',['/bin/labcompose','/public/bridge.json'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 def alarm(signum,frame):raise TimeoutError('hard bridge deadline')
 previous=signal.signal(signal.SIGALRM,alarm)
 signal.setitimer(signal.ITIMER_REAL,20)
 end=min(time.monotonic()+20,time.monotonic()+max(0,deadline-time.time()));answer=None
 try:
  for _ in range(260):
   remaining=end-time.monotonic();assert remaining>0,'bridge timeout'
   ready,_,_=select.select([p.stdout],[],[],remaining);assert ready,'bridge output deadline'
   line=p.stdout.readline((8<<20)+1);assert 0<len(line)<=8<<20,'bridge output bound'
   msg=json.loads(line)
   if msg.get('done'):answer=msg;break
   method=msg.get('rpc');assert method in ['getblockchaininfo','getblockhash','getblockheader','name_show','getrawtransaction','gettxout','getrawmempool','getblock']
   args=msg.get('params') or []
   if method=='name_show':
    assert len(args)==2 and args[1]=={'nameEncoding':'ascii','valueEncoding':'ascii','allowExpired':False},'exact requested encoding required'
   try:
    result=rpc(method,*args)
    if method=='name_show':
     assert result.get('name_encoding')==args[1]['nameEncoding'] and result.get('value_encoding')==args[1]['valueEncoding']
     result['name'].encode('ascii');result['value'].encode('ascii')
    response={'result':result}
   except Exception:response={'failed':True}
   reads.append({'at':stamp(),'mode':mode,'method':method,'params':args,'reply':normalize(response)})
   p.stdin.write(exact_dumps(response).encode()+b'\n');p.stdin.flush()
  assert answer is not None
  p.stdin.close();p.wait(timeout=3);finish(p,item);assert p.returncode==0
  return answer
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
  if p.poll() is None:
   if birth(p.pid)==item['birth']:os.killpg(p.pid,signal.SIGKILL)
   p.wait(timeout=3);finish(p,item)
def sign_request(index):
 req={'type':'grants-local-operation-1','request_id':'actual-request-'+str(index),'certificate_id':'actual-operator-to-requester','entry_id':'repo-create','cycle_id':'codex-dm','operation_use_id':'codex-dm/create','subject':subject,'audience':audience,'action':'repository.create','target':{'organization':'relux-works','name':'matrix-grants-poc-261031','visibility':'private'},'expires_at':'2026-11-08T14:00:00Z'}
 save('operation.json',req)
 digest,_=run('requester',['/bin/labtestsigner','prepare-request','--payload','/public/operation.json','--requester-spki','/public/requester.der'])
 signed,_=run('requester',['/bin/labtestsigner','request','--payload','/public/operation.json','--requester-spki','/public/requester.der','--digest',digest.decode(),'--key','/private/keys/requester.pk8'])
 (PUBLIC/('request'+('' if index==1 else str(index))+'.json')).write_bytes(signed)
 return signed

node=None;status='FAIL'
try:
 # Parent never opens any PKCS8 file. Public DER alone crosses actor roots.
 for role,key in [('owner','owner'),('requester','requester')]:
  run(role,['/bin/labtestsigner','keygen','--dir','/private/keys'])
  public=(P('/private/actors')/role/'private/keys'/(key+'.der')).read_bytes()
  (PUBLIC/(key+'.der')).write_bytes(public)
 owner_der=(PUBLIC/'owner.der').read_bytes();requester_der=(PUBLIC/'requester.der').read_bytes();assert owner_der!=requester_der
 # Probe only fresh harmless sentinels, never another actor's key bytes.
 for role in ['owner','requester']:
  (P('/private/actors')/role/'private/custody-sentinel').write_text('own-test-sentinel')
 for role,other in [('owner','requester'),('requester','owner')]:
  probe="import os; own='/actors/"+role+"/private/custody-sentinel'; other='/actors/"+other+"/private/custody-sentinel'; assert open(own).read()=='own-test-sentinel'; denied=False\ntry: f=open(other); f.close()\nexcept PermissionError: denied=True\nassert denied; assert not os.path.exists('/home/agent'); assert 'SSH_AUTH_SOCK' not in os.environ; print('own sentinel allowed; other actor denied; no host home or agent environment')"
  out,_=run(role,['/usr/bin/python3','-I','-c',probe])
  reg_stage('actor-filesystem-custody-control',role=role,result=out.decode().strip())
 subject={'account_mxid':'@requester:example.invalid','device_id':'LAB-REQUESTER'}
 audience={'deployment_id':'lab-thin-slice','executor_id':'lab-verify-only'}
 cycle={'cycle_id':'codex-dm','runtime':'codex','channel':'encrypted-dm'}
 draft={'certificate_id':'actual-operator-to-requester','subject':subject,'audience':audience,'cycles':[cycle],'not_before':'2026-11-07T14:00:00Z','expires_at':'2026-11-09T14:00:00Z','organization':'relux-works','name':'matrix-grants-poc-261031'}
 save('draft.json',draft)
 payload,review=run('owner',['/bin/keyvault','grants','local-prepare','--plan','/public/draft.json','--owner-mxid','@operator:example.invalid','--issuer-spki-der','/public/owner.der','--requester-spki-der','/public/requester.der'])
 (PUBLIC/'prepared.json').write_bytes(payload)
 digest=H(b'swarma-grants/local-certificate/1\n'+payload)
 assert digest.encode() in review
 cert,_=run('owner',['/bin/labtestsigner','certificate','--payload','/public/prepared.json','--digest',digest,'--key','/private/keys/owner.pk8','--owner-spki','/public/owner.der','--requester-spki','/public/requester.der'])
 (PUBLIC/'certificate.json').write_bytes(cert);cert_hash=H(cert)
 request=sign_request(1)
 reg_stage('separate-actor-real-signer',certificate_sha256=cert_hash,request_sha256=H(request),owner_der_sha256=H(owner_der),requester_der_sha256=H(requester_der))
 node_root=P('/private/actors/node/private');(node_root/'data').mkdir(mode=0o700)
 password=base64.urlsafe_b64encode(os.urandom(32)).decode()
 (node_root/'node.conf').write_text('regtest=1\nserver=1\nlisten=0\ndnsseed=0\ndiscover=0\nlistenonion=0\ntxindex=1\nprinttoconsole=0\ndebug=0\nrpcuser=closed-lab\nrpcpassword='+password+'\ndatadir=/actors/node/private/data\n[regtest]\nconnect=0\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=18443\n')
 os.chmod(node_root/'node.conf',0o600);del password
 console=(node_root/'console.log').open('wb')
 node,item=actor('node',['/bin/namecoind','-conf=/private/node.conf','-regtest','-deprecatedrpc=create_bdb','-fallbackfee=0.002'],stdin=subprocess.DEVNULL,stdout=console,stderr=console)
 # Finite own-node startup readiness, not another worker's polling.
 for attempt in range(30):
  if node.poll() is not None:
   console.flush()
   # Core startup diagnostics are sanitized before evidence export.
   lines=(node_root/'console.log').read_text(errors='replace').splitlines()
   safe=[line for line in lines if not any(x in line.lower() for x in ['password','rpcuser','cookie','key','auth','token'])]
   raise RuntimeError('own Core startup: '+' | '.join(safe[-5:]))
  try:network();break
  except Exception:
   if attempt==29:raise
   time.sleep(.1)
 for wallet in ['funder','issuer','requester']:
  mutation('createwallet',wallet,False,False,'',False,False)
 mine_address=mutation('getnewaddress','','legacy',wallet='funder');mine(101)
 issuer_address=mutation('getnewaddress','','legacy',wallet='issuer')
 reserve_address=mutation('getnewaddress','','legacy',wallet='issuer')
 second_address=mutation('getnewaddress','','legacy',wallet='issuer')
 requester_address=mutation('getnewaddress','','legacy',wallet='requester')
 allocation=mutation('sendmany','',{reserve_address:Decimal('0.875'),issuer_address:Decimal('0.06'),second_address:Decimal('0.065')},wallet='funder')
 mutation('sendtoaddress',requester_address,Decimal('0.03'),wallet='funder');mine()
 reserved=point(allocation,reserve_address)
 mutation('lockunspent',False,[{'txid':reserved['txid'],'vout':reserved['vout']}],wallet='issuer')
 issuer_script=rpc('getaddressinfo',issuer_address,wallet='issuer')['scriptPubKey']
 requester_script=rpc('getaddressinfo',requester_address,wallet='requester')['scriptPubKey']
 net=rpc('getnetworkinfo');assert net['connections']==0
 reg_stage('regtest-allocated-funds',reserved_principal_sat=reserved['value_sat'],selected_total_owner_sat=100000000,reserved_locked=True,network=network()['chain'],node_connections=net['connections'])
 names={};reservations={}
 for role,address,key,name in [('issuer',issuer_address,'owner','id/swarma-poc-operator'),('requester',requester_address,'requester','id/swarma-poc-requester')]:
  nonce=os.urandom(20).hex()
  raw=builder(role,address,[],[{address:Decimal('0.01')}],name_op={'op':'name_new','name':name,'rand':nonce})
  txid=send(raw);reservations[role]=(point(txid,address,True),nonce,name,key,address)
 mine(12)
 for role,(u,nonce,name,key,address) in reservations.items():
  pin=base64.urlsafe_b64encode((PUBLIC/(key+'.der')).read_bytes()).decode().rstrip('=')
  value=json.dumps({'swarma':{'keyvault_'+key+'_spki':pin}},separators=(',',':'))
  raw=builder(role,address,[{'txid':u['txid'],'vout':u['vout']}],[{address:Decimal('0.01')}],name_op={'op':'name_firstupdate','name':name,'rand':nonce,'value':value})
  txid=send(raw);names[role]=name
 mine()
 reg_stage('real-name-spki-records',owner=rpc('name_show',names['issuer']),requester=rpc('name_show',names['requester']))
 # A confirmed 0.875 reserve stays locked; selected ordinary inputs fit remaining allocation.
 ledger={'reserved_sat':87500000,'prior_fee_sat':1000000,'name_count':2,'other_locked_sat':0}
 def bounds():
  tip=network();return {'accepted_epoch':accepted,'deadline_epoch':int(datetime.datetime.fromisoformat(accept['deadline']).timestamp()),'step_started_epoch':int(time.time()),'broadcast_tip_height':tip['blocks'],'broadcast_tip_hash':tip['bestblockhash']}
 def adapter_tx(kind,seal=None):
  u=seal if kind=='revoke' else ordinary('issuer',issuer_script)
  plan=adapter.prepare(kind,cert,{'address':issuer_address,'script':issuer_script},u,ledger,bounds(),now=int(time.time()),seal=seal)
  intent=plan.intent()
  if kind=='revoke':
   raw=mutation('createrawtransaction',list(intent.inputs),list(intent.outputs))
   signed=mutation('signrawtransactionwithwallet',raw,wallet='issuer');assert signed['complete'];raw=signed['hex']
  else:raw=builder('issuer',issuer_address,list(intent.inputs),list(intent.outputs),cap=plan.public()['vsize_cap'],fee_cap=plan.public()['fee_cap_sat'])
  prev={u['txid']:rpc('getrawtransaction',u['txid'],True)}
  checked=adapter.inspect(plan,cert,raw,prev,now=int(time.time()))
  assert rpc('testmempoolaccept',[raw])[0]['allowed']
  txid=send(raw)
  assert txid==checked['txid']
  (OUT/(kind+'-plan.json')).write_bytes(plan.encoded)
  (OUT/(kind+'-inspection.json')).write_text(json.dumps(normalize(checked),indent=2)+'\n')
  (OUT/(kind+'-signed-raw.txt')).write_text(raw+'\n')
  ledger['prior_fee_sat']+=checked['fee_sat']
  ledger['other_locked_sat']+=100000 if kind=='seal' else -100000 if kind=='revoke' else 0
  return checked
 seal_info=adapter_tx('seal');seal=seal_info['seal'];mine()
 mutation('lockunspent',False,[{'txid':seal['txid'],'vout':seal['vout']}],wallet='issuer')
 ordinary_anchor=adapter_tx('anchor',seal);mine()
 reg_stage('actual-adapter-seal-and-ordinary-anchor',seal=seal,anchor=ordinary_anchor,seal_chain=rpc('gettxout',seal['txid'],seal['vout'],True))
 current=rpc('name_show',names['issuer'])
 value=json.dumps({'swarma':{'keyvault_owner_spki':base64.urlsafe_b64encode(owner_der).decode().rstrip('='),'keyvault_certificate_sha256':cert_hash,'keyvault_seal':{'txid':seal['txid'],'vout':seal['vout']}}},separators=(',',':'))
 assert len(value.encode())<=520
 raw=builder('issuer',issuer_address,[{'txid':current['txid'],'vout':current['vout']}],[{issuer_address:Decimal('0.01')},{'data':cert_hash}],name_op={'op':'name_update','name':names['issuer'],'value':value})
 anchor_txid=send(raw);mine();anchor=public_tx(anchor_txid);tip=network()
 reg_stage('exact-name-update-certificate-anchor',name=rpc('name_show',names['issuer']),transaction=anchor,ordinary_anchor_txid=ordinary_anchor['txid'],certificate_sha256=cert_hash,bridge_regtest_vsize_cap=1024,actual_vsize=anchor['vsize'])
 policy={'OwnerName':names['issuer'],'RequesterName':names['requester'],'Account':subject['account_mxid'],'Device':subject['device_id'],'Deployment':audience['deployment_id'],'Executor':audience['executor_id'],'Cycle':cycle['cycle_id'],'CLI':'/actors/verifier/bin/keyvault','PrivateRoot':'/actors/verifier/private','AnchorTxID':anchor_txid,'AnchorBlock':anchor['blockhash'],'SealTxID':seal['txid'],'SealVout':seal['vout']}
 binding={'Seal':{'txid':seal['txid'],'vout':seal['vout']},'SealScript':seal['script'],'Anchor':{'height':tip['blocks'],'hash':anchor['blockhash'],'txid':anchor_txid},'Commitment':cert_hash,'Genesis':rpc('getblockhash',0),'Chain':'regtest','StartTip':{'height':tip['blocks'],'hash':tip['bestblockhash']},'Deadline':datetime.datetime.fromtimestamp(deadline,datetime.timezone.utc).isoformat(),'ProofValidUntil':'2026-11-08T14:00:00Z','LastBlockAt':stamp()}
 watcher=bridge('watch',policy,binding);positive=bridge('verify',policy,binding)
 reg_stage('real-positive-verification',watcher=watcher,wrapper=positive)
 assert watcher['watch']['state']=='UNSPENT' and positive['verified'],'actual positive verification failed'
 # Bounded clock control: same real tip, simulated elapsed idle interval.
 stale=dict(binding);stale['LastBlockAt']=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=30,seconds=1)).isoformat()
 stopped=bridge('watch',policy,stale)
 assert stopped['watch']['state']=='STOP' and stopped['watch']['reason']=='NO_NEW_BLOCK_30_MIN' and stopped['watch']['calls']==0
 reg_stage('causal-no-block-stop-control',watcher=stopped,controlled_last_block_at=stale['LastBlockAt'],real_wait_seconds=0,clock_control='binding timestamp; not protected clock qualification')
 generation_policy=dict(policy);generation_policy['PrivateRoot']+='/generation-control'
 P('/private/actors/verifier/private/generation-control').mkdir(mode=0o700)
 assert bridge('verify',generation_policy,binding)['verified']
 current=rpc('name_show',names['issuer'])
 replacement_raw=builder('issuer',issuer_address,[{'txid':current['txid'],'vout':current['vout']}],[{issuer_address:Decimal('0.01')},{'data':cert_hash}],name_op={'op':'name_update','name':names['issuer'],'value':value})
 replacement_txid=send(replacement_raw);replacement_block=mine()[0]
 changed=rpc('name_show',names['issuer']);assert changed['txid']==replacement_txid and changed['height']==tip['blocks']+1
 generation_refusal=bridge('verify',generation_policy,binding)
 assert not generation_refusal['verified']
 mutation('invalidateblock',replacement_block)
 restored=rpc('name_show',names['issuer']);assert restored['txid']==anchor_txid
 restored_refusal=bridge('verify',generation_policy,binding)
 assert not restored_refusal['verified'] and restored_refusal['read_calls']==2
 latch=P('/private/actors/verifier/private/generation-control')/('closed-'+cert_hash)
 assert latch.is_file() and latch.stat().st_mode&0o777==0o600
 reg_stage('confirmed-generation-replacement-restored-branch-refusal',replacement_txid=replacement_txid,replacement_block=replacement_block,confirmed_replacement=changed,restored_name=restored,first_refusal=generation_refusal,fresh_process_restored_refusal=restored_refusal,independent_private_root=True)
 revoked=adapter_tx('revoke',seal)
 suspended=bridge('watch',policy,binding);refused=bridge('verify',policy,binding)
 reg_stage('immediate-mempool-refusal',watcher=suspended,wrapper=refused,spend_txid=revoked['txid'],mempool=rpc('getrawmempool',False))
 assert suspended['watch']['state']=='SUSPEND' and not refused['verified']
 binding['Prior']=suspended['watch'];mine()
 final=bridge('watch',policy,binding);final_refusal=bridge('verify',policy,binding)
 reg_stage('one-block-final-refusal',watcher=final,wrapper=final_refusal,spend_transaction=public_tx(revoked['txid']))
 assert final['watch']['state']=='FINALREVOKED' and not final_refusal['verified']
 new_request=sign_request(2)
 # Cryptographic validity is checked independently using real unchanged CLI.
 config={'type':'grants-local-enrollment-2','owner_mxid':'@operator:example.invalid','owner_spki':base64.urlsafe_b64encode(owner_der).decode().rstrip('='),'requester_spki':base64.urlsafe_b64encode(requester_der).decode().rstrip('='),'subject':subject,'audience':audience,'cycle':cycle,'organization':'relux-works','name':'matrix-grants-poc-261031','state_dir':'/private/ABSENT-STATE','gh_path':'/private/ABSENT-PROVIDER'}
 # CLI requires an owner-private config, so copy only this public-pin configuration into verifier custody.
 config_path=P('/private/actors/verifier/private/config.json');config_path.write_text(json.dumps(config,separators=(',',':'),sort_keys=True));os.chmod(config_path,0o600)
 valid,_=run('verifier',['/bin/keyvault','grants','verify','--config','/private/config.json','--certificate','/public/certificate.json','--request','/public/request2.json','--at',stamp()])
 valid=json.loads(valid);assert valid['verdict']=='accepted'
 subsequent=bridge('verify',policy,binding,'request2.json')
 reg_stage('new-cryptographically-valid-request-still-refused',unchanged_cli=valid,wrapper=subsequent,request_sha256=H(new_request))
 assert not subsequent['verified']
 # Export public wire bytes only, never test keys, RPC configuration or wallet data.
 for name in ['owner.der','requester.der','certificate.json','request.json','request2.json']:
  (OUT/name).write_bytes((PUBLIC/name).read_bytes())
 status='PASS'
except Exception as e:
 reg_stage('actual-failure',error=str(e),traceback=traceback.format_exc())
finally:
 for p,item in reversed(children):
  if p.poll() is None:
   try:
    if birth(p.pid)==item['birth']:os.killpg(p.pid,signal.SIGTERM)
    p.wait(timeout=5)
   except subprocess.TimeoutExpired:
    if p.poll() is None and birth(p.pid)==item['birth']:os.killpg(p.pid,signal.SIGKILL)
    p.wait(timeout=3)
   finish(p,item)
 (OUT/'child-receipts.json').write_text(json.dumps(children and [i for p,i in children],indent=2)+'\n')
 (OUT/'bridge-public-reads.json').write_text(json.dumps(reads,indent=2)+'\n')
 (OUT/'actual-result.json').write_text(json.dumps({'status':status,'finished_at':stamp(),'elapsed_seconds':time.monotonic()-started,'rpc_calls':rpc_count,'children_reaped':all(p.poll() is not None for p,i in children),'actual_separate_OS_users':False,'actor_filesystem_roots':True,'original_acceptance':accept,'bounds':{'wall_seconds':600,'RPC_calls':1800,'actor_command_seconds':15,'bridge_seconds':20,'kill_reap_seconds':8,'export_reserve_seconds':120}},indent=2)+'\n')
sys.exit(0 if status=='PASS' else 1)
