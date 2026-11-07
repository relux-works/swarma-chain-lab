"""Bounded disposable closed-world regtest supervisor. Export allowlisted public evidence only."""
import os,sys,time,json,asyncio,subprocess,pathlib,http.client,base64,threading,http.server,signal,hashlib,traceback,resource,statistics,copy,socket,struct
from datetime import datetime,timezone
from thin import Client,h,sh,fold,header_proof,txproof,parse_name,Coin,M
P=pathlib.Path
os.umask(0o077)
START=time.monotonic();STARTUTC=datetime.now(timezone.utc).isoformat()
DEADLINE=min(time.time()+1400,datetime.fromisoformat('2026-11-07T06:27:46.931651+00:00').timestamp())
R={'started_at':STARTUTC,'status':'RUNNING','rpc_calls':[],'scenarios':{},'processes':[],'resource_samples':[],'protocol_receipts':[]}
CHILDREN=[];SECRETS=[];COOKIE=None;SERVERS=[];RPC_ID=0;RPC_LOCK=threading.Lock();CLIENTS=[]
LAB=P('/lab');NODE=LAB/'node';ENV=None;SERVER=None

def utc():return datetime.now(timezone.utc).isoformat()
def scrub(s):
 for secret in SECRETS:s=s.replace(secret,'<redacted ephemeral RPC auth>')
 return s

def emit(kind,obj):
 print(json.dumps({'kind':kind,'at':utc(),'data':obj},default=str),flush=True)

def bounds():
 if time.time()>DEADLINE:raise RuntimeError('immutable wall/export reserve bound reached')
 fs=os.statvfs('/lab');used=(fs.f_blocks-fs.f_bfree)*fs.f_frsize
 if used>int(1610612736*.8):raise RuntimeError('private tmpfs 80% stop threshold reached')
 return used

def rpc(method,*params,wallet='',record=True):
 global RPC_ID,COOKIE
 bounds();t=time.monotonic_ns();a=utc()
 if COOKIE is None:
  COOKIE=(NODE/'regtest/.cookie').read_text().strip();SECRETS.extend([COOKIE,base64.b64encode(COOKIE.encode()).decode(),COOKIE.split(':',1)[-1]])
 with RPC_LOCK:RPC_ID+=1;idx=RPC_ID
 c=http.client.HTTPConnection('127.0.0.1',18443,timeout=10)
 body=json.dumps({'jsonrpc':'1.0','id':idx,'method':method,'params':params})
 try:
  c.request('POST','/wallet/'+wallet if wallet else '/',body,{'Authorization':'Basic '+base64.b64encode(COOKIE.encode()).decode(),'Content-Type':'application/json'})
  resp=c.getresponse();raw=resp.read(12*1024**2);result=json.loads(raw)
  if record:R['rpc_calls'].append({'method':method,'start':a,'end':utc(),'elapsed_ns':time.monotonic_ns()-t,'http_status':resp.status,'rpc_error':result.get('error')})
  if result.get('error'):raise RuntimeError('RPC '+str(result['error']['code'])+': '+result['error']['message'])
  return result['result']
 finally:c.close()

READ_RPC={'getblockhash','getblockcount','getblock','getrawtransaction','getrawmempool','getmempoolinfo','getnetworkinfo','getblockchaininfo','getindexinfo','getmempoolentry','estimatefee','estimatesmartfee','gettxout'}
class RPCProxy(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  try:
   n=int(self.headers.get('Content-Length','0'));assert 0<n<1000000
   body=json.loads(self.rfile.read(n));items=body if isinstance(body,list) else [body];answers=[]
   for req in items:
    if req.get('method') not in READ_RPC:
     ans={'jsonrpc':'2.0','id':req.get('id'),'error':{'code':-32601,'message':'read-only laboratory RPC capability'}}
    else:
     try:ans={'jsonrpc':'2.0','id':req.get('id'),'result':rpc(req['method'],*req.get('params',[]),record=False),'error':None}
     except Exception as e:
      msg=scrub(str(e));ans={'jsonrpc':'2.0','id':req.get('id'),'result':None,'error':{'code':-1,'message':msg}}
    answers.append(ans)
   data=json.dumps(answers if isinstance(body,list) else answers[0]).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
  except Exception:
   self.send_error(400,'bounded fixture request rejected')

READ_ELECTRUM={'server.version','server.features','server.ping','blockchain.headers.subscribe','blockchain.block.header','blockchain.block.headers','blockchain.scripthash.subscribe','blockchain.scripthash.get_history','blockchain.scripthash.listunspent','blockchain.transaction.get','blockchain.transaction.get_merkle','blockchain.name.get_value_proof'}
FAULT={'rule':'none','responses':{}}
ADAPTER_LOG=[]
async def adapter(reader,writer,mode):
 br=bw=None
 try:
  br,bw=await asyncio.open_connection('127.0.0.1',50000,limit=10000001);pending={}
  async def upstream():
   while line:=await reader.readline():
    req=json.loads(line);method=req.get('method')
    if method not in READ_ELECTRUM:
     writer.write(json.dumps({'jsonrpc':'2.0','id':req.get('id'),'error':{'code':-32601,'message':'read-only protocol capability'}}).encode()+b'\n');await writer.drain();continue
    pending[req['id']]=(method,req.get('params',[]));bw.write(line);await bw.drain()
  async def downstream():
   while line:=await br.readline():
    obj=json.loads(line);method,params=pending.pop(obj.get('id'),(obj.get('method'),obj.get('params',[])))
    if mode=='fault' and FAULT['rule']!='none':
     key=json.dumps([method,params],sort_keys=True)
     if obj.get('method') and FAULT['rule']=='omit-seal' and params and params[0]==FAULT.get('seal_sh'):
      ADAPTER_LOG.append({'rule':'omit-seal-notification','mono_ns':time.monotonic_ns(),'message_sha256':hashlib.sha256(line).hexdigest()});continue
     if key in FAULT['responses'] and 'result' in obj:
      original=hashlib.sha256(json.dumps(obj['result'],sort_keys=True).encode()).hexdigest();obj['result']=copy.deepcopy(FAULT['responses'][key])
      ADAPTER_LOG.append({'rule':FAULT['rule'],'method':method,'params':params,'mono_ns':time.monotonic_ns(),'original_result_sha256':original,'replacement_result_sha256':hashlib.sha256(json.dumps(obj['result'],sort_keys=True).encode()).hexdigest()})
    writer.write(json.dumps(obj).encode()+b'\n');await writer.drain()
  tasks=[asyncio.create_task(upstream()),asyncio.create_task(downstream())]
  await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
  for t in tasks:t.cancel()
  await asyncio.gather(*tasks,return_exceptions=True)
 except Exception as e:ADAPTER_LOG.append({'adapter_error':scrub(str(e))})
 finally:
  for w in [writer,bw]:
   if w:w.close()

async def arpc(method,*args,wallet=''):return await asyncio.to_thread(rpc,method,*args,wallet=wallet)
def spawn(role,args,env=None):
 f=open('/lab/'+role+'.log','wb');p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,env=env);CHILDREN.append((role,p,f));R['processes'].append({'role':role,'pid_inside_namespace':p.pid,'start':utc(),'argv':args});return p

async def waitrpc():
 until=time.monotonic()+30
 while time.monotonic()<until:
  if CHILDREN[0][1].poll() is not None:raise RuntimeError('node exited before RPC readiness')
  try:return await arpc('getblockchaininfo')
  except Exception:await asyncio.sleep(.1)
 raise RuntimeError('Core RPC readiness timeout 30s')

async def waitindex(c,height):
 until=time.monotonic()+15
 while time.monotonic()<until:
  info=await c.call('blockchain.headers.subscribe',[])
  if info['height']==height:return {'mono_ns':time.monotonic_ns(),'tip':info}
  await asyncio.sleep(.25)
 raise RuntimeError('index readiness timeout 15s')

async def anchor(height):
 # Oracle computes a checkpoint commitment; only height/root reach the thin verifier.
 hashes=[]
 for i in range(height+1):hashes.append(bytes.fromhex(await arpc('getblockhash',i))[::-1])
 return {'height':height,'root':M.root(hashes)[::-1].hex(),'trust':'out-of-band local fully validating Core oracle; not self-authenticated by server'}

async def connect(version='1.4.3',port=50001):
 c=Client();CLIENTS.append(c);a=await c.connect(port,version);R.setdefault('negotiations',[]).append({'port':port,'requested':version,'result':a});return c

def samples():
 used=bounds();rows=[]
 for role,p,f in CHILDREN:
  if p.poll() is None:
   st=P('/proc/'+str(p.pid)+'/status').read_text();mem={ln.split(':')[0]:ln.split(':')[1].strip() for ln in st.splitlines() if ln.startswith(('VmRSS:','VmHWM:','Threads:'))};rows.append({'role':role,**mem})
 R['resource_samples'].append({'at':utc(),'private_tmpfs_bytes':used,'processes':rows})

async def main():
 global ENV,SERVER
 for n in ['home','tmp','cache','node','index']:(LAB/n).mkdir(mode=0o700)
 os.sched_setaffinity(0,set(sorted(os.sched_getaffinity(0))[:2]))
 assert os.environ['HOME']=='/lab/home' and os.environ['TMPDIR']=='/lab/tmp'
 assert not list(P('/home').iterdir()) and not P('/run').exists()
 assert 'SSH_AUTH_SOCK' not in os.environ
 R['boundary']={'net_ns':os.readlink('/proc/self/ns/net'),'pid_ns':os.readlink('/proc/self/ns/pid'),'uid':os.getuid(),'tcp_before':P('/proc/net/tcp').read_text(),'route':P('/proc/net/route').read_text(),'cpu_affinity':sorted(os.sched_getaffinity(0)),'mountinfo':P('/proc/self/mountinfo').read_text(),'env_keys':sorted(os.environ),'lab_tmpfs_bytes':os.statvfs('/lab').f_blocks*os.statvfs('/lab').f_frsize}
 for d in ['/src','/tools','/runtime']:
  try:
   fd=os.open(d+'/.write-probe',os.O_CREAT|os.O_WRONLY,0o600);os.close(fd);raise RuntimeError('readonly mount failed '+d)
  except OSError as e:assert e.errno==30
 nodeargs=['/runtime/node/namecoind','-regtest','-datadir=/lab/node','-server=1','-listen=0','-dnsseed=0','-discover=0','-connect=0','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1','-rpcport=18443','-txindex=1','-assumevalid=0','-dbcache=64','-par=2','-rpcthreads=2','-rpcworkqueue=16','-fallbackfee=0.002','-deprecatedrpc=create_bdb','-printtoconsole=0','-debuglogfile=0','-maxmempool=16']
 node=spawn('core',nodeargs);info=await waitrpc();assert info['chain']=='regtest' and info['blocks']==0
 genesis=await arpc('getblockhash',0);assert genesis==Coin.GENESIS_HASH
 R['genesis']={'chain':info['chain'],'hash':genesis,'note':'Namecoin and Bitcoin regtest share genesis; chain binding also needs independent checkpoint/consensus context'}
 await arpc('createwallet','fixture');miner=await arpc('getnewaddress','','legacy',wallet='fixture');owner=await arpc('getnewaddress','','legacy',wallet='fixture');notice=await arpc('getnewaddress','','legacy',wallet='fixture');seal=await arpc('getnewaddress','','legacy',wallet='fixture')
 await arpc('generatetoaddress',200,miner)
 name='d/closed-fixture';new=await arpc('name_new',name,wallet='fixture');await arpc('generatetoaddress',12,miner)
 R['fixture']={'name':name,'miner_public_address':miner,'owner_public_address':owner,'notification_public_address':notice,'seal_public_address':seal,'commitment_txid':new[0],'initial_maturity_blocks':200,'commitment_wait_blocks':12}
 rpcserver=http.server.ThreadingHTTPServer(('127.0.0.1',18444),RPCProxy);rpcserver.daemon_threads=True;threading.Thread(target=rpcserver.serve_forever,daemon=True).start();SERVERS.append(rpcserver)
 ENV=dict(os.environ);ENV.update(COIN='Namecoin',NET='regtest',DAEMON_URL='http://fixture:readonly@127.0.0.1:18444',DB_DIRECTORY='/lab/index',DB_ENGINE='leveldb',CACHE_MB='128',SERVICES='tcp://127.0.0.1:50000',REPORT_SERVICES='',PEER_DISCOVERY='off',PEER_ANNOUNCE='',MAX_SESSIONS='2',MAX_SEND='10000000',MAX_RECV='1000000',INITIAL_CONCURRENT='1',LOG_LEVEL='info',ANON_LOGS='1')
 R['server_config']={k:v for k,v in ENV.items() if k not in os.environ};R['server_cost_limits']={'COST_SOFT_LIMIT':1000,'COST_HARD_LIMIT':10000,'BW_UNIT_COST':5000,'REQUEST_SLEEP_ms':2500,'REQUEST_TIMEOUT_seconds':30,'DAEMON_POLL_INTERVAL_BLOCKS_ms':5000,'DAEMON_POLL_INTERVAL_MEMPOOL_ms':5000,'modified':False}
 SERVER=spawn('electrumx',['/usr/bin/python3','-m','electrumx.cli.electrumx_server'],ENV)
 until=time.monotonic()+45
 while time.monotonic()<until:
  if SERVER.poll() is not None:raise RuntimeError('ElectrumX exited during initial index')
  try:
   rd,wr=await asyncio.open_connection('127.0.0.1',50000);wr.close();await wr.wait_closed();break
  except OSError:await asyncio.sleep(.2)
 else:raise RuntimeError('ElectrumX initial readiness timeout 45s')
 for port,mode in [(50001,'normal'),(50002,'fault'),(50003,'normal')]:
  srv=await asyncio.start_server(lambda rd,wr,m=mode:adapter(rd,wr,m),'127.0.0.1',port,limit=10000001);SERVERS.append(srv)
 c=await connect('1.4.1');features=await c.call('server.features',[]);assert features['genesis_hash']==genesis
 R['server_features']=features;await waitindex(c,212)
 if '--smoke' in sys.argv:
  R['status']='SMOKE_START_STOP_COMPLETE';return
 # Prove client-facing and backend RPC read-only gates before any workload.
 try:await c.call('blockchain.transaction.broadcast',['00'])
 except Exception as e:R['readonly_protocol_control']={'rejected':True,'error':str(e)}
 else:raise RuntimeError('broadcast policy failure')
 endpoint=http.client.HTTPConnection('127.0.0.1',18444,timeout=5);endpoint.request('POST','/',json.dumps({'id':1,'method':'sendrawtransaction','params':['00']}),{'Content-Type':'application/json'});rr=json.loads(endpoint.getresponse().read());endpoint.close();assert rr['error']['code']==-32601;R['readonly_rpc_control']=rr
 scripts={}
 for label,addr in [('owner',owner),('notification',notice),('seal',seal)]:scripts[label]=(await arpc('getaddressinfo',addr,wallet='fixture'))['scriptPubKey']
 scripts['name_index']=Coin.build_name_index_script(name.encode()).hex();hashes={k:sh(bytes.fromhex(v)) for k,v in scripts.items()};R['subscriptions']={k:{'script':scripts[k],'scripthash':v,'initial_status':await c.call('blockchain.scripthash.subscribe',[v])} for k,v in hashes.items()}
 samples();rows=[];saved_name=[];sealinfo=None
 async def trigger(label,make_tx,expected,nameproof=False):
  txid=await make_tx();before_note=len(c.notes);dispatch=time.monotonic_ns();dispatchutc=utc();blocks=await arpc('generatetoaddress',1,miner);returned=time.monotonic_ns();height=await arpc('getblockcount');ix=await waitindex(c,height)
  until=time.monotonic()+12
  while time.monotonic()<until:
   notes=[n for n in c.notes[before_note:] if n['message'].get('method')=='blockchain.scripthash.subscribe' and n['message']['params'][0] in [hashes[k] for k in expected]]
   have={n['message']['params'][0] for n in notes}
   if all(hashes[k] in have for k in expected):break
   await asyncio.sleep(.05)
  else:raise RuntimeError('notification timeout 12s '+label)
  # Keep only confirmed notifications whose status equals fetched post-mine history.
  statuses={}
  for k in expected:
   hist=await c.call('blockchain.scripthash.get_history',[hashes[k]])
   status=hashlib.sha256(''.join(f"{x['tx_hash']}:{x['height']}:" for x in hist).encode()).hexdigest() if hist else None
   statuses[k]={'history':hist,'status':status}
  matched=[n for n in notes if any(n['message']['params']==[hashes[k],statuses[k]['status']] for k in expected)]
  assert all(any(n['message']['params']==[hashes[k],statuses[k]['status']] for n in matched) for k in expected),'no confirmed status notification'
  first=min(n['mono_ns'] for n in matched);a=await anchor(height);proof=await c.proof(txid,height,a,name if nameproof else None);verified=time.monotonic_ns()
  row={'label':label,'txid':txid,'height':height,'blockhash':blocks[0],'mining_dispatch_utc':dispatchutc,'dispatch_ns':dispatch,'return_ns':returned,'index_observed_ns':ix['mono_ns'],'confirmed_notification_ns':first,'verified_ns':verified,'dispatch_to_notification_ms':(first-dispatch)/1e6,'return_to_notification_ms':(first-returned)/1e6,'index_observed_to_notification_ms':(first-ix['mono_ns'])/1e6,'notification_to_verified_ms':(verified-first)/1e6,'expected_scripts':expected,'histories':statuses,'anchor':a,'proof_verification':proof}
  if nameproof:
   oracle=await arpc('name_show',name);assert oracle['txid']==txid and oracle['value']==proof['name_output']['value'];row['node_name_oracle']={k:oracle[k] for k in ['name','value','txid','vout','height'] if k in oracle};saved_name.append(row)
  rows.append(row);R['trigger_observations']=rows;samples();emit('trigger',row);return txid
 async def first():return await arpc('name_firstupdate',name,new[1],new[0],'value-0',{'destAddress':owner},wallet='fixture')
 await trigger('name_firstupdate',first,['owner','name_index'],True)
 for i in [1,2]:
  async def upd(i=i):return await arpc('name_update',name,'value-'+str(i),{'destAddress':owner},wallet='fixture')
  await trigger('name_update_'+str(i),upd,['owner','name_index'],True)
 # Switch to 1.4.3 and exercise the protocol-provided name bundle against current trusted checkpoint.
 await c.close();c=await connect('1.4.3')
 for v in hashes.values():await c.call('blockchain.scripthash.subscribe',[v])
 tip=await arpc('getblockcount');a=await anchor(tip);bundle=await c.call('blockchain.name.get_value_proof',[hashes['name_index'],tip]);assert hashes['name_index'] in bundle
 verified_bundle=[]
 for entry in bundle[hashes['name_index']]:
  head=header_proof(entry['header'],entry['height'],a);tx=Coin.DESERIALIZER(bytes.fromhex(entry['tx'])).read_tx();txid=tx.txid_rev[::-1].hex();txproof(entry['tx'],txid,entry['tx_merkle'],head);verified_bundle.append({'txid':txid,'height':entry['height'],'name_output':parse_name(tx,name)})
 assert verified_bundle[0]['name_output']['value']=='value-2'
 R['name_value_proof']={'anchor':a,'wire_bundle':bundle,'verified_entries':verified_bundle,'coverage':'inclusion of supplied name output; not latest-state, omission, script signatures, full consensus or AuxPoW validation'}
 # Actual nonzero checkpoint-header regression exercise using real mined headers.
 no_cp=await c.call('blockchain.block.headers',[210,2,0]);cp_equal=await c.call('blockchain.block.headers',[210,2,211]);cp_later=await c.call('blockchain.block.headers',[210,2,tip]);single=[await c.call('blockchain.block.header',[i,tip]) for i in [210,211]]
 assert cp_equal['count']==2 and len(cp_equal['hex'])==320 and cp_later['hex']==''.join(x['header'] for x in single)
 assert fold(h(bytes.fromhex(cp_later['hex'][-160:]))[::-1].hex(),cp_later['branch'],211)==a['root']
 R['real_header_controls']={'no_checkpoint':no_cp,'checkpoint_equal':cp_equal,'checkpoint_later':cp_later,'individual':single,'representative_mainnet_auxpow':'NOT_QUALIFIED'}
 try:await c.call('blockchain.block.headers',[210,2,210])
 except Exception as e:R['bad_checkpoint_control']={'detected':True,'actual_error':str(e)}
 else:raise RuntimeError('bad checkpoint not rejected')
 # Shared mutable client reference means trigger uses the newly negotiated client.
 for i in range(4):
  async def pay():return await arpc('sendtoaddress',notice,0.01,wallet='fixture')
  await trigger('notification_payment_'+str(i+1),pay,['notification'])
 async def fundseal():return await arpc('sendtoaddress',seal,0.01,wallet='fixture')
 seal_tx=await trigger('seal_create',fundseal,['seal'])
 decoded=await arpc('getrawtransaction',seal_tx,True);vout=next(x['n'] for x in decoded['vout'] if x['scriptPubKey']['hex']==scripts['seal']);sealinfo={'txid':seal_tx,'vout':vout}
 # Capture genuine earlier evidence for the omission adapter; all responses are actual pre-spend protocol bytes.
 pre={m:await c.call(m,[hashes['seal']]) for m in ['blockchain.scripthash.get_history','blockchain.scripthash.listunspent','blockchain.scripthash.subscribe']}
 R['seal_spend_fixture_fee']={'input_nmc':0.01,'output_nmc':0.0096,'fee_nmc':0.0004,'reason':'first attempt preserved Core -26: min relay fee not met, 10000 < 19100; no relay-policy change'}
 R['seal_unspent_positive_control']={'outpoint':sealinfo,'node_unspent':await arpc('gettxout',seal_tx,vout),'wire':pre}
 fault=await connect('1.4.3',50002);await fault.call('blockchain.scripthash.subscribe',[hashes['seal']])
 FAULT.update(rule='omit-seal',seal_sh=hashes['seal'],responses={json.dumps([m,[hashes['seal']]],sort_keys=True):v for m,v in pre.items()})
 fault_note_before=len(fault.notes)
 async def spendseal():
  raw=await arpc('createrawtransaction',[sealinfo],{notice:0.0096});signed=await arpc('signrawtransactionwithwallet',raw,wallet='fixture');assert signed['complete'];return await arpc('sendrawtransaction',signed['hex'])
 spend=await trigger('seal_spend',spendseal,['seal','notification'])
 stale={m:await fault.call(m,[hashes['seal']]) for m in ['blockchain.scripthash.get_history','blockchain.scripthash.listunspent','blockchain.scripthash.subscribe']}
 honest={m:await c.call(m,[hashes['seal']]) for m in ['blockchain.scripthash.get_history','blockchain.scripthash.listunspent']}
 assert stale['blockchain.scripthash.get_history']==pre['blockchain.scripthash.get_history'] and stale['blockchain.scripthash.listunspent']==pre['blockchain.scripthash.listunspent']
 assert honest['blockchain.scripthash.listunspent']==[] and await arpc('gettxout',seal_tx,vout) is None
 assert all(n['message'].get('method')!='blockchain.scripthash.subscribe' for n in fault.notes[fault_note_before:])
 # Validate included old transaction proof even while the spend is omitted.
 tip=await arpc('getblockcount');a=await anchor(tip);fundheight=next(x['height'] for x in rows if x['label']=='seal_create');oldproof=await fault.proof(seal_tx,fundheight,a)
 R['scenarios']['omitted_seal_spend']={'single_server':'UNDETECTED_WITH_SINGLE_SERVER_INCLUSION_EVIDENCE','two_view_comparison':'DETECTED_DISAGREEMENT','node_oracle':'DETECTED_SPENT','notification_suppressed':True,'faulty_wire':stale,'honest_wire':honest,'funding_inclusion_still_verifies':oldproof,'no_unspent_completeness_claim':True,'spend_txid':spend}
 R['scenarios']['two_disagreeing_servers']={'detected':stale['blockchain.scripthash.get_history']!=honest['blockchain.scripthash.get_history'],'views_share_one_backend':True,'independent_operators':False,'evidence':'retained faulty and honest seal history/unspent responses'}
 FAULT.update(rule='none',responses={});await fault.close()
 async def paylast():return await arpc('sendtoaddress',notice,0.01,wallet='fixture')
 await trigger('notification_payment_5',paylast,['notification'])
 # Replay an earlier valid, still included name proof. Inclusion alone cannot identify the latest value.
 tip=await arpc('getblockcount');a=await anchor(tip);current=await c.call('blockchain.name.get_value_proof',[hashes['name_index'],tip])
 old=saved_name[0];raw=await c.call('blockchain.transaction.get',[old['txid']]);mp=await c.call('blockchain.transaction.get_merkle',[old['txid'],old['height']]);hp=await c.call('blockchain.block.header',[old['height'],tip]);mp.pop('block_height')
 stale_bundle={hashes['name_index']:[{'height':old['height'],'tx':raw,'tx_merkle':mp,'header':hp}]}
 FAULT.update(rule='stale-name',responses={json.dumps(['blockchain.name.get_value_proof',[hashes['name_index'],tip]],sort_keys=True):stale_bundle})
 bad=await connect('1.4.3',50002);got=await bad.call('blockchain.name.get_value_proof',[hashes['name_index'],tip]);entry=got[hashes['name_index']][0];head=header_proof(entry['header'],entry['height'],a);tx=Coin.DESERIALIZER(bytes.fromhex(entry['tx'])).read_tx();txproof(entry['tx'],tx.txid_rev[::-1].hex(),entry['tx_merkle'],head);oldname=parse_name(tx,name);assert oldname['value']=='value-0'
 known_newer_conflict=entry['height']<saved_name[-1]['height'] and oldname['value']!=saved_name[-1]['proof_verification']['name_output']['value'];assert known_newer_conflict
 R['scenarios']['stale_name']={'known_newer_conflict_evaluated':known_newer_conflict,'single_server_inclusion_only':'UNDETECTED_AS_STALE','known_newer_txid_control':'DETECTED_CONFLICT_WITH_PREVIOUSLY_VERIFIED_UPDATE','node_oracle':'DETECTED_CURRENT_VALUE_value-2','faulty_wire':got,'honest_wire':current,'trusted_checkpoint':a,'old_inclusion_and_name_output_verify':True,'freshness_timer':'NOT_A_COMPLETENESS_PROOF'}
 FAULT.update(rule='none',responses={});await bad.close()
 # Wrong-chain uses the actual canonical mainnet genesis header, not invalid synthetic bytes; checkpoint membership is not full SPV.
 hp=await c.call('blockchain.block.header',[old['height'],tip]);head=header_proof(hp,old['height'],a)
 mainnet_genesis=struct.pack('<I',1)+bytes(32)+bytes.fromhex('41c62dbd9068c89a449525e3cd5ac61b20ece28c3c38b3f35b2161f0e6d3cb0d')[::-1]+struct.pack('<III',1303000001,0x1c007fff,0xa21ea192)
 assert h(mainnet_genesis)[::-1].hex()=='000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770'
 wrong=copy.deepcopy(hp);wrong['header']=mainnet_genesis.hex()
 FAULT.update(rule='wrong-chain-header',responses={json.dumps(['blockchain.block.header',[old['height'],tip]],sort_keys=True):wrong})
 bad=await connect('1.4.3',50002);got=await bad.call('blockchain.block.header',[old['height'],tip])
 try:header_proof(got,old['height'],a)
 except Exception as e:R['scenarios']['wrong_chain_header']={'detected':True,'reason':str(e),'positive_control':'unchanged actual header checkpoint proof verifies','fault':'valid canonical Namecoin mainnet genesis header substituted for a regtest header; independently hash-matched to pinned Core chainparams.cpp:168-171','foreign_header_hash':h(mainnet_genesis)[::-1].hex(),'full_consensus_or_spv_claim':False,'wire':got}
 else:raise RuntimeError('foreign header not detected')
 FAULT.update(rule='none',responses={});await bad.close()
 tamper=copy.deepcopy(hp);tamper['root']='00'*32
 try:header_proof(tamper,old['height'],a)
 except Exception as e:R['tampered_checkpoint_control']={'detected':True,'reason':str(e)}
 else:raise RuntimeError('tampered root not detected')
 txid=old['txid'];realmp=await c.call('blockchain.transaction.get_merkle',[txid,old['height']]);tamp=copy.deepcopy(realmp);tamp['merkle'][0]='00'*32
 try:txproof(raw,txid,tamp,head)
 except Exception as e:R['tampered_merkle_control']={'detected':True,'reason':str(e)}
 else:raise RuntimeError('tampered Merkle not detected')
 # Cap and 1.6 array semantics use the same canonical server after releasing the other connection.
 cap=await c.call('blockchain.block.headers',[210,2017,tip]);assert cap['count']==tip-210+1 and cap['max']==2016
 R['bounded_chunk_control']={'requested':2017,'actual_count':cap['count'],'server_max':cap['max'],'tip_truncation':True,'wire_bytes':len(json.dumps(cap))}
 await c.close();v16=await connect('1.6');arr=await v16.call('blockchain.block.headers',[210,2,tip]);assert len(arr['headers'])==2 and all(len(x)==160 for x in arr['headers']);R['protocol_1_6_array_control']=arr;await v16.close()
 R['latency_summary']={k:{'n':len(rows),'min':min(v),'median':statistics.median(v),'p95_nearest_rank':sorted(v)[max(0,int(len(v)*.95+.999)-1)],'max':max(v)} for k in ['dispatch_to_notification_ms','return_to_notification_ms','index_observed_to_notification_ms','notification_to_verified_ms'] for v in [[x[k] for x in rows]]}
 R['latency_limitations']=['Mining RPC dispatch/return bracket local mining call; neither is an instrumented consensus acceptance instant.','Index observation may follow notification, so its subtraction can be negative.','Notifications matched to confirmed history status; mempool notifications are retained separately.','One local isolated VM run is not a network latency guarantee.']
 R['final_state']={'height':tip,'hash':await arpc('getblockhash',tip),'name':await arpc('name_show',name),'txindex':await arpc('getindexinfo'),'connections':await arpc('getconnectioncount')}
 assert R['final_state']['connections']==0
 assert sum(x.requests for x in CLIENTS)<=256
 assert sum(x.received for x in CLIENTS)<=64*1024**2
 R['status']='PART_A_BOUNDED_OBSERVATIONS_COMPLETE_REVIEW_REQUIRED'

async def finish():
 R['cleanup']={'start':utc(),'children':[]}
 for c in CLIENTS:
  try:await c.close()
  except Exception:pass
 for s in SERVERS:
  try:
   if isinstance(s,asyncio.Server):s.close();await s.wait_closed()
   else:s.shutdown();s.server_close()
  except Exception as e:R['cleanup'].setdefault('errors',[]).append(scrub(str(e)))
 # Stop index first, flush, then the private validating daemon.
 for role,p,f in reversed(CHILDREN):
  if p.poll() is None:
   if role=='core':
    try:await arpc('stop')
    except Exception: p.terminate()
   else:p.send_signal(signal.SIGINT)
  try:await asyncio.to_thread(p.wait,20)
  except subprocess.TimeoutExpired:
   p.terminate()
   try:await asyncio.to_thread(p.wait,10)
   except subprocess.TimeoutExpired:p.kill();await asyncio.to_thread(p.wait,5)
  f.close();R['cleanup']['children'].append({'role':role,'exit':p.returncode,'drained_at':utc()})
 samples()
 for role,p,f in CHILDREN:
  # Export exact logs after credential substitutions; logs are bounded by file ulimit.
  data=P('/lab/'+role+'.log').read_text(errors='replace');R.setdefault('service_logs',{})[role]=scrub(data[-200000:])
 R['protocol_receipts']=[{'client_index':i,'requests':c.requests,'received_bytes':c.received,'records':c.records} for i,c in enumerate(CLIENTS)]
 R['adapter_receipts']=ADAPTER_LOG
 R['cleanup']['retained_private_bytes_by_directory']={n:sum(p.lstat().st_blocks*512 for p in (LAB/n).rglob('*') if not p.is_symlink()) for n in ['node','index','home','tmp','cache']}
 R['cleanup']['all_children_reaped']=all(p.poll() is not None for _,p,_ in CHILDREN)
 R['cleanup']['tcp_after']=P('/proc/net/tcp').read_text();R['cleanup']['end']=utc()
 R['cleanup']['private_state_disposal']='ephemeral tmpfs disappears at namespace exit; no wallet, cookie, private key or chain directory exported'
 R['end']=utc();R['elapsed_seconds']=time.monotonic()-START;R['children_rusage']=list(resource.getrusage(resource.RUSAGE_CHILDREN))
 serialized=json.dumps(R,default=str)
 for sec in SECRETS:
  if sec in serialized:serialized=serialized.replace(sec,'<redacted ephemeral RPC auth>')
 emit('final',json.loads(serialized))

async def entry():
 try:await main()
 except BaseException as e:
  R['status']='STOPPED_PARTIAL';R['failure']={'type':type(e).__name__,'cause':scrub(str(e)),'traceback':scrub(traceback.format_exc()),'at':utc()}
 finally:await finish()
 if R['status']=='STOPPED_PARTIAL':sys.exit(1)
asyncio.run(entry())
