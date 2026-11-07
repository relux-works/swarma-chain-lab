"""Thin read-only protocol driver: no node RPC, cookie, wallet or full chain reads.
Uses unchanged pinned ElectrumX Merkle and Namecoin transaction/script parsers.
It checks inclusion against an explicitly supplied trusted laboratory checkpoint;
it is not a consensus SPV client or a latest-state/completeness verifier.
"""
import asyncio,json,time,sys,hashlib,copy
from electrumx.lib.merkle import Merkle
from electrumx.lib.coins import NamecoinRegtest as Coin
from electrumx.lib.script import Script
M=Merkle()
def h(x):return hashlib.sha256(hashlib.sha256(x).digest()).digest()
def sh(x):return hashlib.sha256(x).digest()[::-1].hex()
def fold(txid,branch,pos):
 assert len(branch)<=30 and pos>=0 and all(len(bytes.fromhex(x))==32 for x in branch)
 return M.root_from_proof(bytes.fromhex(txid)[::-1],[bytes.fromhex(x)[::-1] for x in branch],pos)[::-1].hex()
def header_proof(obj,height,anchor):
 if not isinstance(anchor,dict):raise ValueError('checkpoint must be an object')
 checkpoint_height=anchor.get('height')
 # Match fold's existing 30-level limit; bool is not an integer height.
 if type(checkpoint_height) is not int or not 0<=checkpoint_height<1<<30:
  raise ValueError('checkpoint height must be an integer in [0, 2**30)')
 root=anchor.get('root')
 if not isinstance(root,str) or len(root)!=64 or len(bytes.fromhex(root))!=32:
  raise ValueError('checkpoint root must be a 32-byte hex string')
 # An odd-width tree pads its last leaf: folding alone cannot bound positions.
 if type(height) is not int or not 0<=height<=checkpoint_height:
  raise ValueError('entry height must be an integer within the checkpoint')
 raw=bytes.fromhex(obj['header']);assert len(raw)==80
 assert obj['root']==anchor['root'], 'untrusted checkpoint root'
 assert len(obj['branch'])==M.branch_length(checkpoint_height+1)
 got=fold(h(raw)[::-1].hex(),obj['branch'],height)
 assert got==anchor['root'],'checkpoint membership mismatch'
 return raw

def txproof(rawhex,txid,proof,header):
 tx=Coin.DESERIALIZER(bytes.fromhex(rawhex)).read_tx()
 assert tx.txid_rev[::-1].hex()==txid,'transaction ID mismatch'
 root=fold(txid,proof['merkle'],proof['pos'])
 assert root==header[36:68][::-1].hex(),'transaction Merkle mismatch'
 return tx

def parse_name(tx,name):
 found=[]
 for i,out in enumerate(tx.outputs):
  named,addr=Coin.interpret_name_prefix(out.pk_script,Coin.NAME_OPERATIONS)
  if named and named.get('name',(None,None))[1]==name.encode():
   # Match the already parsed operation's exact push bytes without inventing a validator.
   ops=Script.get_ops(out.pk_script)
   vals=[op[1] for op in ops if isinstance(op,tuple)]
   # firstupdate: name,salt,value; update: name,value
   assert vals[0]==name.encode()
   found.append({'vout':i,'value':vals[2 if out.pk_script[0]==82 else 1].decode(),'script':out.pk_script.hex(),'address_script':addr.hex()})
 assert len(found)==1, 'exactly one requested name output required'
 return found[0]

class Client:
 total_requests=0
 total_received=0
 def __init__(self):self.reader=None;self.writer=None;self.pending={};self.seq=0;self.records=[];self.notes=[];self.requests=0;self.received=0;self.max_frames=10000000
 async def connect(self,port=50001,version='1.4.3'):
  self.reader,self.writer=await asyncio.open_connection('127.0.0.1',port,limit=self.max_frames+1)
  self.task=asyncio.create_task(self.read())
  return await self.call('server.version',['thin-regtest-fixture',version])
 async def read(self):
  try:
   while line:=await self.reader.readline():
    self.received+=len(line);Client.total_received+=len(line);assert Client.total_received<=64*1024**2
    obj=json.loads(line);t=time.monotonic_ns();self.records.append({'direction':'receive','mono_ns':t,'message':obj})
    if 'method' in obj:self.notes.append({'mono_ns':t,'message':obj})
    elif obj.get('id') in self.pending:
     f=self.pending.pop(obj['id']);f.set_result(obj)
  except Exception as e:
   for f in self.pending.values():
    if not f.done():f.set_exception(e)
 async def call(self,method,params):
  self.requests+=1;Client.total_requests+=1;assert Client.total_requests<=256
  self.seq+=1;idx=self.seq
  obj={'jsonrpc':'2.0','id':idx,'method':method,'params':params}
  f=asyncio.get_running_loop().create_future();self.pending[idx]=f
  self.records.append({'direction':'send','mono_ns':time.monotonic_ns(),'message':obj})
  self.writer.write(json.dumps(obj).encode()+b'\n');await self.writer.drain()
  answer=await asyncio.wait_for(f,5)
  if 'error' in answer:raise RuntimeError('PROTOCOL_ERROR '+json.dumps(answer['error']))
  return answer['result']
 async def close(self):
  if self.writer:self.writer.close();await self.writer.wait_closed()
  if hasattr(self,'task'):self.task.cancel();await asyncio.gather(self.task,return_exceptions=True)
 async def proof(self,txid,height,anchor,name=None):
  raw=await self.call('blockchain.transaction.get',[txid])
  merkle=await self.call('blockchain.transaction.get_merkle',[txid,height])
  hp=await self.call('blockchain.block.header',[height,anchor['height']])
  head=header_proof(hp,height,anchor)
  assert merkle['block_height']==height
  tx=txproof(raw,txid,merkle,head)
  out={'txid':txid,'height':height,'header_hash':h(head)[::-1].hex(),'transaction_bytes':len(bytes.fromhex(raw)),'verified':'txid_and_transaction_merkle_inclusion_and_header_checkpoint_membership'}
  if name:out['name_output']=parse_name(tx,name)
  return out
