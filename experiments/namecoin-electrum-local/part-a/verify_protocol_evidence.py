"""Replay real protocol inclusion proofs offline with no node, cookie or chain mounts."""
import json,hashlib,pathlib,copy
from thin import header_proof,txproof,parse_name,h,fold
P=pathlib.Path
r=json.loads(P('/inputs/proof-evidence.json').read_text())
assert not P('/lab').exists() and not P('/runtime/node').exists()
assert not list(P('/home').iterdir())
responses={}
for client in r['protocol_receipts']:
 pending={}
 for row in client['records']:
  msg=row['message']
  if row['direction']=='send':pending[msg['id']]=(msg['method'],msg['params'])
  elif 'id' in msg and msg['id'] in pending and 'result' in msg:
   method,params=pending.pop(msg['id']);responses.setdefault(json.dumps([method,params],sort_keys=True),[]).append(msg['result'])
def answer(method,params):return responses[json.dumps([method,params],sort_keys=True)][0]
checked=[]
for row in r['trigger_observations']:
 txid=row['txid'];height=row['height'];anchor=row['anchor']
 raw=answer('blockchain.transaction.get',[txid]);mp=answer('blockchain.transaction.get_merkle',[txid,height]);hp=answer('blockchain.block.header',[height,anchor['height']])
 header=header_proof(hp,height,anchor);tx=txproof(raw,txid,mp,header)
 assert h(header)[::-1].hex()==row['blockhash']
 name=None
 if row['label'].startswith('name_'):
  name=parse_name(tx,r['fixture']['name']);assert name==row['proof_verification']['name_output']
 all_matching_notes=[]
 for k,data in row['histories'].items():
  hist=data['history'];got=hashlib.sha256(''.join(f"{x['tx_hash']}:{x['height']}:" for x in hist).encode()).hexdigest() if hist else None
  assert got==data['status']
  matched=[]
  for c in r['protocol_receipts']:
   for e in c['records']:
    msg=e['message']
    if e['direction']=='receive' and msg.get('method')=='blockchain.scripthash.subscribe' and msg['params']==[r['subscriptions'][k]['scripthash'],got]:matched.append(e['mono_ns'])
  assert matched
  all_matching_notes.extend(matched)
 assert row['confirmed_notification_ns']==min(all_matching_notes)
 checked.append({'label':row['label'],'txid':txid,'height':height,'block_hash_matches_oracle':True,'name_output':name})
assert len(checked)==10
assert {x['label'] for x in checked}>={'name_firstupdate','name_update_1','name_update_2','seal_create','seal_spend'}
final=r['final_state'];tip_headers=[]
for c in r['protocol_receipts']:
 for e in c['records']:
  msg=e['message']
  result=msg.get('result')
  if isinstance(result,dict) and result.get('height')==final['height'] and 'hex' in result:tip_headers.append(result['hex'])
assert tip_headers and all(h(bytes.fromhex(x)[:80])[::-1].hex()==final['hash'] for x in tip_headers)
assert final['txindex']['txindex']['synced'] and final['connections']==0
s=r['scenarios'];assert s['omitted_seal_spend']['single_server'].startswith('UNDETECTED')
assert s['two_disagreeing_servers']['detected'] is True
assert s['stale_name']['known_newer_conflict_evaluated'] is True
assert s['wrong_chain_header']['detected'] is True
foreign=s['wrong_chain_header']['wire'];assert h(bytes.fromhex(foreign['header']))[::-1].hex()==s['wrong_chain_header']['foreign_header_hash']
try:header_proof(foreign,r['trigger_observations'][0]['height'],r['scenarios']['stale_name']['trusted_checkpoint'])
except AssertionError:pass
else:raise AssertionError('foreign header negative did not reject')
# Corrupting an actual transaction invalidates its recorded inclusion identity.
row=r['trigger_observations'][0];raw=answer('blockchain.transaction.get',[row['txid']]);b=bytearray.fromhex(raw);b[-1]^=1
hp=answer('blockchain.block.header',[row['height'],row['anchor']['height']]);head=header_proof(hp,row['height'],row['anchor']);mp=answer('blockchain.transaction.get_merkle',[row['txid'],row['height']])
try:txproof(b.hex(),row['txid'],mp,head)
except AssertionError:pass
else:raise AssertionError('corrupt transaction negative did not reject')
assert all(len(c['records'])<1000 for c in r['protocol_receipts'])
assert sum(c['requests'] for c in r['protocol_receipts'])<=256
assert sum(c['received_bytes'] for c in r['protocol_receipts'])<64*1024**2
listeners=[line for line in r['cleanup']['tcp_after'].splitlines()[1:] if line.split()[3]=='0A'];assert not listeners
print(json.dumps({'status':'PASS','real_proofs_checked':checked,'final_indexed_tip_matches_oracle':True,'txindex_synced':True,'corrupt_transaction_negative':'REJECTED','valid_foreign_chain_header_negative':'REJECTED','all_four_required_adversarial_outcomes_evidenced':True,'no_full_chain_or_node_capability_mounted':True,'consensus_and_auxpow_validation':'NOT_PERFORMED_BY_THIN_VERIFIER','latest_state_completeness':'NOT_PROVEN'},indent=2))
