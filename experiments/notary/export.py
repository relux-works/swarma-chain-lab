"""Public allowlist export. Never reads wallets or key files."""
import hashlib,json,re
from pathlib import Path
P=Path('/public');E=P/'export';E.mkdir(mode=0o700,exist_ok=True)
allow={'source-binding.json','node-supervision.json','boundary.json','policy.json','separate-fixture.json','separate-fixture-current.json','cosigned-fixture.json','cosigned-fixture-current.json','separate-fresh-proof.json','cosigned-fresh-proof.json','cases.json','identities.json','final-chain.json','runtime.json','supervision.json','failure.json'}
redacted=[]
def transform(v,path=''):
    if isinstance(v,dict):
        out={}
        # Retain hashes of exact original canonical protocol objects.
        if v.get('version') in ['synthetic-notarized-grant-v1','synthetic-notary-statement-v1']:
            raw=json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode();out['original_canonical_sha256']=hashlib.sha256(raw).hexdigest()
        for k,x in v.items():
            if k in ['address','pubkey','grantee','script','grant_signature','notary_signature'] and isinstance(x,str):
                out[k+'_sha256']=hashlib.sha256(x.encode()).hexdigest();redacted.append(path+'/'+k)
            else:out[k]=transform(x,path+'/'+k)
        return out
    if isinstance(v,list):return [transform(x,path+'/'+str(i)) for i,x in enumerate(v)]
    return v
manifest=[]
for p in sorted(P.iterdir()):
    if p.name not in allow:continue
    original=p.read_bytes();o=transform(json.loads(original),p.name)
    b=(json.dumps(o,indent=2)+'\n').encode();(E/p.name).write_bytes(b)
    manifest.append({'file':p.name,'original_sha256':hashlib.sha256(original).hexdigest(),'export_sha256':hashlib.sha256(b).hexdigest()})
# No raw RPC request/response, wallets, cookie, raw signatures or runtime key
# material is on this allowlist. Hashes are correlation labels, not test vectors.
for p in E.iterdir():
    data=p.read_text()
    assert not re.search(r'(?i)BEGIN .*PRIVATE KEY|xprv|tprv|__cookie__|rpcpassword|seed phrase',data)
(E/'export-audit.json').write_text(json.dumps({'status':'PASS','files':manifest,'redacted_field_count':len(redacted),'runtime_public_keys_or_signatures_exported':False,'runtime_secret_material_read_by_exporter':False,'raw_chain_or_wallet_files_exported':False,'trace_representation':'hashes and synthetic role labels; not reusable public test vectors','limitations':'allowlist and targeted marker check; no claim of exhaustive detection of all secret encodings'},indent=2)+'\n')
