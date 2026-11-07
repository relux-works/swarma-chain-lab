#!/usr/bin/env python3
"""Deterministic public parser fixtures. Associations are synthetic, not TLS keys.
Later lab must replace them with hashes of disposable runtime-only SPKIs.
"""
import base64, hashlib, json, pathlib, sys
out=pathlib.Path(sys.argv[1]); out.mkdir(parents=True,exist_ok=True)
manifest=[]
for case,owner,host,ip,label in [
 ('alice','alice','mx','192.0.2.10','provider-A'),
 ('bob-before','bob','mx','192.0.2.20','provider-B'),
 ('bob-after','bob','mx2','192.0.2.30','provider-Bprime')]:
    h=hashlib.sha256(('PUBLIC SYNTHETIC ASSOCIATION '+label).encode()).digest()
    b64=base64.b64encode(h).decode()
    value={'mx':[[10,f'{host}.{owner}.bit.']],'map':{host:{'ip':ip,'map':{'_tcp':{'map':{'_25':{'tls':[[3,1,1,b64]]}}}}}}}
    text=json.dumps(value,separators=(',',':')); assert len(text.encode())<=520
    (out/(case+'.json')).write_text(text)
    records=[f'{owner}.bit. 600 IN MX 10 {host}.{owner}.bit.',f'{host}.{owner}.bit. 600 IN A {ip}',f'_25._tcp.{host}.{owner}.bit. 600 IN TLSA 3 1 1 {h.hex().upper()}']
    (out/(case+'.rr')).write_text('\n'.join(sorted(records))+'\n')
    manifest.append({'case':case,'name':'d/'+owner,'apex':owner+'.bit.','bytes':len(text.encode()),'sha256':hashlib.sha256(text.encode()).hexdigest(),'association':'synthetic public bytes; no actual TLS key'})
# Current parser srv field at the actual owner; it must not create an MX.
text=json.dumps({'map':{'_tcp':{'map':{'_smtp':{'srv':[[10,0,25,'mx.bob.bit.']]}}}}},separators=(',',':'))
(out/'ifa-srv.json').write_text(text)
(out/'ifa-srv.rr').write_text('_smtp._tcp.bob.bit. 600 IN SRV 10 0 25 mx.bob.bit.\n')
manifest.append({'case':'ifa-srv','name':'d/bob','apex':'bob.bit.','bytes':len(text.encode()),'expected_mx_count':0})
text='{"service":[["smtp","tcp",10,0,25,"mx.bob.bit."]]}\n'
(out/'legacy-service.json').write_text(text)
(out/'legacy-service.rr').write_text('')
manifest.append({'case':'legacy-service','name':'d/bob','apex':'bob.bit.','bytes':len(text.encode()),'expected_rr_count':0})
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
