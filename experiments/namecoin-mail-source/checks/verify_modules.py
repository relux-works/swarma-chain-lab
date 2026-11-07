#!/usr/bin/env python3
"""Check exact upstream lock sums against canonical proxy bytes and lookup records.
No network, extraction, code import from dependencies, or dependency updates.
"""
import base64, hashlib, json, pathlib, zipfile
root=pathlib.Path('/upstream')
rows=[]
for line in (root/'ncdns/testdata/go.sum').read_text().splitlines():
    module,version,want=line.split()
    version,sep,_=version.partition('/go.mod')
    escaped=''.join('!'+c.lower() if c.isupper() else c for c in module)
    stem=root/'proxy'/escaped/'@v'/version
    if sep:
        data=pathlib.Path(str(stem)+'.mod').read_bytes()
        entries=[('go.mod',hashlib.sha256(data).hexdigest())]
    else:
        with zipfile.ZipFile(str(stem)+'.zip') as z:
            names=sorted(z.namelist())
            assert len(names)==len(set(names)), 'duplicate zip member'
            entries=[]
            for name in names:
                assert name.startswith(module+'@'+version+'/') and '..' not in name.split('/'),name
                assert not name.endswith('/'),name
                entries.append((name,hashlib.sha256(z.read(name)).hexdigest()))
        canonical=(root/'sumdb'/escaped/'@v'/(version+'.lookup')).read_text()
        assert f'{module} {version} {want}\n' in canonical, 'canonical sumdb h1 mismatch'
        modwant=next(l.split()[2] for l in (root/'ncdns/testdata/go.sum').read_text().splitlines() if l.startswith(module+' '+version+'/go.mod '))
        assert f'{module} {version}/go.mod {modwant}\n' in canonical
    digest=hashlib.sha256(''.join(f'{h}  {n}\n' for n,h in sorted(entries)).encode()).digest()
    actual='h1:'+base64.b64encode(digest).decode()
    assert actual==want,(module,version,actual,want)
    rows.append({'module':module,'version':version,'artifact':'go.mod' if sep else 'zip','h1':actual})
pathlib.Path('/evidence/module-h1.json').write_text(json.dumps({'verified':rows,'canonical_lookup_transport':'HTTPS sum.golang.org; no independent log inclusion proof claimed','upgrades':False},indent=2)+'\n')
print(f'PASS {len(rows)} canonical lock artifact hashes; no dependency upgrades')
