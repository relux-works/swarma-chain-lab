import io,tarfile,pathlib,subprocess,hashlib,json
from lab_paths import lab_root
root=lab_root()
base=pathlib.Path.cwd()
archive=base/'input/namecoin-28.0-x86_64-linux-gnu.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860'
create="from pathlib import Path; import os,sys; assert os.getuid()==1002; p=Path(sys.argv[1]); p.mkdir(mode=0o700); [(p/x).mkdir(mode=0o700) for x in ['source','bin','private','public']]; [(p/'private'/x).mkdir(mode=0o700) for x in ['home','tmp','cache']]"
subprocess.run(['sudo','-n','-u','lab','-i','env','-i','PATH=/usr/bin:/bin','/usr/bin/python3','-',str(root)],input=create.encode(),check=True)
# Directory creation is passed through stdin to avoid shell-quoting ambiguity.
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w') as t:
 for p in (base/'source').iterdir():
  if p.is_file():t.add(p,arcname='source/'+p.name)
 with tarfile.open(archive) as a:
  for name in ['namecoind','namecoin-cli']:
   data=a.extractfile('namecoin-28.0/bin/'+name).read();info=tarfile.TarInfo('bin/'+name);info.size=len(data);info.mode=0o700;t.addfile(info,io.BytesIO(data))
subprocess.run(['sudo','-n','-u','lab','-i','env','-i','PATH=/usr/bin:/bin','/usr/bin/tar','-x','-C',str(root)],input=buf.getvalue(),check=True)
(base/'evidence/runtime-binary-sha256.json').write_text(json.dumps({'namecoind_sha256':hashlib.sha256(tarfile.open(archive).extractfile('namecoin-28.0/bin/namecoind').read()).hexdigest(),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest()},indent=2))
