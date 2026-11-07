import hashlib,json,os,tarfile,zipfile,subprocess,pathlib
P=pathlib.Path
os.umask(0o077)
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
assert sha('/inputs/namecoin.tar.gz')=='6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860'
assert sha('/inputs/electrum.tar.gz')=='a88c859ac7271ddb2f844508c9c2957c1f3e114e367438e0df96bbffcd36c3f9'
pins=json.loads(P('/src/experiments/namecoin-electrum-local/dependencies.json').read_text())
for e in pins:
 p=P('/artifacts/wheels')/e['filename'];assert sha(p)==e['sha256'];assert p.stat().st_size==e['bytes']
r=P('/scratch/runtimepack');r.mkdir(mode=0o700)
for n in ['node','electrum','site','lib','gpg']:(r/n).mkdir(mode=0o700)
with tarfile.open('/inputs/namecoin.tar.gz') as t:
 for n in ['namecoind','namecoin-cli']:
  m=t.getmember('namecoin-28.0/bin/'+n);p=r/'node'/n;p.write_bytes(t.extractfile(m).read());p.chmod(0o700)
assert sha(r/'node/namecoind')=='dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7'
assert sha(r/'node/namecoin-cli')=='318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1'
with tarfile.open('/inputs/electrum.tar.gz') as t:t.extractall(r/'electrum',filter='data')
wheels=[P('/artifacts/wheels')/e['filename'] for e in pins if e['role']=='runtime' and e['filename'].endswith('.whl')]
wheels += [P('/artifacts/patched/e_x-2.0.1-py3-none-any.whl'),P('/artifacts/built/plyvel-1.5.1-cp314-cp314-linux_x86_64.whl')]
assert sha(wheels[-2])=='d888ac1ba35333f7fecd1f18b7d5fac69fc92a4aa030389ef768e28e295871ab'
assert sha(wheels[-1])=='95819dae46bc2eec595810dc739552724b1578142e34a905f703de6433ea3b34'
for w in wheels:
 with zipfile.ZipFile(w) as z:z.extractall(r/'site')
lib=r/'lib/libleveldb.so.1.23.0';lib.write_bytes(P('/artifacts/built/libleveldb.so.1.23.0').read_bytes());assert sha(lib)=='0dd642312a8a2e501abcfbdbba6ae4aa0ba310a2383989f33b655e3eaadab954'
(r/'lib/libleveldb.so.1d').symlink_to(lib.name);(r/'lib/libleveldb.so.1').symlink_to(lib.name)
for key,sig,data,expected in [('/inputs/RoseTuring.asc','/inputs/namecoin.SHA256SUMS.asc','/inputs/namecoin.SHA256SUMS','FD8366A807A99FA27FD9CCEA9FE3BFDDA6C53495'),('/inputs/JeremyRand-Electrum.asc','/inputs/electrum.tar.gz.asc','/inputs/electrum.tar.gz','A0BE08C865661A9316E0A7FF762ED28DA5C007DA')]:
 args=['gpg','--homedir',str(r/'gpg'),'--batch']
 a=subprocess.run(args+['--import',key],capture_output=True,text=True);assert a.returncode==0
 a=subprocess.run(args+['--status-fd','1','--verify',sig,data],capture_output=True,text=True);print(a.stdout,a.stderr);assert a.returncode==0;assert expected in a.stdout
print(json.dumps({'dependencies':len(pins),'runtime_wheels':len(wheels),'archive_and_binaries':'exact_pins_verified','release_signatures':'both_passed_published_fingerprint_pins_ownertrust_undefined'}))
