#!/usr/bin/env python3
"""Render nonsecret candidates only. Never create TLS/DNS private keys or services."""
import base64, hashlib, json, pathlib, re, sys
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); out.mkdir(parents=True,exist_ok=True)
for role,host,domain,ip,recipient in [('A','mx.alice.bit','alice.bit','192.0.2.10','alice'),('B','mx.bob.bit','bob.bit','192.0.2.20','bob'),('Bprime','mx2.bob.bit','bob.bit','192.0.2.30','bob')]:
 d=out/role; d.mkdir(exist_ok=True)
 substitutions={'@MTA_HOST@':host,'@MAIL_DOMAIN@':domain,'@MTA_IP@':ip,'@NCDNS_IP@':'192.0.2.3','@VALIDATOR_IP@':'192.0.2.2','@CONTROLLER_IP@':'192.0.2.1','@RECORDER_IP@':'192.0.2.4'}
 for f in src.glob('*.in'):
  text=f.read_text()
  for a,b in substitutions.items(): text=text.replace(a,b)
  assert not re.search(r'@[A-Z_]+@',text),f
  (d/f.name.removesuffix('.in')).write_text(text)
 (d/'vmailbox').write_text(f'{recipient}@{domain} {recipient}/\n')
 (d/'resolv.conf').write_bytes((src/'resolv.conf').read_bytes())
 # Checker-only public DNSKEY bytes, with no corresponding private material.
 # Actual runtime must use separately generated disposable DNSSEC keys/anchor.
 anchor='bit. 600 IN DNSKEY 257 3 15 '+base64.b64encode(hashlib.sha256(b'PUBLIC CHECKER ONLY NO PRIVATE KEY').digest()).decode()+'\n'
 (d/'bit.key').write_text(anchor)
print('Rendered A/B/Bprime nonsecret candidates; no keys generated, no services started')
