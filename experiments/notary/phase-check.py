from pathlib import Path
import datetime,hashlib,json,sys
r=Path('ROOT-UPDATE.md');entry={'phase':sys.argv[1],'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'root_update_present':r.exists(),'acceptance_clock_reset':False}
if r.exists():
 print(r.read_text());entry['root_update_sha256']=hashlib.sha256(r.read_bytes()).hexdigest()
p=Path('evidence/phase-checks.jsonl');p.open('a').write(json.dumps(entry)+'\n')
print(json.dumps(entry))
