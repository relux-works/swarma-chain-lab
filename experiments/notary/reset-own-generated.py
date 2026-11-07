"""After a failed, stopped namespace and completed public export: own state only."""
import datetime,json,os,shutil
from pathlib import Path
from lab_paths import lab_root
assert os.getuid()==1002
p=lab_root();assert p.is_dir() and not p.is_symlink()
r=json.loads((p/'public/export/runtime.json').read_text());a=json.loads((p/'public/export/export-audit.json').read_text());s=json.loads((p/'public/export/node-supervision.json').read_text())
assert r['node_exit']==0 and r['status']=='FAILED' and a['status']=='PASS' and s['exit']==1
# Calling controller has already copied the sanitized export to attempt-1.
for name in ['private','public']:
 q=p/name;assert not q.is_symlink();shutil.rmtree(q);q.mkdir(mode=0o700)
for name in ['home','tmp','cache']:(p/'private'/name).mkdir(mode=0o700)
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'own_generated_state_removed_after_failed_run_export':True,'node_exit':0,'other_tasks_or_processes_accessed':False,'secure_erasure_claim':False}))
