"""Control-plane cleanup: exact own task directory only, after public export."""
import datetime,json,os,shutil
from pathlib import Path
from lab_paths import lab_root
assert os.getuid()==1002
p=lab_root()
assert not p.is_symlink() and p.is_dir()
public=p/'public/export'
s=json.loads((public/'node-supervision.json').read_text());r=json.loads((public/'runtime.json').read_text());a=json.loads((public/'export-audit.json').read_text())
assert s['exit']==0 and r['node_exit']==0 and a['status']=='PASS'
size=sum(q.lstat().st_blocks*512 for q in p.rglob('*') if not q.is_symlink())
shutil.rmtree(p)
assert not p.exists()
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'own_task_root_removed':True,'private_state_keys_wallets_cookies_removed':True,'only_own_task_path_accessed':True,'other_tasks_or_processes_inspected_or_signaled':False,'after_sanitized_public_export':True,'allocated_bytes_before_cleanup':size,'secure_erasure_claim':False},indent=2))
