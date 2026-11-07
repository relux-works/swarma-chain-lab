"""Budgets for only this namespace; immutable total execution cutoff.

Admission is refused before spawning; budget stops always report failure.
"""
import datetime,json,os,resource,signal,subprocess,sys,time
from pathlib import Path
resource.setrlimit(resource.RLIMIT_FSIZE,(256*1024**2,256*1024**2))
resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(1800,1800))
resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
start=time.monotonic()
cutoff=datetime.datetime.fromisoformat('2026-11-07T03:16:00+00:00').timestamp()
end=min(start+2100,start+max(0,cutoff-time.time()))
command=sys.argv[1:] or ['/usr/bin/python3','-B','/source/lab.py']
peak=0;peak_processes=0;reason=None
def receipt(exit_code,child_exit,child_started):
    Path('/public/supervision.json').write_text(json.dumps({'exit':exit_code,'child_exit':child_exit,'child_started':child_started,'stop_reason':reason,'elapsed_seconds':time.monotonic()-start,'peak_private_public_allocated_bytes':peak,'peak_namespace_processes':peak_processes,'time_limit_seconds':2100,'absolute_cutoff':'2026-11-07T03:16:00Z','disk_limit_bytes':1900*1024**2,'process_limit':32},indent=2)+'\n')
# Recheck the absolute clock at the admission boundary, including equality.
# The monotonic deadline also refuses a start if preparation used the window.
if time.time()>=cutoff or time.monotonic()>=end:
    reason='ADMISSION_EXPIRED'
    receipt(1,None,False)
    raise SystemExit(1)
p=subprocess.Popen(command,start_new_session=True)
while p.poll() is None:
    size=sum(q.lstat().st_blocks*512 for root in ['/private','/public'] for q in Path(root).rglob('*') if not q.is_symlink())
    count=sum(q.name.isdigit() for q in Path('/proc').iterdir());peak=max(peak,size);peak_processes=max(peak_processes,count)
    if time.monotonic()>=end:reason='TIME_BUDGET'
    elif size>1900*1024**2:reason='DISK_BUDGET'
    elif count>32:reason='PROCESS_BUDGET'
    if reason:
        os.killpg(p.pid,signal.SIGTERM)
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
        break
    time.sleep(.1)
exit_code=1 if reason else p.returncode
receipt(exit_code,p.returncode,True)
raise SystemExit(exit_code)
