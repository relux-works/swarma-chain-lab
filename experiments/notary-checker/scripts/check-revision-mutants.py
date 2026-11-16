#!/usr/bin/env python3
"""Adopted rev374 mutation controls plus FIFO and strict-default controls. Copies the candidate module into a fresh dir per
mutant, applies one exact substitution (must match exactly once), runs go test,
and records killed/survived with failing test names. Never touches the candidate."""
import argparse, json, os, shutil, subprocess, sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]

SVC = 'internal/service/service.go'
M = [
 # id, file, old, new, packages
 ('S1-sign-on-checker-refusal', SVC,
  'if err != nil {\n\t\treturn Response{}, err\n\t}',
  'if err != nil {\n\t\t_, _ = s.sign(make([]byte, 32))\n\t\treturn Response{}, err\n\t}', './internal/service'),
 ('S2-sign-in-service-fail-closure', SVC,
  'fail := func(code string) (Response, error) { return Response{}, check.Refusal(code) }',
  'fail := func(code string) (Response, error) { _, _ = s.sign(make([]byte, 32)); return Response{}, check.Refusal(code) }', './internal/service'),
 ('S3-sign-on-notary-lookup-refusal', SVC,
  'if e != nil {\n\t\treturn Response{}, e\n\t}\n\tin := check.Input',
  'if e != nil {\n\t\t_, _ = s.sign(make([]byte, 32))\n\t\treturn Response{}, e\n\t}\n\tin := check.Input', './internal/service'),
 ('S4-sign-before-final-view', SVC,
  '\tif e = node.View(statement.TipHeight, statement.TipHash); e != nil {\n\t\treturn Response{}, e\n\t}\n\tif ctx.Err() != nil {\n\t\treturn fail("REQUEST_TIMEOUT")\n\t}\n\tdigest, e := hex.DecodeString(result.Digest)\n\tif e != nil {\n\t\treturn fail("ATTESTATION_BINDING")\n\t}\n\tsig, e := s.sign(digest)',
  '\tdigest, e := hex.DecodeString(result.Digest)\n\tif e != nil {\n\t\treturn fail("ATTESTATION_BINDING")\n\t}\n\tsig, e := s.sign(digest)\n\tif ve := node.View(statement.TipHeight, statement.TipHash); ve != nil {\n\t\treturn Response{}, ve\n\t}\n\tif ctx.Err() != nil {\n\t\treturn fail("REQUEST_TIMEOUT")\n\t}', './internal/service'),
 ('S5-delete-final-presign-view', SVC,
  '\tif e = node.View(statement.TipHeight, statement.TipHash); e != nil {\n\t\treturn Response{}, e\n\t}\n',
  '', './internal/service'),
 ('S6-delete-notary-registration-check', SVC,
  '\tif !found {\n\t\treturn fail("NOTARY_REGISTRATION_MISMATCH")\n\t}\n',
  '\t_ = found\n', './internal/service'),
 ('S7-delete-notary-key-check', SVC,
  '\tif a.NotaryKey != s.public {\n\t\treturn fail("NOTARY_KEY_MISMATCH")\n\t}\n',
  '', './internal/service'),
 ('S8-delete-presign-deadline-check', SVC,
  '\tif ctx.Err() != nil {\n\t\treturn fail("REQUEST_TIMEOUT")\n\t}\n\tdigest',
  '\tdigest', './internal/service'),
 ('S9-delete-attestation-network-check', SVC,
  '\tif a.Network != "regtest" {\n\t\treturn fail("NODE_NETWORK")\n\t}\n',
  '', './internal/service'),
 ('S10-refusal-body-carries-candidate', SVC,
  '\t\trefused(w, 422, code)\n',
  '\t\twrite(w, 422, Response{Decision: code, AnchorFrame: "00"})\n', './internal/service'),
 ('N1-delete-lookup-post-read-view', 'node.go',
  '\tif e := n.View(height, hash); e != nil {\n\t\treturn NameObservation{}, e\n\t}\n\treturn NameObservation{Point',
  '\treturn NameObservation{Point', '.'),
 ('N2-delete-lookup-pre-read-view', 'node.go',
  '\tif e := n.View(height, hash); e != nil {\n\t\treturn NameObservation{}, e\n\t}\n\topts',
  '\topts', '.'),
 ('N3-delete-getblockhash-crosscheck', 'node.go',
  '\tif got != hash {\n\t\treturn refuse("NODE_TIP_MISMATCH")\n\t}\n',
  '', '.'),
 ('N4-credential-mode-unchecked', 'node.go',
  '|| !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {\n\t\treturn nil, refuse("NODE_CREDENTIALS")',
  '|| !st.Mode().IsRegular() {\n\t\treturn nil, refuse("NODE_CREDENTIALS")', '. ./internal/service'),
 ('N5-credential-follows-symlink', 'node.go',
  'f, e := os.OpenFile(credentialFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)',
  'f, e := os.OpenFile(credentialFile, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)', '. ./internal/service'),
 ('N6-registration-latest-not-history', 'node.go',
  'return NameObservation{Point{registration.TxID, registration.Vout}',
  '_ = registration; return NameObservation{Point{current.TxID, current.Vout}', '.'),
 ('N7-reregistration-boundary-off-by-one', 'node.go',
  'if h.Height >= height+prev.ExpiresIn {',
  'if h.Height > height+prev.ExpiresIn {', '.'),
 ('N8-expired-current-accepted', 'node.go',
  'if current.Expired || current.ExpiresIn <= 0 {',
  'if current.Expired {', '.'),
 ('K1-key-follows-symlink', 'internal/service/key.go',
  'f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)',
  'f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)', './internal/service'),
 ('K2-key-mode-unchecked', 'internal/service/key.go',
  '|| !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {',
  '|| !st.Mode().IsRegular() {', './internal/service'),
 ('K3-key-cleared-before-drain', SVC,
  '\t\ts.active.Wait()\n\t\tif s.key != nil {\n\t\t\ts.key.Zero()\n\t\t}',
  '\t\tif s.key != nil {\n\t\t\ts.key.Zero()\n\t\t}\n\t\ts.active.Wait()', './internal/service'),
 ('K4-key-never-cleared', SVC,
  '\t\tif s.key != nil {\n\t\t\ts.key.Zero()\n\t\t}',
  '', './internal/service'),
 ('B1-strict-depth-cap-removed', 'internal/service/strict.go',
  'if depth > 64 {', 'if depth > 100000 {', './internal/service'),
 ('B2-header-cap-removed', SVC,
  'MaxHeaderBytes: 8192, ', '', './internal/service'),
 ('B3-read-timeout-removed', SVC,
  'ReadHeaderTimeout: timeout, ReadTimeout: timeout, ', '', './internal/service'),
 ('B4-rpc-response-cap-raised', 'node.go',
  'b, e := io.ReadAll(io.LimitReader(resp.Body, 1048577))\n\tif e != nil || len(b) > 1048576 {',
  'b, e := io.ReadAll(resp.Body)\n\tif e != nil {', '. ./internal/service'),
 ('B5-concurrency-unbounded', SVC,
  '\tdefault:\n\t\trefused(w, 503, "BUSY")\n\t\treturn\n\t}',
  '\tdefault:\n\t}', './internal/service'),
 ('B6-body-cap-removed', SVC,
  'io.ReadAll(http.MaxBytesReader(w, r.Body, s.config.Limits.RequestBytes))',
  'io.ReadAll(r.Body)', './internal/service'),
 ('B7-rate-unbounded', SVC,
  '\tif s.tokens < 1 {\n\t\treturn false\n\t}', '', './internal/service'),
 ('B8-dup-key-allowed', 'internal/service/strict.go',
  'if !ok || seen[key] {', 'if !ok {', './internal/service'),
 ('C1-serve-accepts-fixture-flag', 'cmd/notary-service/main.go',
  '\t\tflags.StringVar(&path, "config", "", "strict service config")',
  '\t\tflags.StringVar(&path, "config", "", "strict service config")\n\t\tflags.String("offline-name-fixture", "", "")', './cmd/notary-service'),
]

# Every control requires a contract-specific named failure; setup failures,
# panics, process timeouts and an unapplied substitution are never kills.
EXPECTED = {
 'S1': 'TestRefusalNeverSigns', 'S2': 'TestRev374ServiceRefusalsNeverSign',
 'S3': 'TestDeadlineNeverSigns', 'S4': 'TestRev374FinalViewTipAdvance',
 'S5': 'TestRev374FinalViewTipAdvance', 'S6': 'TestRev374RegistrationMismatch',
 'S7': 'TestRev374NotaryKeyMismatch', 'S8': 'TestRev374PreSignDeadline',
 'S9': 'TestServiceAttestationNetworkGuard', 'S10': 'TestRefusalNeverSigns',
 'N1': 'TestNodeReaderBoundsAndNames/mid-read-tip',
 'N2': 'TestNodeReaderBoundsAndNames/mid-read-tip',
 'N3': 'TestNodeReaderBoundsAndNames/blockhash', 'N4': 'TestRev374CredentialRules',
 'N5': 'TestRev374CredentialRules', 'N6': 'TestNodeReaderBoundsAndNames/update',
 'N7': 'TestNodeReaderBoundsAndNames/expiry-at',
 'N8': 'TestNodeReaderBoundsAndNames/zero-expiry', 'K1': 'TestKeyCustody',
 'K2': 'TestKeyCustody', 'K3': 'TestShutdownDrainsBeforeKeyClear',
 'K4': 'TestRev374KeyZeroAfterClose', 'B1': 'TestRev374MemberDepth',
 'B2': 'TestRev374HeaderCap', 'B3': 'TestNetworkTimeBounds/slow-body',
 'B4': 'TestRev374RPCResponseCap', 'B5': 'TestRequestBounds/busy',
 'B6': 'TestRequestBounds/size', 'B7': 'TestRequestBounds/rate',
 'B8': 'TestRequestBounds/json', 'C1': 'TestServeFIFOAndFixtureFlag',
 'F1': 'TestPrivateFileFIFORefusal/key',
 'F2': 'TestPrivateFileFIFORefusal/credential',
 'F3': 'TestOperatorFileFIFORefusal/config',
 'F4': 'TestInputFIFORefusal/parent',
 'D1': 'TestDeploymentPolicyStrictDefaultAndExplicitMVP/omitted',
}
M += [
 ('F3-operator-blocking-fifo', 'internal/operatorfile/read.go',
  'os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)',
  'os.Open(path)', './internal/service ./cmd/notary-service'),
 ('F4-checker-blocking-fifo', 'internal/operatorfile/read.go',
  'os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)',
  'os.Open(path)', './cmd/notary-check'),
 ('F1-key-blocking-fifo', 'internal/service/key.go',
  'os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK',
  'os.O_RDONLY|syscall.O_NOFOLLOW', './internal/service ./cmd/notary-service'),
 ('F2-credential-blocking-fifo', 'node.go',
  'os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK',
  'os.O_RDONLY|syscall.O_NOFOLLOW', './internal/service ./cmd/notary-service'),
 ('D1-strict-default-relaxed', 'check.go',
  'if (policy.NotaryOwner == policy.IssuerOwner || policy.NotaryOwner == policy.DelegatorOwner) && policy.Mode != MVPPairOwnedNotary {',
  'if (policy.NotaryOwner == policy.IssuerOwner || policy.NotaryOwner == policy.DelegatorOwner) && false {', './internal/service'),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work-dir', type=Path, required=True)
    ap.add_argument('only', nargs='*')
    args = ap.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    only = set(args.only)
    env = dict(os.environ, GOTOOLCHAIN='local', GOFLAGS='-modcacherw', GOWORK='off', GOPROXY='off')
    results = []
    for mid, rel, old, new, pkgs in M:
        if only and mid not in only:
            continue
        d = work / mid
        shutil.copytree(SRC, d, ignore=shutil.ignore_patterns('.temp', '.tmp', '__pycache__'))
        p = d / rel
        source = p.read_text()
        n = source.count(old)
        if n != 1:
            results.append({'id': mid, 'result': 'NOT_APPLIED', 'count': n})
            print(mid, 'NOT_APPLIED', n, flush=True)
            shutil.rmtree(d)
            continue
        p.write_text(source.replace(old, new))
        cmd = ['go', 'test', '-count=1', '-timeout', '30s'] + pkgs.split()
        proc = subprocess.Popen(cmd, cwd=d, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (work / (mid + '.pid')).write_text(str(proc.pid) + '\n')
        try:
            raw = proc.communicate(timeout=90)[0]
            out = raw.decode(errors='replace')
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0].decode(errors='replace')
            timed_out = True
        (work / (mid + '.log')).write_text(' '.join(cmd) + '\n' + out + f'\nexit={proc.returncode}\n')
        fails = sorted({line.split()[2] for line in out.splitlines() if line.strip().startswith('--- FAIL:')})
        expected = EXPECTED[mid.split('-')[0]]
        invalid = timed_out or any(x in out for x in ('[build failed]', '[setup failed]', 'panic:', 'WARNING: DATA RACE'))
        result = 'KILLED' if not invalid and proc.returncode == 1 and expected in fails else 'SURVIVED'
        row = {'id': mid, 'file': rel, 'result': result, 'exit': proc.returncode,
               'required_failing_test': expected, 'failing_tests': fails, 'invalid_execution': invalid}
        results.append(row)
        print(mid, result, proc.returncode, ','.join(fails), flush=True)
        shutil.rmtree(d)
    (work / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if results and all(r['result'] == 'KILLED' for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
