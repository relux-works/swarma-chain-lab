#!/usr/bin/env python3
"""Disable one rule at a time in disposable copies; require its named test to fail.

No source mutation touches the candidate. A compile error, panic, timeout or an
unrelated test failure is not a killed mutant. Tables state when a control
proves first-refusal precedence rather than end-to-end false acceptance.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# Mutant, source, refusal disabled, named test, exact boundary narrowed.
CASES = [
 ('explicit-time','check.go','AT_TIME','TestVectors/negative-no-time','time-input refusal precedes window refusal'),
 ('grant-shape','grant.go','GRANT_ENCODING','TestVectors/negative-grant-unknown-member','unknown grant members refuse'),
 ('grant-fields','grant.go','GRANT_FIELD','TestVectors/negative-grant-version','version 4 is unsupported'),
 ('grant-signature','grant.go','GRANT_SIGNATURE','TestVectors/negative-signature','grant signature is mandatory'),
 ('not-before','grant.go','GRANT_NOT_YET_VALID','TestVectors/negative-child-not-yet-valid','not-before boundary'),
 ('not-after','grant.go','GRANT_EXPIRED','TestVectors/negative-child-expired','exclusive end boundary'),
 ('grant-consent','grant.go','GRANT_CONSENT','TestVectors/negative-consent-signature','countersignature is mandatory'),
 ('contract-hash','grant.go','CONTRACT_HASH','TestVectors/negative-contract-hash','hash refusal precedes malformed contract refusal'),
 ('contract-members','contract.go','CONTRACT_ENCODING','TestContractRules/negative-contract-unknown-member','unknown contract members refuse'),
 ('contract-profile','contract.go','CONTRACT_PROFILE','TestContractRules/negative-profile','profile /2 is required'),
 ('contract-fields','contract.go','CONTRACT_FIELD','TestContractRules/negative-field','text hash syntax'),
 ('contract-actions','contract.go','CONTRACT_ACTIONS','TestContractRules/negative-unknown-action','closed action vocabulary'),
 ('contract-repos','contract.go','CONTRACT_REPOS','TestContractRules/negative-repo-grammar','repository grammar'),
 ('contract-budget','contract.go','CONTRACT_BUDGET','TestContractRules/negative-budget-without-spend','budget requires spend action'),
 ('contract-note','contract.go','CONTRACT_NOTE','TestContractRules/negative-note','note length'),
 ('contract-parent','contract.go','CONTRACT_PARENT','TestContractRules/negative-parent-shape','ordinal and parent are coupled'),
 ('delegate-members','contract.go','CONTRACT_DELEGATE','TestContractRules/negative-row-unknown-member','nested row member set'),
 ('delegate-notary','contract.go','DELEGATE_NO_NOTARY','TestVectors/negative-no-notaries','missing-notary refusal precedes delegate refusal'),
 ('parent-id','check.go','PARENT_ID_MISMATCH','TestVectors/negative-parent-id','exact signed parent identity'),
 ('depth','check.go','CHAIN_DEPTH','TestVectors/negative-depth-two','ancestor refusal precedes not-delegable refusal'),
 ('delegable','check.go','NOT_DELEGABLE','TestVectors/negative-not-delegable','not-delegable refusal precedes ordinal refusal'),
 ('subject','check.go','SUBJECT_MISMATCH','TestVectors/negative-subject','common principal'),
 ('request','check.go','DELEGATION_REQUEST','TestVectors/negative-request-missing','complete signed request'),
 ('ordinal','check.go','CHILD_ORDINAL','TestVectors/negative-ordinal','ordinal bounds before row selection'),
 ('executor','check.go','CHILD_AGENT_NOT_ALLOWED','TestVectors/negative-executor','row executor equality'),
 ('grantee','check.go','CHILD_GRANTEE_NOT_ALLOWED','TestVectors/negative-grantee','row grantee equality'),
 ('actions','check.go','CHILD_ACTIONS_WIDER','TestVectors/negative-actions','child within delegable action set'),
 ('repos','check.go','CHILD_REPOS_WIDER','TestVectors/negative-repositories','exact repository subset'),
 ('budget','check.go','CHILD_BUDGET_OVER','TestRowVectors/row-budget-over','isolated cap defense; not spend admission'),
 ('window','check.go','CHILD_WINDOW_NOT_NESTED','TestVectors/negative-window-after','nested window'),
 ('text','check.go','TEXT_JUDGEMENT_REQUIRED','TestVectors/negative-text-different','different text requires judgement and refuses'),
 ('text-octets','check.go','DELEGATION_BUNDLE','TestVectors/negative-text-octets','text octets bind the signed hash'),
 ('policy','check.go','OWNER_EVIDENCE_REQUIRED','TestVectors/negative-policy-binding','policy binds exact parent and child IDs'),
 ('designation','check.go','NOTARY_NOT_DESIGNATED','TestVectors/negative-not-designated','designated notary required; unsafe known-pin fallback'),
 ('owner-pin','check.go','NOTARY_NAME_CHANGED','TestVectors/negative-owner-pin-mismatch','notary owner must match signed pin'),
 ('owner-relation','check.go','NOTARY_OWNER_RELATION','TestVectors/negative-owner-relation','same-owner issuer affiliation'),
 ('cross-owner-relation','check.go','NOTARY_OWNER_RELATION','TestVectors/negative-cross-owner-not-third-party','strict default requires a third owner despite bilateral agreement'),
 ('cross-owner-agreement','check.go','CROSS_OWNER_CERTIFIER_REQUIRED','TestVectors/negative-cross-owner-missing-certifier','both owners agree'),
 ('notary-delegator','check.go','NOTARY_IS_DELEGATOR','TestVectors/negative-notary-is-delegator','key independence from delegator'),
 ('notary-delegatee','check.go','NOTARY_IS_DELEGATEE','TestVectors/negative-notary-is-delegatee','key independence from delegatee'),
 ('notary-executor','check.go','NOTARY_IS_EXECUTOR','TestVectors/negative-notary-is-executor','name independence from executors'),
 ('statement','check.go','STATEMENT_FIELD','TestVectors/negative-statement','explicit statement fields'),
 ('attestation-output-size','check.go','ATTESTATION_TOO_LARGE','TestVectors/negative-attestation-8193','complete candidate cap, not just the smaller statement'),
 ('policy-mode','check.go','POLICY_MODE_UNSUPPORTED','TestVectors/negative-mvp-unknown-mode','unknown deployment modes refuse'),
 ('policy-mode-required','check.go','POLICY_MODE_REQUIRED','TestVectors/negative-mvp-approvals-without-mode','approvals never infer an absent mode'),
 ('mvp-distinct-pair','check.go','MVP_MODE_PAIR_REQUIRED','TestVectors/negative-mvp-one-owner-pair','two-owner mode rejects a one-owner pair before approval checks'),
 ('mvp-both-approvals','policy.go',None,'TestVectors/negative-mvp-no-approvals','mode requires both signed exact-scope approvals, not just agreed_by'),
]


def disable(source, code):
    # Keep the predicate and all other rules; remove just its refusal effect.
    pattern = r'return (?:c, d, )?(?:fail|refuse)\("' + re.escape(code) + r'"\)'
    changed, n = re.subn(pattern, '// rule disabled by isolated mutation', source)
    if n == 0:
        raise RuntimeError('mutation did not apply: '+code)
    return changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work-dir', type=Path, required=True, help='new disposable task-scoped directory')
    args = ap.parse_args()
    work = args.work_dir.resolve()
    if work.exists():
        raise SystemExit('work directory already exists; use a fresh path')
    work.mkdir(parents=True)
    cases = list(CASES) + [
      ('lexical','encoding.go',None,'TestVectors/negative-contract-escape','no normalization of signed string spelling'),
      ('notary-value','name.go',None,'TestVectors/negative-notary-key','notary key must be a curve point'),
      ('row-selection','check.go',None,'TestVectors/negative-other-row-executor','ordinal selects its own row'),
      ('attestation-signature','check.go',None,'TestSignedAttestationRejectsMismatch/signature','service signature binds the candidate'),
      ('row-pool-sum','contract.go',None,'TestContractRules/negative-parent-row-cap','row caps fit the separate signed pool'),
      ('delegate-spend','contract.go',None,'TestContractRules/negative-delegated-spend','D12 independently forbids delegated spend'),
      ('anchor-id','check.go',None,'TestAnchorRejectsMalformedID','frame IDs must be 32-byte digests'),
      ('attestation-size-off-by-one','check.go',None,'TestVectors/negative-attestation-8193','8193 refuses while the 8192-byte control passes'),
      ('attestation-decode-size','check.go',None,'TestAttestationOutputSize/negative-attestation-8193','signed decode also rejects an oversized correctly signed candidate'),
      ('mvp-signature','policy.go',None,'TestVectors/negative-mvp-different-notary','owner signatures bind even another designated notary name'),
      ('mvp-approval-order','policy.go',None,'TestVectors/negative-mvp-approval-order','approval owner order is canonical'),
      ('mvp-signing-authorities','check.go',None,'TestVectors/negative-mvp-opposite-owner-key','opposite compressed parities cannot reuse one BIP-340 signing authority for both owners'),
      ('mvp-current-grant-key','policy.go',None,'TestVectors/positive-mvp-current-grant-key','current chain grant key verifies independently of policy owner identifiers'),
      ('mvp-distinct-registration','policy.go','MVP_OWNER_REGISTRATION_REUSED','TestVectors/negative-mvp-owner-registration-reused','different names with one registration cannot count as two owners'),
      ('mvp-distinct-name','policy.go','MVP_OWNER_NAME_REUSED','TestVectors/negative-mvp-owner-name-reused','one name cannot approve twice with two keys'),
      ('mvp-name-view','policy.go','MVP_NAME_VIEW_MISMATCH','TestVectors/negative-mvp-name-height','observed height must match the statement'),
      ('mvp-name-registration','policy.go','MVP_NAME_REGISTRATION_MISMATCH','TestVectors/negative-mvp-name-registration','current registration must equal the approved identity'),
    ]
    env = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off')
    go = env.get('GO', 'go')
    rows = ['| Mutant | Boundary narrowed | Named failing test | Observed after disabling |', '| --- | --- | --- | --- |']
    survivors = []
    for name, file, code, test, bound in cases:
        copy = work/name
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('.temp', '.tmp', '__pycache__'))
        path = copy/file
        source = path.read_text()
        if code:
            source = disable(source, code)
            if name == 'ordinal':
                source = source.replace('row := pd.Slots[cc.Ordinal-1]', 'row := pd.Slots[0]')
            if name == 'designation':
                # Avoid an unrelated nil dereference once the designation gate
                # is removed. This intentionally substitutes a known pin, as
                # an implementation trusting an undesignated name would do.
                source = source.replace('if designated == nil {', 'if designated == nil {\n designated = &pd.Notaries[0]')
        elif name == 'lexical':
            start = source.index('func decode(')
            end = source.index('\nfunc sorted', start)
            source = source[:start]+'func decode(raw []byte, out any, limit int) bool { return json.Unmarshal(raw, out)==nil }\n'+source[end:]
        elif name == 'row-pool-sum':
            source = source.replace('if total > d.Budget {', 'if false {')
        elif name == 'delegate-spend':
            source = source.replace('if contains(d.Actions, "spend") {', 'if false {')
        elif name == 'notary-value':
            source = source.replace('!key(binding.Notary.Attest)', 'false')
        elif name == 'row-selection':
            source = source.replace('row := pd.Slots[cc.Ordinal-1]', 'row := pd.Slots[0]')
        elif name == 'attestation-signature':
            source = source.replace('!signature(a.NotaryKey, r.Digest, sig)', 'false')
        elif name == 'anchor-id':
            source = source.replace('!ishex(attestationID, 64) || !ishex(childID, 64) || !ishex(parentID, 64)', 'false')
        elif name == 'attestation-size-off-by-one':
            source = source.replace('len(raw) > MaxAttestationBytes', 'len(raw) > MaxAttestationBytes+1')
        elif name == 'attestation-decode-size':
            source = source.replace('decode(r.Attestation, &a, MaxAttestationBytes)', 'decode(r.Attestation, &a, MaxAttestationBytes+1)')
        elif name == 'mvp-both-approvals':
            # Deliberately accept a missing approval set without indexing it;
            # a crash after dropping the length gate would prove nothing.
            source = source.replace('return refuse("MVP_MODE_APPROVAL_REQUIRED")', 'return nil', 1)
        elif name == 'mvp-current-grant-key':
            source = source.replace('!signature(k, digest, a.Signature)', '!signature(a.Owner[2:], digest, a.Signature) || k == ""')
        elif name == 'mvp-signature':
            source = source.replace('!signature(k, digest, a.Signature)', 'k == "" || digest == ""')
        elif name == 'mvp-approval-order':
            source = source.replace('approvals[0].Owner >= approvals[1].Owner', 'false')
        elif name == 'mvp-signing-authorities':
            source = source.replace('policy.IssuerOwner[2:] == policy.DelegatorOwner[2:]', 'policy.IssuerOwner == policy.DelegatorOwner')
        if source == path.read_text():
            raise RuntimeError('mutation did not apply: '+name)
        path.write_text(source)
        pattern = '/'.join('^'+re.escape(x)+'$' for x in test.split('/'))
        command = [go, 'test', '-count=1', '-run', pattern, '.']
        proc = subprocess.Popen(command, cwd=copy, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (work/(name+'.pid')).write_text(str(proc.pid)+'\n')
        try:
            output = proc.communicate(timeout=90)[0].decode(errors='replace')
        except subprocess.TimeoutExpired:
            proc.kill()  # Only this script's own exact child PID.
            proc.communicate()
            raise RuntimeError('mutant timed out: '+name) from None
        (work/(name+'.log')).write_text(output)
        named = '--- FAIL: '+test+' '
        killed = proc.returncode == 1 and named in output and 'panic:' not in output and '[build failed]' not in output
        observed = re.search(r'got ([A-Z_]+)', output)
        verdict = observed.group(1) if observed else 'named assertion failed'
        if not killed:
            survivors.append((name, test, 'SURVIVOR; this test does not establish '+bound))
            verdict = 'SURVIVOR (exit '+str(proc.returncode)+')'
        rows.append('| '+ ' | '.join([name, bound, test if killed else 'none', verdict])+' |')
        (work/'mutation-results.md').write_text('\n'.join(rows)+'\n')
        shutil.rmtree(copy)
    report = '\n'.join(rows)+'\n'
    (work/'mutation-results.md').write_text(report)
    print(report, end='')
    for name, test, bound in survivors:
        print(f'SURVIVOR {name}: {test}: {bound}', file=sys.stderr)
    print(f'{len(cases)-len(survivors)}/{len(cases)} named controls killed; {len(survivors)} survivors')
    return bool(survivors)


if __name__ == '__main__':
    raise SystemExit(main())
