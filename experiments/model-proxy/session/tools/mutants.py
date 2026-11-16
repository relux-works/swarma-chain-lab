#!/usr/bin/env python3
"""Bounded compiler-overlay controls; never modify the candidate source.

Run with -I from the model-proxy module. Logs contain commands, exit codes,
source digests and named failing assertions. Compilation/setup failures are
not killed mutants. Each command executes directly, without shell pipelines.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE = Path('session/session.go').resolve()
# Each replacement targets one laboratory contract, not a production proxy.
MUTANTS = [
 ('write-front-gate', 'WriteOK cannot outrank T8.1 channel or replay refusals', 'TestWriteCommitOrder',
  [('if !s.ready {', 'if !f.WriteOK { return "JOURNAL_WRITE" }; if !s.ready {'),
   ('func gate(p Profile, s State) Code {', 'func gate(p Profile, s State, f Facts) Code {'),
   ('gate(p, input)', 'gate(p, input, f)')]),
 ('channel', 'channel before open/token processing', 'TestVectors/S13-23',
  [('return c == "local" || c == "private-authenticated"', 'return true')]),
 ('replay', 'signed request identity is single admission', 'TestVectors/S13-2',
  [('return s.seen[f.RequestID] || (s.fenced && f.Iat <= s.fence)', 'return false')]),
 ('binding', 'open requires a supported binding form', 'TestVectors/S13-5',
  [('if !validBinding(f.Binding) {', 'if false {')]),
 ('window', 'open window check cannot be omitted', 'TestVectors/S13-3',
  [('if !validWindow(f.Now, f.End) {', 'if false {')]),
 ('limits', 'requested ceilings cannot exceed grant authority', 'TestVectors/S13-4',
  [('if !validLimits(f) {', 'if false {')]),
 ('unknown', 'signed mutations require path-bound session identity', 'TestVectors/S13-14',
  [('return commit(input, s, f, result(Unknown))', 'return commit(input, s, f, result(Admitted))')]),
 ('token', 'an unrecognized token cannot borrow a known session', 'TestVectors/S13-8',
  [('if id == "" {\n\t\treturn fail(input, TokenUnknown)\n\t}',
    'if id == "" { for k := range input.sessions { id = k; break } }'),
   ('digest: digest,', 'digest: r.Digest,')]),
 ('peer', 'known token alone is insufficient for a different uid', 'TestVectors/S13-7',
  [('if !peerMatches(f, r.Binding) {', 'if false {')]),
 ('ended', 'a recorded close stays final before clock expiry', 'TestVectors/S13-19',
  [('if r.Ended {', 'if false {')]),
 ('command', 'bearer cannot authorize lifecycle commands', 'TestVectors/S13-10',
  [('if f.Action == "open" || f.Action == "extend" || f.Action == "close" {', 'if false {')]),
 ('session-account', 'session counter is checked after grant/row counters', 'TestVectors/S13-17',
  [('if !fits(used[l.Key], l.Amount, r.Limits[l.Key]) {', 'if false {')]),
 ('window-plus-one', '3601 seconds is outside the proposed hour', 'TestVectors/S13-3',
  [('end-now <= 3600', 'end-now <= 3601')]),
 ('expiry', 'window end is exclusive', 'TestVectors/S13-9',
  [('if now >= r.End {', 'if now > r.End {')]),
 ('extension-backwards', 'extension cannot shorten an existing end', 'TestVectors/S13-12',
  [('r.End = max(r.End, f.End)', 'r.End = f.End')]),
 ('token-storage', 'retained state has no plaintext token field', 'TestTokenCustody',
  [('type record struct {', 'type record struct {\n Plain Token'),
   ('ID: f.RequestID,', 'ID: f.RequestID, Plain: f.Random,')]),
 ('token-repeat', 'a repeated opening returns no credential', 'TestTokenCustody',
  [('return commit(input, s, f, result(Replay))', 'token := f.Random; return commit(input, s, f, Result{Code:Admitted, Token:&token})')]),
 ('profile', 'default profile refuses', 'TestProfileGate',
  [('if p != Draft {', 'if false {')]),
 ('unvalidated-spend', 'unvalidated evidence creates no closure', 'TestVectors/unvalidated-observation',
  [('if c.Validated && c.Grant != "" {', 'if c.Grant != "" {')]),
 ('partial-debit', 'late refusal leaves earlier debit uncommitted', 'TestVectors/S13-17',
  [('accounts[own] += l.Amount', 'accounts[own] += l.Amount\n s.accounts = accounts')]),
 ('closure-race', 'current journal end and closure stop a prepared request', 'TestVectors/S13-24',
  [('if !live(&s, r.ID, f.Now) {', 'if false {'),
   ('if closedPath(s, r.Path) {', 'if false {')]),
 ('recovery-fence', 'fresh journal refuses lost-era signed requests', 'TestVectors/S13-21',
  [('return s.seen[f.RequestID] || (s.fenced && f.Iat <= s.fence)', 'return s.seen[f.RequestID]')]),
 ('absent-session-limit', 'missing session limit has ceiling zero', 'TestVectors/session-missing-limit',
  [('if !fits(used[l.Key], l.Amount, r.Limits[l.Key]) {',
    'ceiling, present := r.Limits[l.Key]; if !present { ceiling = ^uint64(0) }; if !fits(used[l.Key], l.Amount, ceiling) {')]),
 ('token-format', 'all fmt verbs redact numeric and hex token arrays', 'TestTokenOutputFormat',
  [('func (Token) Format(s fmt.State, _ rune)', 'func (Token) removedFormat(s fmt.State, _ rune)')]),
 ('token-json', 'Token implements the explicit JSON redaction boundary', 'TestTokenOutputJSON',
  [('func (Token) MarshalJSON()', 'func (Token) removedMarshalJSON()')]),
 ('token-text', 'Token implements the explicit text redaction boundary', 'TestTokenOutputText',
  [('func (Token) MarshalText()', 'func (Token) removedMarshalText()')]),
 ('token-inline-storage', 'bad-verb %p cannot reflect inline token octets', 'TestTokenBadVerb/Token/value/fmt/%p',
  [('type Token struct{ value *string }', 'type Token [32]byte'),
   ('func newToken(raw [32]byte) Token {\n\tif raw == [32]byte{} {\n\t\treturn Token{}\n\t}\n\tvalue := string(raw[:])\n\treturn Token{value: &value}\n}',
    'func newToken(raw [32]byte) Token { return Token(raw) }'),
   ('func tokenBytes(t Token) (raw [32]byte) {\n\tif t.value != nil {\n\t\tcopy(raw[:], *t.value)\n\t}\n\treturn raw\n}',
    'func tokenBytes(t Token) [32]byte { return [32]byte(t) }')]),
 ('token-return', 'explicit opening accessor preserves the issued token', 'TestTokenExplicitReturn',
  [('return tokenBytes(t)', 'return [32]byte{}')]),

]


def execute(command, path):
    with path.open('w') as out:
        process = subprocess.Popen(command, stdout=out, stderr=subprocess.STDOUT)
        pid = process.pid
        try:
            code = process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=15)
            code = 124
    return dict(command=command, pid=pid, exit=code, log=path.name)


def main():
    if not sys.flags.isolated or len(sys.argv) != 2:
        raise SystemExit('usage: python3 -I session/tools/mutants.py <owned-output-directory>')
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    report = dict(source_sha256=hashlib.sha256(source.encode()).hexdigest(), controls=[])
    baseline = execute(['go', 'test', '-count=1', './session'], out / 'baseline.log')
    report['baseline'] = baseline
    if baseline['exit']:
        (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        raise SystemExit('baseline failed')
    failed = False
    for name, bound, target, replacements in MUTANTS:
        mutated = source
        for old, new in replacements:
            # A shared helper can have several call sites; this is explicit and
            # recorded rather than choosing an arbitrary substring occurrence.
            count = mutated.count(old)
            if not count:
                raise SystemExit(f'{name}: mutation not applied')
            mutated = mutated.replace(old, new)
        path = out / (name + '.go')
        path.write_text(mutated)
        overlay = out / (name + '.json')
        overlay.write_text(json.dumps({'Replace': {str(SOURCE): str(path)}}))
        run = execute(['go', 'test', '-vet=off', '-count=1', '-overlay=' + str(overlay),
                       '-run', '/'.join('^' + re.escape(part) + '$' for part in target.split('/')), './session'], out / (name + '.log'))
        log = (out / run['log']).read_text()
        witness = re.findall(r'--- FAIL: (Test[^\n]+)', log)
        killed = (run['exit'] == 1 and witness and target in log
                  and 'build failed' not in log and 'panic:' not in log
                  and ('verdict=' in log or 'token' in log or 'default profile' in log
                       or 'refusal partially' in log or 'end of' in log
                       or 'secret disclosed by output sink' in log))
        row = dict(mutant=name, bound=bound, target=target, witness=witness,
                   status='killed' if killed else 'survived-or-invalid',
                   mutant_sha256=hashlib.sha256(mutated.encode()).hexdigest(), **run)
        report['controls'].append(row)
        failed |= not killed
        print(f"{name}: {row['status']} exit={run['exit']} target={target}", flush=True)
        (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != report['source_sha256']:
        raise SystemExit('candidate source changed')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
