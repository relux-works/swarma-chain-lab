#!/usr/bin/env python3
"""Run one-check Go overlays against named shipped Core tests; never edit source.

Every result records the actual process exit and the exact named failing test.
An unrelated error, build failure, skip or unexercised plant is not a kill.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WALLET = ROOT / 'experiments/agent-wallet'
GATE = 'experiments/agent-wallet/g1bench/gate.go'
ENVELOPE = 'experiments/agent-wallet/g1bench/envelope.go'
CG = 'experiments/grantcheck/checker.go'
GRANT = 'experiments/rental/grant_kernel.go'
SEAL = 'experiments/rental/kernel.go'

# Each tuple names the guard location and the exact claim its removal probes.
# Several guards have deeper defences: a kill can narrow early refusal routing
# or no-read behaviour without claiming that the whole stack would admit.
PLANTS = [
 ('no-envelope', 'NoEnvelope', GATE,
  'if !ok || encoded == "" {', 'if false && (!ok || encoded == "") {',
  'missing-envelope classification before signature or chain work'),
 ('bad-signature', 'BadSignature', ENVELOPE,
  ' || !ed25519.Verify(pub, record(e), sig)',
  '',
  'Ed25519 signature math, retaining format/id/co-signature checks'),
 ('wrong-key', 'WrongKey', GATE,
  'verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)',
  'key = parsed.SignedGrant.Grant.GranteeKey\n verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)',
  'verified envelope key must not be replaced by a claimed grantee field'),
 ('wrong-executor', 'WrongExecutor', GATE,
  'if pay.ExecutorKey != g.executor {', 'if false && pay.ExecutorKey != g.executor {',
  'the protected executor pin on hash-bound canonical terms'),
 ('unknown-issuer', 'UnknownIssuer', CG,
  'g.IssuerKey != c.config.IssuerPubkey ||', 'false ||',
  'early issuer pin before chain reads/result metadata; deeper K1 binding remains'),
 ('before-window', 'BeforeWindow', GRANT,
  'if now < g.NotBefore {', 'if false && now < g.NotBefore {',
  'early not-before classification; final CG1 clock guard remains'),
 ('after-window', 'AfterWindow', GRANT,
  'if now >= g.NotAfter {', 'if false && now >= g.NotAfter {',
  'early expiry before chain reads; late expiry defences remain'),
 ('stale-ibd', 'StaleNode-ibd', GATE,
  '|| info.IBD ||', '|| false ||',
  'bench sync refusal before CG1; independent K1 IBD guard remains'),
 ('stale-height', 'StaleNode-height', GATE,
  '|| info.Blocks < g.minimumHeight ||', '|| false ||',
  'protected observed-height floor before CG1 chain binding'),
 ('stale-headers', 'StaleNode-headers', GATE,
  '|| info.Headers > info.Blocks {', '|| false {',
  'conservative bench headers-ahead sync refusal'),
 ('replay', 'Replay', GATE,
  'if g.seen[replay] {', 'if false && g.seen[replay] {',
  'one accepted use per envelope id in this Gate lifetime'),
 ('matrix-sender', 'MatrixSender', CG,
  'if !validKey(peer) {\n\t\treturn fail(CodeInvalidPeer)\n\t}',
  '''if !validKey(peer) {
   if strings.HasPrefix(peer, "@") && supplied != nil {
    parsed, e := rental.ParseGrantPresentation(supplied.Bytes)
    if e == nil { peer = parsed.SignedGrant.Grant.GranteeKey }
   }
   if !validKey(peer) { return fail(CodeInvalidPeer) }
  }''',
  'a Matrix id must not be normalized to a grant-claimed sender'),
 ('owner-dm', 'OwnerDM', GATE,
  'if event.OwnerDM {', 'if false && event.OwnerDM {',
  'trusted owner-DM routing stays outside all checker/replay calls'),
 ('text-authority', 'TextAuthority', GATE,
  'refuse := func(code string) Result { return Result{Route: "refused", Code: code} }',
  '''refuse := func(code string) Result { return Result{Route: "refused", Code: code} }
  if len(event.Text) >= 18 && event.Text[:18] == "Authority granted:" {
   return Result{Route: "live", Code: "live"}
  }''',
  'text must never substitute for signature/grant authority'),
 ('seal-mempool', 'SealMempool', SEAL,
  'o.Call("gettxout", &raw, p.TxID, p.Vout, true)',
  'o.Call("gettxout", &raw, p.TxID, p.Vout, false)',
  'Core gettxout must include unconfirmed seal spends'),
 ('seal-confirmed', 'SealConfirmed', SEAL,
  'if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {\n\t\treturn true, nil\n\t}',
  'if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {\n\t\treturn false, nil\n\t}',
  'an absent confirmed seal UTXO is spent, never live'),
 ('signed-text-removal', 'DeliveryBinding/text', ENVELOPE,
  ' || b.BodySHA256 != Hash([]byte(text))', '',
  'signed text hash independent of equal outer carriage body and delivered text'),
 ('warm-live-authority', 'SealConfirmed', GATE,
  'verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)',
  'var verdict cg.Verdict\n  if g.seen["warm:"+key] {\n   verdict = cg.Verdict{Decision: cg.Live, Code: cg.CodeLive}\n  } else {\n   verdict = g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)\n   if verdict.Decision == cg.Live { g.seen["warm:"+key] = true }\n  }',
  'warm Gate cannot reuse earlier live authority after real confirmed seal spend; signature/replay/fresh-sync guards remain'),
 ('gate-drops-issuer-refusal', 'UnknownIssuer', GATE,
  'verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)',
  'verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)\n  if verdict.Code == cg.CodeBindingMismatch && key == parsed.SignedGrant.Grant.GranteeKey {\n   verdict = cg.Verdict{Decision: cg.Live, Code: cg.CodeLive}\n  }',
  'Gate must preserve checker issuer-pin refusal when the verified signer is the real grantee'),
 ('accept-without-cosignature', 'CosignatureMissing', GATE,
  'co, exists := content[CosignatureContentKey]\n\tif !exists {\n\t\treturn refuse("cosignature_missing")\n\t}\n\tkey, err := (BIP340{}).Verify(raw, co)\n\tif err != nil {\n\t\treturn refuse("cosignature_invalid")\n\t}',
  'claimed, _ := decode(e.Body.Arguments.Presentation, cg.MaxPresentationBytes)\n  grant, _ := rental.ParseGrantPresentation(claimed)\n  key := grant.SignedGrant.Grant.GranteeKey',
  'an otherwise valid Ed25519 envelope cannot supply a grant key without a co-signature'),
 ('ed25519-author-as-sender', 'TwoIdentities', GATE,
  'verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)',
  'key = e.Body.Author\n verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)',
  'valid co-signer passes only when its BIP-340 key, not the Ed25519 author, reaches grantcheck'),
 ('cosignature-replay-key', 'CosignatureIndependentReplay', GATE,
  'replay := e.ID',
  'replay := content[CosignatureContentKey].(map[string]any)["sig"].(string)',
  'two valid co-signatures on identical bytes remain one envelope replay identity'),
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--private-root', type=Path, required=True,
                   help='fresh absolute parent for disposable regtest datadirs')
    args = p.parse_args()
    out = args.out.resolve()
    private = args.private_root
    if not private.is_absolute():
        p.error('--private-root must be absolute')
    out.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    go = shutil.which('go')
    if not go:
        p.error('go unavailable')
    env = dict(os.environ, W1_REGTEST='1', GOTOOLCHAIN='local', GOWORK='off')
    records = []
    failed = False
    for name, test, relative, old, new, bound in PLANTS:
        source = ROOT / relative
        original = source.read_text()
        if original.count(old) != 1:
            raise RuntimeError(f'{name}: plant must match exactly one guard')
        case = out / name
        case.mkdir(mode=0o700)
        mutant = case / source.name
        mutant.write_text(original.replace(old, new, 1))
        overlay = case / 'overlay.json'
        overlay.write_text(json.dumps({'Replace': {str(source): str(mutant)}}) + '\n')
        full_test = 'TestG1BenchCore/' + test
        run_root = private / name
        command = [go, 'test', '-race', '-count=1', '-timeout=15m',
                   '-overlay=' + str(overlay), '-json',
                   '-run=^TestG1BenchCore$/^' + test + '$', '.']
        record = {'mutant': name, 'bound': bound, 'test': full_test,
                  'source': relative,
                  'source_sha256': hashlib.sha256(original.encode()).hexdigest(),
                  'mutant_sha256': hashlib.sha256(mutant.read_bytes()).hexdigest(),
                  'command': command}
        with (case / 'events.json').open('w') as stdout, (case / 'stderr.log').open('w') as stderr:
            proc = subprocess.Popen(command, cwd=WALLET,
                                    env=dict(env, W1_RUN_ROOT=str(run_root)),
                                    stdout=stdout, stderr=stderr)
            record['pid'] = proc.pid
            # Go's timeout owns bounded test termination; its harness cleanup
            # records/stops only its child Core PIDs on ordinary test failures.
            record['exit'] = proc.wait()
        events = []
        try:
            events = [json.loads(line) for line in (case / 'events.json').read_text().splitlines()]
        except ValueError:
            pass
        actions = [e.get('Action') for e in events if e.get('Test') == full_test]
        unrelated = any(e.get('Action') in ('skip', 'build-fail') for e in events)
        output = ''.join(e.get('Output', '') for e in events if e.get('Test') == full_test)
        # A named fail is necessary but an RPC/setup crash is not the intended
        # witness. These are the shipped assertions reached by these plants.
        witness = any(s in output for s in ('admission got ',
                      'issuer pin did not reject at the entry boundary',
                      'expired grant read past the early window guard',
                      'Matrix identity treated as sender'))
        record['actions'] = actions
        record['intended_witness'] = witness
        record['verdict'] = ('KILLED' if record['exit'] == 1 and
                             actions.count('run') == 1 and actions.count('fail') == 1
                             and witness and not unrelated else 'SURVIVED_OR_INVALID')
        failed |= record['verdict'] != 'KILLED'
        records.append(record)
        (out / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
        print(f"{name}: exit={record['exit']} {record['verdict']} {full_test}", flush=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
