#!/usr/bin/env python3
"""Bounded controls for B3a-CHILD. An intended named failure is mandatory.

No source is modified. Go overlays are isolated in --scratch. Full JSON test
streams, exact process exits and a summary are retained. Public-API plants
bound ordered slice refusals, successful neighbours and exact selected row
positions. None establishes the full admission predicate.
"""
import argparse
import json
from pathlib import Path
import subprocess

PLANTS = (
    ('f11-no-key-passes', 'const childNoKeyPassV4 = false', 'const childNoKeyPassV4 = true',
     'TestChildV4ParentNameValueReader', 'TestChildV4ParentNameValueReader/nostr-absent', 'want typed implementation:no-key'),
    ('f11-refused-as-no-key', 'return childValueRefusalV4(ParentNameValueRefused)', 'return childValueRefusalV4(ParentNameValueNoKey)',
     'TestChildV4ParentNameValueReader', 'TestChildV4ParentNameValueReader/duplicate-top-level-nostr', 'want typed implementation:refused'),
    ('f11-refused-as-empty-keys', 'return childValueRefusalV4(ParentNameValueRefused)', 'o.ChannelKeys = nil',
     'TestChildV4ParentNameValueReader', 'TestChildV4ParentNameValueReader/duplicate-top-level-nostr', 'want typed implementation:refused'),
    ('f11-unset-as-no-key', 'return childValueRefusalV4(o.ValueState)', 'return childValueRefusalV4(ParentNameValueNoKey)',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/value-unset', 'want typed implementation:'),
    ('nil-pair-parent-first', 'if child == nil || child.object == nil {',
     'if parent == nil || parent.object == nil { return ChildAttenuationEvaluation{}, childRefusalV4(2, WireID) }; if child == nil || child.object == nil {',
     'TestChildV4InputPrecedence', 'TestChildV4InputPrecedence/missing', 'input precedence:'),
    ('f11-before-f10', 'seal := d.get("child_seal_key")',
     'if childKeyXV4(c.get("seal").get("key").text) == delegation { return ChildAttenuationEvaluation{}, childRefusalV4(11, DelegateKeyReuse) }; seal := d.get("child_seal_key")',
     'TestChildV4RoleKeys', 'TestChildV4RoleKeys/missing-childseal-before-delegation-reuse', 'want CHILD_SEAL_KEY at F10'),
    ('f17a-first-limit-only', 'for _, limit := range c.get("limits").elements {',
     'for _, limit := range c.get("limits").elements[:min(1, len(c.get("limits").elements))] {',
     'TestChildV4Template', 'TestChildV4Template/limit-later-missing-key-true', 'want exact code CHILD_BUDGET_OVER'),
    ('f11-again-mark-conflated', 'Code: DelegateKeyReuse, Again: ChildAgainState',
     'Code: DelegateKeyReuse, Again: ChildAgainNo',
     'TestChildV4Again', 'TestChildV4Again/delegation-in-set', 'want state'),
    ('missing-parent-again-no', 'Code: WireID, Again: ChildAgainInput',
     'Code: WireID, Again: ChildAgainNo',
     'TestChildV4InputPrecedence', 'TestChildV4InputPrecedence/missing-parent', 'want input'),
    ('accept-everything', 'func CheckChildAttenuationV4(parent, child *SignedGrant, observation *ParentNameObservation) (ChildAttenuationEvaluation, error) {',
     'func CheckChildAttenuationV4(parent, child *SignedGrant, observation *ParentNameObservation) (ChildAttenuationEvaluation, error) {\n return ChildAttenuationEvaluation{}, nil',
     'TestChildV4Prefix', 'TestChildV4Prefix/contract', 'want CHILD_CONTRACT_DIFFERS'),
    ('always-in-set', 'if key == delegation {', 'if true || key == delegation {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/name-valid-neighbour', 'comparison refused valid neighbour'),
    ('never-in-set', 'if key == delegation {', 'if false && key == delegation {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/delegation-in-set', 'want DELEGATE_KEY_REUSE at F11'),
    ('observation-name-ignored', 'if o.Name != name.text {', 'if false && o.Name != name.text {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/different-name', 'want typed input:name'),
    ('observation-empty-allowed', 'if len(o.ChannelKeys) == 0 {', 'if false && len(o.ChannelKeys) == 0 {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/empty-set', 'want typed input:empty'),
    ('observation-duplicate-allowed', 'if seen[key] {', 'if false && seen[key] {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/duplicate-set', 'want typed input:duplicate'),
    ('observation-malformed-key-allowed', 'if CheckSigningKey(key) != nil {', 'if false && CheckSigningKey(key) != nil {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/offcurve-key', 'want typed input:key'),
    ('observation-chain-ignored', 'if o.Genesis != parent.get("genesis").text {', 'if false && o.Genesis != parent.get("genesis").text {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/different-chain', 'want typed input:chain'),
    ('observation-identity-ignored', 'if !hexForm(o.Genesis, 32) || !hexForm(o.TipHash, 32) {', 'if false && (!hexForm(o.Genesis, 32) || !hexForm(o.TipHash, 32)) {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/missing-tip', 'want typed input:identity'),
    ('first-channel-only', 'for _, key := range keys {', 'for _, key := range keys[:1] {',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/delegation-last-in-set', 'want DELEGATE_KEY_REUSE at F11'),
    ('observation-before-octets', 'd := p.get("delegate")', 'if err := observation.validate(p); err != nil { return ChildAttenuationEvaluation{}, err }; d := p.get("delegate")',
     'TestChildV4ParentNameObservation', 'TestChildV4ParentNameObservation/contract-before-observation', 'want CHILD_CONTRACT_DIFFERS at F5'),
    ('reject-everything', 'func checkChildTemplateV4(p, c, template *value) error {',
     'func checkChildTemplateV4(p, c, template *value) error {\n return childRefusalV4(14, ChildAgentNotAllowed)',
     'TestChildV4Template', 'TestChildV4Template/template-valid', 'comparison refused valid neighbour'),
    ('public-reject-everything', 'func CheckChildAttenuationV4(parent, child *SignedGrant, observation *ParentNameObservation) (ChildAttenuationEvaluation, error) {',
     'func CheckChildAttenuationV4(parent, child *SignedGrant, observation *ParentNameObservation) (ChildAttenuationEvaluation, error) {\n return ChildAttenuationEvaluation{}, childRefusalV4(13, ChildOrdinal)',
     'TestChildV4Prefix', 'TestChildV4Prefix/prefix-open', 'comparison refused valid neighbour'),
    ('parity-blind-seal', 'if c.get("seal").get("key").text != seal.text {',
     'if childKeyXV4(c.get("seal").get("key").text) != childKeyXV4(seal.text) {',
     'TestChildV4Prefix', 'TestChildV4Prefix/seal-parity', 'want CHILD_SEAL_KEY at F12'),
    ('executor-name-only', 'if !bytes.Equal(serialize(c.get("executor")), serialize(template.get("executor"))) {',
     'if c.get("executor").get("name").text != template.get("executor").get("name").text {',
     'TestChildV4Template', 'TestChildV4Template/executor-key', 'want CHILD_AGENT_NOT_ALLOWED'),
    ('unknown-kind-as-absent', 'if len(c.get("limits").elements) != 0 || len(template.get("limits").elements) != 0 {',
     'if false {', 'TestChildV4Template', 'TestChildV4Template/limit-5', 'want LIMIT_KIND_UNDEFINED'),
    ('missing-key-ignored', 'if !keys[grantLimitKey(limit)] {', 'if false && !keys[grantLimitKey(limit)] {',
     'TestChildV4Template', 'TestChildV4Template/new-key-zero', 'want exact code CHILD_BUDGET_OVER'),
    ('equal-window-rejected', 'grantNumber(c.get("not_before_height")) < grantNumber(p.get("not_before_height"))',
     'grantNumber(c.get("not_before_height")) <= grantNumber(p.get("not_before_height"))',
     'TestChildV4Template', 'TestChildV4Template/window-10-20', 'comparison refused valid neighbour'),
    ('ordinal-equality-rejected', 'ordinal == 0 || ordinal > count', 'ordinal == 0 || ordinal >= count',
     'TestChildV4Ordinal', 'TestChildV4Ordinal/ordinal-2', 'comparison refused valid neighbour'),
    ('ordinal-count-last-range-only', 'count += grantNumber(rng.get("count"))', 'count = grantNumber(rng.get("count"))',
     'TestChildV4Ordinal', 'TestChildV4Ordinal/ordinal-groups-ranges-9', 'comparison refused valid neighbour'),
    ('selected-row-bypassed', 'if err := checkChildTemplateV4(p, c, template); err != nil {',
     'if err := checkChildTemplateV4(p, c, template); false && err != nil {',
     'TestChildV4Selection', 'TestChildV4Selection/selection-other-template', 'want CHILD_AGENT_NOT_ALLOWED at F14'),
    ('groups-reversed', 'for groupIndex, group := range d.get("groups").elements {',
     'for groupOffset := range d.get("groups").elements { groupIndex := len(d.get("groups").elements)-1-groupOffset; group := d.get("groups").elements[groupIndex]',
     'TestChildV4Selection', 'TestChildV4Selection/selection-1', 'comparison refused valid neighbour'),
    ('ranges-reversed', 'for rangeIndex, rng := range group.get("ranges").elements {',
     'for rangeOffset := range group.get("ranges").elements { rangeIndex := len(group.get("ranges").elements)-1-rangeOffset; rng := group.get("ranges").elements[rangeIndex]',
     'TestChildV4Selection', 'TestChildV4Selection/selection-1', 'selected row ='),
    ('coins-descending', 'Vout: grantNumber(rng.get("first")) + remaining',
     'Vout: grantNumber(rng.get("first")) + rangeCount - 1 - remaining',
     'TestChildV4Selection', 'TestChildV4Selection/selection-1', 'selected row ='),
    ('coins-octet-order', 'Vout: grantNumber(rng.get("first")) + remaining',
     'Vout: func() uint64 { first := grantNumber(rng.get("first")); for candidate := first; candidate < first+rangeCount; candidate++ { rank := uint64(0); for other := first; other < first+rangeCount; other++ { if fmt.Sprint(other) < fmt.Sprint(candidate) { rank++ } }; if rank == remaining { return candidate } }; return first }()',
     'TestChildV4Selection', 'TestChildV4Selection/selection-1', 'selected row ='),
    ('count-from-zero', 'remaining := ordinal - 1', 'remaining := ordinal',
     'TestChildV4Selection', 'TestChildV4Selection/selection-1', 'selected row ='),
    ('template-before-bound', 'var count uint64',
     'checkChildTemplateV4(p, c, d.get("groups").elements[0].get("template"))\n var count uint64',
     'TestChildV4BoundBeforeTemplate', 'TestChildV4BoundBeforeTemplate/selection-zero', 'template read before ordinal bound'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', required=True, type=Path)
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    module = Path(__file__).resolve().parents[1]
    source = module / 'child_v4.go'
    original = source.read_text()
    results = []

    def run(name, command):
        with (scratch / (name+'.json')).open('wb') as log:
            proc = subprocess.Popen(command, cwd=module, stdout=log, stderr=subprocess.STDOUT)
            (scratch / (name+'.pid')).write_text(str(proc.pid))
            code = proc.wait()
        (scratch / (name+'.exit')).write_text(str(code)+'\n')
        return code, (scratch / (name+'.json')).read_text()

    code, _ = run('baseline', ['go', 'test', '-count=1', '-json', '-run', '^TestChildV4', '.'])
    if code != 0:
        raise SystemExit('baseline did not pass: exit '+str(code))
    for name, old, new, group, witness, diagnostic in PLANTS:
        if original.count(old) != 1:
            raise SystemExit('non-unique plant anchor: '+name)
        planted = scratch / (name+'.go')
        planted.write_text(original.replace(old, new))
        overlay = scratch / (name+'-overlay.json')
        overlay.write_text(json.dumps({'Replace': {str(source): str(planted)}}))
        code, output = run(name, ['go', 'test', '-overlay='+str(overlay), '-count=1', '-json', '-run', '^'+group+'$', '.'])
        events = []
        for line in output.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        failed = any(e.get('Action') == 'fail' and e.get('Test') == witness for e in events)
        killed = code == 1 and failed and diagnostic in output
        results.append(dict(plant=name, exit=code, test=witness, diagnostic=diagnostic, killed=killed))
        print(name, 'exit', code, 'killed', killed, flush=True)
    (scratch/'results.json').write_text(json.dumps(results, indent=2)+'\n')
    if not all(r['killed'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
