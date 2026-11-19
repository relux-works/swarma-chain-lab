#!/usr/bin/env python3
"""Bounded controls for B3a-CHILD. An intended named failure is mandatory.

No source is modified. Go overlays are isolated in --scratch. Full JSON test
streams, exact process exits and a summary are retained. Public-API plants
bound ordered slice refusals, successful neighbours and exact selected row
positions. None establishes the full admission predicate.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

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


OCTETS = '''\tfor _, key := range []string{c.get("seal").get("key").text, childRecipientKeyV4(c.get("recipient"))} {
\t\tif childKeyXV4(key) == delegation {
\t\t\treturn ChildAttenuationEvaluation{}, childRefusalV4(11, DelegateKeyReuse)
\t\t}
\t}'''
CS3 = '''\tfor _, key := range append(roles, delegation) {
\t\tif childKeyXV4(key) == childKeyXV4(seal.text) {
\t\t\treturn ChildAttenuationEvaluation{}, childRefusalV4(10, DelegateKeyReuse)
\t\t}
\t}'''
LIMIT_KEYS = '''\tfor _, limit := range c.get("limits").elements {
\t\tif !keys[grantLimitKey(limit)] {
\t\t\treturn childRefusalV4(17, ChildBudgetOver)
\t\t}
\t}'''
PLANTS += (
    ('f11-recipient-before-f10', 'seal := d.get("child_seal_key")',
     'if childKeyXV4(childRecipientKeyV4(c.get("recipient"))) == delegation { return ChildAttenuationEvaluation{}, childRefusalV4(11, DelegateKeyReuse) }; seal := d.get("child_seal_key")',
     'TestChildV4Precedence', 'TestChildV4Precedence/pair-f10-cs1-before-f11-key', 'want CHILD_SEAL_KEY at F10'),
    ('f11-octets-before-cs3', CS3+'\n'+OCTETS, OCTETS+'\n'+CS3,
     'TestChildV4Precedence', 'TestChildV4Precedence/pair-f10-cs3-before-f11-seal-even', 'want DELEGATE_KEY_REUSE at F10'),
    ('f17a-last-limit-only', 'for _, limit := range c.get("limits").elements {',
     'for _, limit := range c.get("limits").elements[max(0,len(c.get("limits").elements)-1):] {',
     'TestChildV4Template', 'TestChildV4Template/limit-missing-position-0-amount-0-true', 'want exact code CHILD_BUDGET_OVER'),
    ('f17a-flag-overwritten', LIMIT_KEYS,
     '\tmissingKey := false\n\tfor _, limit := range c.get("limits").elements { missingKey = !keys[grantLimitKey(limit)] }; if missingKey { return childRefusalV4(17, ChildBudgetOver) }',
     'TestChildV4Template', 'TestChildV4Template/limit-missing-position-0-amount-0-true', 'want exact code CHILD_BUDGET_OVER'),
    ('f2-chaindepth-again-input', 'childRefusalV4(2, ChainDepth)', '&ChildAttenuationFailure{Step:2,Code:ChainDepth,Again:ChildAgainInput}',
     'TestChildV4DefensiveF2', 'TestChildV4DefensiveF2/depth', 'want no at F2'),
    ('f2-notdelegable-again-state', 'childRefusalV4(2, NotDelegable)', '&ChildAttenuationFailure{Step:2,Code:NotDelegable,Again:ChildAgainState}',
     'TestChildV4DefensiveF2', 'TestChildV4DefensiveF2/not-delegable', 'want no at F2'),
    ('f2-mismatch-again-input', 'childRefusalV4(2, WireID)', '&ChildAttenuationFailure{Step:2,Code:WireID,Again:ChildAgainInput}',
     'TestChildV4Documents', 'TestChildV4Documents', 'want no at F2'),
    ('f11-octet-again-state-bykey', 'childRefusalV4(11, DelegateKeyReuse)',
     '&ChildAttenuationFailure{Step:11,Code:DelegateKeyReuse,Again:func() ChildAgain { if observation == nil { return ChildAgainState };return ChildAgainNo }()}',
     'TestChildV4RoleKeys', 'TestChildV4RoleKeys/child-recipient-key-reuse', 'want no at F11'),
    ('contradictory-key-facts-ignored', 'if o.ValueState != ParentNameValueKeys && len(o.ChannelKeys) != 0 {', 'if false {',
     'TestChildV4ValuePolicies', 'TestChildV4ValuePolicies/value-no-key-with-delegation-key/adopted-true', 'want typed input:contradictory'),
    ('adoption-policy-ignored', 'if noKeyPass {', 'if false {',
     'TestChildV4ValuePolicies', 'TestChildV4ValuePolicies/value-no-key/adopted-true', 'comparison refused valid neighbour'),
)


def quantifier_plants():
    for position in range(3):
        for amount in ('0','1'):
            planted = LIMIT_KEYS.replace('for _, limit :=', 'for index, limit :=').replace('if !keys[grantLimitKey(limit)] {', 'if !keys[grantLimitKey(limit)] && !(index == '+str(position)+' && limit.get("amount").text == "'+amount+'") {')
            witness = 'TestChildV4Template/limit-missing-position-'+str(position)+'-amount-'+amount+'-true'
            yield ('f17a-skip-position-'+str(position)+'-amount-'+amount,LIMIT_KEYS,planted,'TestChildV4Template',witness,'want exact code CHILD_BUDGET_OVER')


def precedence_plants(module):
    """Each joint gets a bounded priority-inversion control, not a fixture-ID
    special case: both semantic defect predicates must hold before reversing
    that pair. Single-trigger controls therefore retain their normal outcomes.
    These plants establish only their named overlap, not every input shape.
    """
    delegation = 'd.get("key").text'
    template = 'd.get("groups").elements[0].get("template")'
    conditions = {
        'f5': 'c.get("contract").text != p.get("contract").text',
        'f8': 'c.get("genesis").text != p.get("genesis").text',
        'f9': 'childKeyXV4(p.get("issuer").get("owner").text) == '+delegation,
        'f10': 'd.get("child_seal_key") != nil && childKeyXV4(d.get("child_seal_key").text) == '+delegation,
        'f10-cs1': 'd.get("child_seal_key") == nil',
        'f11': 'childKeyXV4(childRecipientKeyV4(c.get("recipient"))) == '+delegation,
        'f12': 'd.get("child_seal_key") != nil && c.get("seal").get("key").text != d.get("child_seal_key").text',
        'f13a': 'func() bool { var count uint64; for _, group := range d.get("groups").elements { for _, span := range group.get("ranges").elements { count += grantNumber(span.get("count")) } }; ordinal := grantNumber(c.get("ordinal")); return ordinal == 0 || ordinal > count }()',
        'f14': '!bytes.Equal(serialize(c.get("executor")),serialize('+template+'.get("executor")))',
        'f15': '!bytes.Equal(serialize(c.get("recipient")),serialize('+template+'.get("recipient")))',
        'f16': 'func() bool { allowed := map[string]bool{}; for _, action := range d.get("actions").elements { allowed[action.text] = true };for _, action := range c.get("actions").elements { if !allowed[action.text] { return true } }; return false }()',
        'f17a': 'func() bool { allowed := map[string]bool{};for _, limit := range '+template+'.get("limits").elements { allowed[grantLimitKey(limit)] = true }; for _, limit := range c.get("limits").elements { if !allowed[grantLimitKey(limit)] { return true } }; return false }()',
        'f17b': 'len(c.get("limits").elements) != 0 || len('+template+'.get("limits").elements) != 0',
        'f18': 'grantNumber(c.get("not_before_height")) < grantNumber(p.get("not_before_height")) || grantNumber(c.get("not_after_height")) > grantNumber(p.get("not_after_height"))',
        'channel': 'observation != nil && observation.ValueState == ParentNameValueKeys && childChannelContainsV4(observation.ChannelKeys,'+delegation+')',
    }
    conditions['f10-cs3'] = conditions['f10']
    for role in ('seal-even','seal-odd','key','owner-even','owner-odd'):
        conditions['f11-'+role] = ('childKeyXV4(c.get("seal").get("key").text) == '+delegation if role.startswith('seal') else conditions['f11'])
    codes = {'f5':(5,'ChildContractDiffers'),'f8':(8,'SubjectMismatch'),'f9':(9,'DelegateKeyReuse'),
             'f10':(10,'DelegateKeyReuse'),'f11':(11,'DelegateKeyReuse'),'f12':(12,'ChildSealKey'),
             'f13a':(13,'ChildOrdinal'),'f14':(14,'ChildAgentNotAllowed'),'f15':(15,'ChildGranteeNotAllowed'),
             'f16':(16,'ChildActionsWider'),'f17a':(17,'ChildBudgetOver'),'f17b':(17,'LimitKindUndefined'),
             'f18':(18,'ChildWindowNotNested')}
    anchor = 'if c.get("contract").text != p.get("contract").text {'
    vectors = json.loads((module/'testdata/child-v4.json').read_text())['vectors']
    for vector in vectors:
        if not vector.get('pair'):
            continue
        earlier,later = vector['pair']
        if later == 'channel':
            refusal = '&ChildAttenuationFailure{Step:11,Code:DelegateKeyReuse,Again:ChildAgainState}'
            diagnostic = 'want no at F11'
        else:
            step,code = codes.get(later, (11,'DelegateKeyReuse'))
            refusal = 'childRefusalV4('+str(step)+','+code+')'
            diagnostic = ('want exact code '+vector['expect'] if vector['step'] == step else 'want '+vector['expect']+' at F'+str(vector['step']))
        priority = 'if ('+conditions[earlier]+') && ('+conditions[later]+') { return ChildAttenuationEvaluation{}, '+refusal+' }; '+anchor
        yield ('priority-'+vector['id'],anchor,priority,'TestChildV4Precedence','TestChildV4Precedence/'+vector['id'],diagnostic)


def reviewer_plants(original):
    """Real sub-check moves, not predicate-conditioned priority inversions.

    Each named reviewer survivor keeps its mechanism and a generated witness.
    Equivalent and out-of-contract plants are documented, not counted as kills.
    """
    def replace(source, old, new):
        if source.count(old) != 1:
            raise ValueError('non-unique reviewer anchor: '+old[:90])
        return source.replace(old, new, 1)

    def plant(name, changed, vector, diagnostic, group='TestChildV4Generated'):
        witness=group+'/'+vector
        if group=='TestChildV4Generated':
            witness+='/policy-false'
        return name,original,changed,group,witness,diagnostic

    f12='\tif c.get("seal").get("key").text != seal.text {'
    count='\tvar count uint64'
    f9loop='\tfor _, key := range roles {\n\t\tif childKeyXV4(key) == delegation {'
    roles={'grantkey':'index == 0','precipient':'index == 2','pseal':'index == 3','notary':'index >= 4'}
    for role,condition in roles.items():
        for boundary,anchor in (('f10',OCTETS),('f11',f12)):
            changed=replace(original,f9loop,'\tfor index, key := range roles {\n\t\tif ('+condition+') { continue }; if childKeyXV4(key) == delegation {')
            delayed='\tfor index,key := range roles { if ('+condition+') && childKeyXV4(key)==delegation { return ChildAttenuationEvaluation{},childRefusalV4(9,DelegateKeyReuse) } }\n'
            changed=replace(changed,anchor,delayed+anchor)
            form={'precipient':'recipient-key'}.get(role,role)
            later='f10-cs1' if boundary=='f10' else 'f11-octet-seal-even'
            yield plant('f9-'+role+'-after-'+boundary,changed,'form-pair-f9-'+form+'-before-'+later,'want DELEGATE_KEY_REUSE at F9')
    for role,condition in (('pseal','index == 3'),('notaries','index >= 4')):
        changed=replace(original,f9loop,'\tfor index,key := range roles {\n\t\tif ('+condition+') { continue }; if childKeyXV4(key) == delegation {')
        delayed='\tfor index,key := range roles { if ('+condition+') && childKeyXV4(key)==delegation { return ChildAttenuationEvaluation{},childRefusalV4(9,DelegateKeyReuse) } }\n'
        changed=replace(changed,count,delayed+count)
        form='notary' if role=='notaries' else role
        yield plant('f9-'+role+'-after-f12',changed,'form-pair-f9-'+form+'-before-f10-cs1','want DELEGATE_KEY_REUSE at F9')
    for name,anchor in (('cs3-roles-after-f11',f12),('cs3-f9keys-after-f12',count)):
        changed=replace(original,CS3,CS3.replace('append(roles, delegation)','[]string{delegation}'))
        delayed=CS3.replace('append(roles, delegation)','roles')+'\n'
        changed=replace(changed,anchor,delayed+anchor)
        yield plant(name,changed,'adopt-f10-cs3-grantkey-before-f11-key','want DELEGATE_KEY_REUSE at F10')
    overcount='''\tif func() bool { var total uint64; for _,group := range d.get("groups").elements { for _,rng := range group.get("ranges").elements { total += grantNumber(rng.get("count")) } }; return grantNumber(c.get("ordinal"))>total }() { return ChildAttenuationEvaluation{},childRefusalV4(13,ChildOrdinal) }\n'''
    for boundary,anchor,vector,diagnostic in (
            ('f12',f12,'form-pair-f12-seal-before-f13a-overcount','want CHILD_SEAL_KEY at F12'),
            ('f9','\troles := []string{','form-pair-f9-grantkey-before-f13a-overcount','want DELEGATE_KEY_REUSE at F9')):
        changed=replace(original,'ordinal == 0 || ordinal > count','ordinal == 0 || false && ordinal > count')
        changed=replace(changed,anchor,overcount+anchor)
        yield plant('f13a-overcount-before-'+boundary,changed,vector,diagnostic)
    class_block='''\tif r.get("class") != nil {
\t\tif c.get("recipient").get("name") == nil {
\t\t\treturn childRefusalV4(15, ChildGranteeNotAllowed)
\t\t}
\t} else if !bytes.Equal(serialize(c.get("recipient")), serialize(r)) {'''
    skip_class='''\tif r.get("class") != nil {
\t} else if !bytes.Equal(serialize(c.get("recipient")), serialize(r)) {'''
    class_check='\tif template.get("recipient").get("class")!=nil && c.get("recipient").get("name")==nil { return childRefusalV4(15,ChildGranteeNotAllowed) }\n'
    changed=replace(original,class_block,skip_class)
    changed=replace(changed,'\tif !bytes.Equal(serialize(c.get("executor")), serialize(template.get("executor"))) {',class_check+'\tif !bytes.Equal(serialize(c.get("executor")), serialize(template.get("executor"))) {')
    yield plant('f15-class-before-f14',changed,'form-pair-f14-name-before-f15-class','want CHILD_AGENT_NOT_ALLOWED at F14')
    changed=replace(original,class_block,skip_class)
    end='''\t\treturn childRefusalV4(18, ChildWindowNotNested)
\t}
\treturn nil'''
    changed=replace(changed,end,'''\t\treturn childRefusalV4(18, ChildWindowNotNested)
\t}
'''+class_check+'\treturn nil')
    yield plant('f15-class-after-f18',changed,'form-pair-f15-class-before-f16-action','want CHILD_GRANTEE_NOT_ALLOWED at F15')
    lower='grantNumber(c.get("not_before_height")) < grantNumber(p.get("not_before_height"))'
    for boundary,anchor,vector,diagnostic,outer in (
        ('f14','\tif !bytes.Equal(serialize(c.get("executor")), serialize(template.get("executor"))) {','form-pair-f14-name-before-f18-lower','want CHILD_AGENT_NOT_ALLOWED at F14',False),
        ('f17',LIMIT_KEYS,'form-pair-f17a-missing-0-before-f18-lower','want CHILD_BUDGET_OVER at F17',False),
        ('f5','\tif c.get("contract").text != p.get("contract").text {','form-pair-f5-contract-before-f18-lower','want CHILD_CONTRACT_DIFFERS at F5',True)):
        changed=replace(original,lower,'false && '+lower)
        refusal='ChildAttenuationEvaluation{}, ' if outer else ''
        changed=replace(changed,anchor,'\tif '+lower+' { return '+refusal+'childRefusalV4(18,ChildWindowNotNested) }\n'+anchor)
        yield plant('f18-notbefore-before-'+boundary,changed,vector,diagnostic)
    validate='''\tif err := observation.validateWithPolicy(p, noKeyPass); err != nil {
\t\treturn ChildAttenuationEvaluation{}, err
\t}'''
    changed=replace(original,validate,'')
    changed=replace(changed,count,validate+'\n'+count)
    yield plant('value-state-after-f12',changed,'form-pair-f11-value-refused-before-f12-seal','want typed implementation:refused')
    guard='''\tif o.ValueState != ParentNameValueKeys && len(o.ChannelKeys) != 0 {
\t\treturn bad(ParentObservationContradictory, -1)
\t}'''
    early_guard='\tif observation!=nil && p.get("recipient").get("name")!=nil && observation.ValueState!=ParentNameValueKeys && len(observation.ChannelKeys)!=0 { return ChildAttenuationEvaluation{},&ParentNameObservationError{Kind:ParentObservationContradictory,KeyIndex:-1} }\n'
    for name,anchor,vector,diagnostic in (
        ('contradictory-before-octets',OCTETS,'form-pair-f11-octet-key-before-f11-contradictory-no-key','want DELEGATE_KEY_REUSE at F11'),
        ('contradictory-before-f5','\tif c.get("contract").text != p.get("contract").text {','form-pair-f5-contract-before-f11-contradictory-refused','want CHILD_CONTRACT_DIFFERS at F5')):
        changed=replace(original,guard,'')
        changed=replace(changed,anchor,early_guard+anchor)
        yield plant(name,changed,vector,diagnostic)
    narrowed=guard.replace('o.ValueState != ParentNameValueKeys','(o.ValueState == ParentNameValueNoKey || o.ValueState == ParentNameValueRefused || o.ValueState == "")')
    for name in ('contradictory-enumerated','contradictory-known-states-only'):
        yield plant(name,replace(original,guard,narrowed),'adopt-unknown-with-other-key','want typed input:contradictory')
    ref='''\tif c.get("parent").text != parent.ID() {
\t\treturn ChildAttenuationEvaluation{}, childRefusalV4(2, WireID)
\t}'''
    depth='''\tif p.get("parent") != nil {
\t\treturn ChildAttenuationEvaluation{}, childRefusalV4(2, ChainDepth)
\t}'''
    notdeleg='''\tif d == nil {
\t\treturn ChildAttenuationEvaluation{}, childRefusalV4(2, NotDelegable)
\t}'''
    depth_early=depth+'\n'+ref
    changed=replace(original,ref,depth_early)
    changed=replace(changed,depth+'\n\td :=', '\td :=')
    yield plant('q2-depth-before-ref',changed,'f2-ref-before-depth','want exact code WIRE_ID','TestChildV4GeneratedF2')
    for name,anchor,vector,code in (
        ('q2-notdeleg-before-ref',ref,'f2-ref-before-notdelegable','WIRE_ID'),
        ('q2-notdeleg-before-depth',depth,'f2-depth-before-notdelegable','CHAIN_DEPTH'),
        ('f2-notdelegable-before-depth',depth,'f2-depth-before-notdelegable','CHAIN_DEPTH')):
        moved=notdeleg.replace('d == nil','p.get("delegate") == nil')+'\n'
        changed=replace(original,notdeleg,'')
        changed=replace(changed,anchor,moved+anchor)
        yield plant(name,changed,vector,'want exact code '+code,'TestChildV4GeneratedF2')
    contract='''\tif c.get("contract").text != p.get("contract").text {
\t\treturn ChildAttenuationEvaluation{}, childRefusalV4(5, ChildContractDiffers)
\t}'''
    for name in ('q1-f5-before-f2-ref','f5-before-f2-mismatch'):
        changed=replace(original,contract,'')
        changed=replace(changed,ref,contract+'\n'+ref)
        yield plant(name,changed,'f2-ref-before-f5','want WIRE_ID at F2','TestChildV4GeneratedF2')
    for kind,loop,vector,diagnostic in (
        ('f16','for _, action := range c.get("actions").elements {','quant-actions-position-1-bad-true','want CHILD_ACTIONS_WIDER at F16'),
        ('f9','for _, n := range d.get("notaries").elements {','quant-notaries-position-1-bad-true','want DELEGATE_KEY_REUSE at F9')):
        collection='c.get("actions").elements' if kind=='f16' else 'd.get("notaries").elements'
        for end,slice_expr in (('first',collection+'[:min(1,len('+collection+'))]'),('last',collection+'[max(0,len('+collection+')-1):]')):
            changed=replace(original,loop,loop.replace(collection,slice_expr))
            yield plant(kind+'-'+end+('-action-only' if kind=='f16' else '-notary-only'),changed,vector,diagnostic)


def generated_quantifier_plants(original):
    for label,collection,loop,vector,diagnostic in (
        ('delegable-actions','p.get("delegate").get("actions").elements','for _, action := range p.get("delegate").get("actions").elements {','quant-actions-position-1-bad-false','comparison refused valid neighbour'),
        ('template-keys','template.get("limits").elements','for _, limit := range template.get("limits").elements {','quant-template-keys-position-1-bad-false','want exact code LIMIT_KIND_UNDEFINED'),
        ('channel-member','keys','for _, key := range keys {','quant-channel-member-position-1-bad-true','want DELEGATE_KEY_REUSE at F11'),
        ('channel-validation','o.ChannelKeys','for i, key := range o.ChannelKeys {','quant-channel-key-position-1-bad-true','want typed input:key')):
        for end,slice_expr in (('first',collection+'[:min(1,len('+collection+'))]'),('last',collection+'[max(0,len('+collection+')-1):]')):
            if original.count(loop)!=1:
                raise ValueError('non-unique quantifier anchor '+label)
            changed=original.replace(loop,loop.replace(collection,slice_expr),1)
            name='generated-'+label+'-'+end+'-only'
            yield name,original,changed,'TestChildV4Generated','TestChildV4Generated/'+vector+'/policy-false',diagnostic
    for end,position in (('first','4'),('last','len(roles)-1')):
        loop='for _, key := range append(roles, delegation) {'
        changed=original.replace(loop,'for index, key := range append(roles, delegation) { if index>=4 && index<len(roles) && index!='+position+' { continue };',1)
        yield 'generated-cs3-notaries-'+end+'-only',original,changed,'TestChildV4Generated','TestChildV4Generated/quant-cs3-notaries-position-1-bad-true/policy-false','want DELEGATE_KEY_REUSE at F10'


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
        while os.getloadavg()[0] >= 10:
            print('load gate waiting', name, os.getloadavg()[0], flush=True)
            time.sleep(15)
        (scratch / (name+'.load')).write_text(str(os.getloadavg()[0])+'\n')
        with (scratch / (name+'.json')).open('wb') as log:
            proc = subprocess.Popen(command, cwd=module, stdout=log, stderr=subprocess.STDOUT)
            (scratch / (name+'.pid')).write_text(str(proc.pid))
            code = proc.wait()
        (scratch / (name+'.exit')).write_text(str(code)+'\n')
        return code, (scratch / (name+'.json')).read_text()

    code, _ = run('baseline', ['go', 'test', '-count=1', '-json', '-run', '^TestChildV4', '.'])
    if code != 0:
        raise SystemExit('baseline did not pass: exit '+str(code))
    for name, old, new, group, witness, diagnostic in (*PLANTS, *quantifier_plants(), *precedence_plants(module), *reviewer_plants(original), *generated_quantifier_plants(original)):
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
        print(name, 'exit', code, 'killed', killed, 'test', witness, flush=True)
    (scratch/'results.json').write_text(json.dumps(results, indent=2)+'\n')
    print('plants total',len(results),'killed',sum(result['killed'] for result in results),'survivors',sum(not result['killed'] for result in results),flush=True)
    if not all(r['killed'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
