#!/usr/bin/env python3
"""Bounded source overlays: require the named behavioral assertion to fail."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

MODULE = Path(__file__).resolve().parents[1]


def run(out, label, args):
    load = Path('/proc/loadavg').read_text()
    (out / (label + '-load.log')).write_text(load)
    if float(load.split()[0]) >= 10:
        raise RuntimeError('load gate blocked')
    proc = subprocess.Popen(args, cwd=MODULE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy())
    stdout, stderr = proc.communicate()
    (out / (label + '-process.json')).write_text(json.dumps({'argv': args, 'cwd': str(MODULE), 'pid': proc.pid, 'exit': proc.returncode}, indent=2) + '\n')
    (out / (label + '.log')).write_bytes(stdout + stderr)
    events = []
    for line in stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    return proc.returncode, events


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError('plant did not apply exactly once')
    return source.replace(before, after, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = Path(args.out)
    if not out.is_absolute() or out.exists():
        raise RuntimeError('output must be a new absolute directory')
    out.mkdir(parents=True)
    adapter = MODULE / 'adapter_linux.go'
    client = MODULE / 'client_linux.go'
    unit = MODULE / 'unit_linux.go'
    source_api = MODULE / 'source_linux.go'
    refusal_tests = MODULE / 'refusal_linux_test.go'
    intake = MODULE / 'intake_linux.go'
    original = {p: p.read_text() for p in (adapter, client, unit, source_api, refusal_tests, intake)}
    source = original[adapter]
    start = source.index('\tid, e := OperationID()\n')
    end = source.index('\tfail := func(', start)
    block = source[start:end]
    ordered = source[:start] + source[end:]
    point = ordered.index('\tif e = guard.Validate(ctx, m, op, "intake")')
    early_material = ordered[:point] + block + ordered[point:]
    plants = [
        ('material-before-admission', adapter, early_material,
         'TestPrepareRefusalsBeforeMaterial', 'TestPrepareRefusalsBeforeMaterial/intake',
         'No lease acquisition before intake, scan and dequeue acceptance.'),
        ('placeholder-instead-of-material', adapter,
         replace_once(source, '"Bearer "+string(l.value)', '"Bearer "+"placeholder-current"'),
         'TestPrepareOrderingAndMapping', 'TestPrepareOrderingAndMapping',
         'The qualified slot maps to the leased value, not the placeholder.'),
        ('unchecked-broker-uid', client,
         replace_once(original[client], 'uid != cfg.BrokerUID', 'uid != uid'),
         'TestIdentityAndRole', 'TestIdentityAndRole/server-uid',
         'Kernel broker UID is verified before hello.'),
        ('ordinary-refusal-closes-all', client,
         replace_once(original[client], 'err := refusal(r.Code)',
                      'c.invalidate()\n\t\terr := refusal(r.Code)'),
         'TestRefusalScope', 'TestRefusalScope/request-lease_unbound',
         'An ordinary refusal preserves unrelated leases and the connection epoch.'),
        ('grant-refusal-closes-connection', client,
         replace_once(original[client], 'err == ErrRole ||',
                      'err == Code("grant_expired") || err == ErrRole ||'),
         'TestBrokerRefusalTable', 'TestBrokerRefusalTable/grant_expired/request',
         'A grant refusal has no connection-wide effect.'),
        ('stale-principal-keeps-connection', client,
         replace_once(original[client], ' || err == Code("lease_not_owner")', ''),
         'TestBrokerRefusalTable', 'TestBrokerRefusalTable/lease_not_owner/renew',
         'A stale principal immediately closes every cached lease.'),
        ('refusal-table-code-added', refusal_tests,
         replace_once(original[refusal_tests], '{"grant_malformed", false},',
                      '{"fixture_new_refusal", false},\n\t{"grant_malformed", false},'),
         'TestBrokerRefusalTable', 'TestBrokerRefusalTable',
         'An extra table row outside the pinned wire set is rejected.'),
        ('refusal-table-code-removed', refusal_tests,
         replace_once(original[refusal_tests], '\t{"grant_malformed", false},\n', ''),
         'TestBrokerRefusalTable', 'TestBrokerRefusalTable',
         'A missing table row cannot silently omit an accepted wire code.'),
        ('dot-generation-admitted', unit,
         replace_once(original[unit], '!generationName.MatchString(in.Generation)',
                      '!valid(in.Generation)'),
         'TestInstallTemplateRefusals', 'TestInstallTemplateRefusals/dot-generation',
         'Listener generations cannot collapse to the parent directory.'),
        ('source-rejects-broker-label', source_api,
         replace_once(original[source_api], '!validCaller(caller)',
                      '!valid(caller.Account) || !valid(caller.Generation) || !valid(caller.LaunchID)'),
         'TestSourceLifecycle', 'TestSourceLifecycle',
         'Source accepts the pinned broker slash-label control.'),
        ('opaque-classification-error', adapter,
         replace_once(source, 'op, body, e := adapter.Classify(in)\n\tif e != nil {\n\t\treturn nil, nil, sanitized(e)',
                      'op, body, e := adapter.Classify(in)\n\tif e != nil {\n\t\treturn nil, nil, e'),
         'TestPrepareErrorSanitization', 'TestPrepareErrorSanitization/classify',
         'Adapter errors cross only the closed diagnostic seam.'),
        ('unchecked-hello-generation', client,
         replace_once(original[client], 'h.Principal.Generation != cfg.Generation', 'false'),
         'TestIdentityAndRole', 'TestIdentityAndRole/generation',
         'Hello must match the protected service generation.'),
    ]
    intake_source = original[intake]
    intake_plants = [
        ('intake-policy-body', 'request.Method == http.MethodGet && len(body) != 0', 'false',
         'TestIntakeRefusalNeighbours', 'TestIntakeRefusalNeighbours/policy/body',
         'A one-byte policy body is not an admitted credentialless request.'),
        ('intake-cookie', '"proxy-authorization", "cookie",', '"proxy-authorization",',
         'TestIntakeRefusalNeighbours', 'TestIntakeRefusalNeighbours/policy/Cookie',
         'Cookie is a worker credential on either admitted shape.'),
        ('intake-auth-token', '"cookie", "x-auth-token",', '"cookie",',
         'TestIntakeRefusalNeighbours', 'TestIntakeRefusalNeighbours/messages/X-Auth-Token',
         'An alternate auth-token cannot bypass the placeholder-only shape.'),
        ('intake-anthropic-token', '"x-auth-token", "anthropic-auth-token",', '"x-auth-token",',
         'TestIntakeRefusalNeighbours', 'TestIntakeRefusalNeighbours/policy/Anthropic-Auth-Token',
         'An Anthropic auth-token is not credentialless policy input.'),
        ('intake-access-token', ', "x-access-token":', ':',
         'TestIntakeRefusalNeighbours', 'TestIntakeRefusalNeighbours/messages/X-Access-Token',
         'An access-token is not an admitted extra worker credential.'),
        ('intake-body-bound', 'len(body) > MaxIntakeBody', 'len(body) > 1<<30',
         'TestIntakeBodyBoundary', 'TestIntakeBodyBoundary/over-boundary',
         'The provider-sized input bound refuses even one extra byte.'),
        ('intake-body-truncation', 'MaxIntakeBody+1', '65537',
         'TestIntakeBodyBoundary', 'TestIntakeBodyBoundary/boundary',
         'Accepted provider-sized bodies reach the upstream without truncation.'),
        ('intake-inventory-bound', 'len(g.values) >= 256', 'len(g.values) >= 1<<30',
         'TestIntakeInventoryExhaustion', 'TestIntakeInventoryExhaustion',
         'The 257th distinct value refuses and fences registered upstream use.'),
        ('intake-inventory-fence', 'if len(g.values) >= 256 {\n\t\tg.blocked = true\n\t\tg.cancel()', 'if len(g.values) >= 256 {\n\t\tg.blocked = true',
         'TestIntakeInventoryExhaustion', 'TestIntakeInventoryExhaustion',
         'Inventory refusal also cancels previously admitted streams.'),
        ('intake-metering', 'if g.source.ReserveGeneration(body) != nil {', 'if false {',
         'TestIntakeMetering', 'TestIntakeMetering',
         'Generation requires successful metering before leasing or forwarding.'),
        ('intake-whole-stream-cap', 'http.Client{Transport: g.transport,', 'http.Client{Transport: g.transport, Timeout: g.idleTimeout,',
         'TestIntakeStreamIdleBound', 'TestIntakeStreamIdleBound/progress',
         'Active streams are not subject to a whole-exchange duration cap.'),
        ('intake-idle-stall', 'idle.Reset(g.idleTimeout)', 'idle.Reset(time.Hour)',
         'TestIntakeStreamIdleBound', 'TestIntakeStreamIdleBound/stalled',
         'A silent upstream must lose authority rather than stall indefinitely.'),
        ('intake-encoded-response', 'if response.Header.Get("Content-Encoding") != "" {', 'if false {',
         'TestIntakeEncodedResponse', 'TestIntakeEncodedResponse/encoded',
         'An encoded response cannot bypass the material byte matcher.'),
        ('intake-peer-uid', 'peer.uid != g.mapping.Caller.UID', 'peer.uid != peer.uid',
         'TestIntakeRefusals', 'TestIntakeRefusals/policy-unauthorized-peer',
         'A public marker and policy path cannot replace the qualified kernel UID.'),
        ('intake-marker', '[]byte("Bearer "+Placeholder)', '[]byte("Bearer other-placeholder")',
         'TestIntakeRefusals', 'TestIntakeRefusals/wrong-placeholder',
         'The incoming model marker is exactly the owner-selected literal.'),
        ('intake-mapping-marker', 'mapping.Placeholder != Placeholder', 'mapping.Placeholder != mapping.Placeholder',
         'TestIntakeMapping', 'TestIntakeMapping/placeholder',
         'Protected mapping data cannot choose another marker.'),
        ('intake-tuple', 'caller != mapping.Caller', 'caller != caller',
         'TestIntakeMapping', 'TestIntakeMapping/caller',
         'The holder and listener must name the same caller tuple.'),
        ('intake-generation', 'generation != mapping.ServiceGeneration', 'generation != generation',
         'TestIntakeMapping', 'TestIntakeMapping/generation',
         'The holder and listener must name the same service generation.'),
        ('intake-message-path', 'request.URL.EscapedPath() == "/v1/messages"', 'request.URL.EscapedPath() == "/v1/complete"',
         'TestIntakeRefusals', 'TestIntakeRefusals/wrong-path',
         'Messages are not a general upstream path proxy.'),
        ('intake-message-method', 'request.Method == http.MethodPost &&', 'request.Method == http.MethodPut &&',
         'TestIntakeRefusals', 'TestIntakeRefusals/wrong-method',
         'Possession of the marker does not admit another model method.'),
        ('intake-policy-path', 'request.URL.EscapedPath() == "/api/claude_code/policy_limits"', 'request.URL.EscapedPath() == "/api/claude_code/settings"',
         'TestIntakeRefusals', 'TestIntakeRefusals/policy-wrong-path',
         'Unmeasured policy/bootstrap endpoints remain closed.'),
        ('intake-policy-method', 'request.Method == http.MethodGet && request.URL.EscapedPath()', 'request.Method == http.MethodPost && request.URL.EscapedPath()',
         'TestIntakeRefusals', 'TestIntakeRefusals/policy-method',
         'The credentialless policy shape admits GET only.'),
        ('intake-duplicate-marker', 'len(authorization) == 1 &&', 'len(authorization) >= 1 &&',
         'TestIntakeRefusals', 'TestIntakeRefusals/duplicate-authorization',
         'Duplicate Authorization values are refused even when identical.'),
        ('intake-api-key', 'else if credentialHeader(key) {', 'else if credentialHeader(key) && !strings.EqualFold(key, "X-Api-Key") {',
         'TestIntakeRefusals', 'TestIntakeRefusals/api-key',
         'A second worker credential is not silently accepted or forwarded.'),
        ('intake-policy-credential', 'return len(authorization) == 0', 'return len(authorization) <= 1',
         'TestIntakeRefusals', 'TestIntakeRefusals/policy-authorization',
         'The policy GET is credentialless, not another bearer path.'),
        ('intake-recipient', 'target := upstreamOrigin +', 'target := "https://untrusted.invalid" +',
         'TestIntakeAdmission', 'TestIntakeAdmission/messages',
         'Only the pinned HTTPS origin receives leased material.'),
        ('intake-query', 'target += "?" + request.URL.RawQuery', 'target += "?discarded=true"',
         'TestIntakeAdmission', 'TestIntakeAdmission/messages',
         'The measured model query bytes reach the fixed recipient unchanged.'),
        ('intake-injection', '"Bearer "+string(material)', '"Bearer "+Placeholder',
         'TestIntakeAdmission', 'TestIntakeAdmission/messages',
         'The upstream receives the leased token rather than the marker.'),
        ('intake-status', 'writer.WriteHeader(response.StatusCode)', 'writer.WriteHeader(http.StatusOK)',
         'TestIntakeUpstreamErrors', 'TestIntakeUpstreamErrors/401',
         'A real upstream refusal cannot become synthetic success.'),
        ('intake-buffering', 'reader.Read(buffer)', 'io.ReadFull(reader, buffer)',
         'TestIntakeSSEIncremental', 'TestIntakeSSEIncremental',
         'The first frame must arrive before upstream completion.'),
        ('intake-body-reflection', 'bytes.ReplaceAll(pending, value, []byte("[redacted]"))', 'bytes.ReplaceAll(pending, value, value)',
         'TestIntakeSecretBoundary', 'TestIntakeSecretBoundary',
         'A token split across upstream reads cannot reach worker bytes.'),
        ('intake-header-reflection', 'if containsMaterial([]byte(key+strings.Join(values, "")), g.needles()) {', 'if len(values) < 0 {',
         'TestIntakeSecretBoundary', 'TestIntakeSecretBoundary',
         'Meaningful response headers are still a secret boundary.'),
        ('intake-lease-fence', 'if call.Err() != nil {', 'if call.Err() != nil && version == "" {',
         'TestIntakeAuthorityFailures', 'TestIntakeAuthorityFailures/cancelled',
         'A cancelled lease version cannot submit an upstream request.'),
        ('intake-worker-body-scan', 'leak := containsMaterial(body, values)', 'leak := false',
         'TestIntakeWorkerLeak', 'TestIntakeWorkerLeak/body',
         'Worker bytes are screened against the newly acquired token before injection.'),
        ('intake-live-leak-fence', 'if leak {\n\t\tg.mu.Lock()\n\t\tg.blocked = true\n\t\tg.cancel()', 'if leak {\n\t\tg.mu.Lock()\n\t\tg.blocked = true',
         'TestIntakeLeakCancelsUse', 'TestIntakeLeakCancelsUse',
         'A worker leak retires already registered upstream use as well as new requests.'),
    ]
    for name, before, after, test, witness, claim in intake_plants:
        try:
            mutated = replace_once(intake_source, before, after)
        except RuntimeError as exc:
            raise RuntimeError(name + ': ' + str(exc)) from exc
        plants.append((name, intake, mutated, test, witness, claim))
    report = []
    code, _ = run(out, 'baseline', ['go', 'test', '-json', '-count=1', './...'])
    report.append({'plant': 'baseline', 'exit': code})
    if code:
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        raise RuntimeError('baseline failed')
    for name, path, mutated, test, witness, claim in plants:
        fixture = out / (name + '.go')
        fixture.write_text(mutated)
        overlay = out / (name + '.json')
        overlay.write_text(json.dumps({'Replace': {str(path): str(fixture)}}))
        code, events = run(out, name, ['go', 'test', '-vet=off', '-json', '-count=1',
                                      '-overlay=' + str(overlay), '-run=^' + test + '$', '.'])
        killed = code == 1 and any(e.get('Action') == 'fail' and e.get('Test') == witness for e in events)
        report.append({'plant': name, 'claim': claim, 'test': witness, 'exit': code,
                       'killed': killed,
                       'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        if not killed:
            (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            raise RuntimeError('plant survived or failed outside its named test')
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if any(p.read_text() != s for p, s in original.items()):
        raise RuntimeError('source changed during plants')
    print('baseline passed; all ' + str(len(plants)) + ' named plants killed')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
