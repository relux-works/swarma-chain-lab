#!/usr/bin/env python3
"""Bounded disposable Core 28.0 regtest service exercise; no external peers.

Requires a binary verified against the official release SHA256SUMS. Generates
throwaway signing keys only in memory; records decisions, not wallet/key data.
Own child PIDs are terminated/waited in finally and the datadir is removed.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference as ref


def octets(v):
    return json.dumps(v, separators=(',', ':'), ensure_ascii=False).encode()


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def write_private(path, value):
    with path.open('xb') as out:
        os.chmod(path, 0o600)
        out.write(value)


def run(args):
    work = Path(args.work_dir).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    data = work / 'node'
    data.mkdir(mode=0o700)
    service = Path(args.service).resolve()
    daemon = Path(args.namecoind).resolve()
    version = subprocess.run([str(daemon), '--version'], check=True, capture_output=True).stdout
    assert b'version v28.0' in version, 'requires Core 28.0'
    rpc_port = port()
    node = None
    serving = None
    results = []
    log = (work / 'process.log').open('wb')
    cookie = data / 'regtest' / '.cookie'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def rpc(method, *params, wallet=False):
        credential = cookie.read_bytes().strip()
        url = f'http://127.0.0.1:{rpc_port}' + ('/wallet/test' if wallet else '')
        req = urllib.request.Request(url, octets(dict(jsonrpc='1.0', id=1, method=method, params=list(params))),
                                     {'Authorization': 'Basic ' + base64.b64encode(credential).decode(), 'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=10) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            result = json.load(error)
        if result.get('error'):
            raise RuntimeError('regtest RPC refused: ' + method + ' code=' + str(result['error']['code']))
        return result['result']

    def stop(proc):
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    try:
        node = subprocess.Popen([str(daemon), f'-datadir={data}', '-regtest=1', '-server=1', '-listen=0',
                                 '-connect=0', '-dnsseed=0', '-discover=0', '-fixedseeds=0', '-namehistory=1',
                                 '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', f'-rpcport={rpc_port}',
                                 '-fallbackfee=0.001', '-printtoconsole=0', '-nodebuglogfile'], stdout=log, stderr=log)
        (work / 'node.pid').write_text(str(node.pid) + '\n')
        for _ in range(100):
            if node.poll() is not None:
                raise RuntimeError('regtest node exited during startup')
            try:
                info = rpc('getblockchaininfo')
                assert info['chain'] == 'regtest'
                break
            except (OSError, RuntimeError):
                time.sleep(0.1)
        else:
            raise RuntimeError('regtest node readiness timeout')
        rpc('createwallet', 'test', False, False, '', False, True)
        address = rpc('getnewaddress', wallet=True)
        rpc('generatetoaddress', 110, address)
        # Reuse fixture encoders only, without executing their vector writers.
        # Replace all public fixture scalars with fresh throwaway in-memory keys.
        source = (ROOT / 'scripts/make-fixtures.py').read_text().split('\nvectors = []')[0]
        env = {'__file__': str(ROOT / 'scripts/make-fixtures.py')}
        exec(compile(source, 'fixture-encoders', 'exec'), env)
        env['TEST_KEYS'] = {role: secrets.randbelow(ref.N - 1) + 1 for role in env['TEST_KEYS']}
        env['AT'] = int(time.time())
        env['event'].__defaults__ = (env['AT'] - 10,)
        public = env['public']
        owner = env['owner']
        sign = env['sign']
        keys = env['TEST_KEYS']
        key_path = work / 'attestation.key'
        generated = subprocess.run([str(service), 'keygen', '-out', str(key_path)], check=True, capture_output=True)
        notary_public = generated.stdout.decode().strip()
        assert len(notary_public) == 64
        names = {
            'id/certifier': dict(swarma=dict(notary=dict(attest=notary_public))),
            'id/owner-a': dict(swarma=dict(landlord=dict(grant=public(keys['issuer_owner'])))),
            'id/owner-b': dict(swarma=dict(landlord=dict(grant=public(keys['delegator_owner'])))),
        }
        commitments = {name: rpc('name_new', name, wallet=True) for name in names}
        rpc('generatetoaddress', 12, address)
        for name, value in names.items():
            txid, rand = commitments[name]
            rpc('name_firstupdate', name, rand, txid, octets(value).decode(), wallet=True)
        rpc('generatetoaddress', 1, address)
        assert rpc('getconnectioncount') == 0, 'unexpected peer'
        observations = {name: rpc('name_show', name) for name in names}
        registrations = {name: dict(txid=n['txid'], vout=n['vout']) for name, n in observations.items()}
        info = rpc('getblockchaininfo')
        parent, child = env['contracts']()
        parent['not_before'] -= 3600
        parent['not_after'] += 3600
        child['not_before'] -= 3600
        child['not_after'] += 3600
        parent['delegate']['notaries'][0]['registration'] = registrations['id/certifier']
        bundle = env['bundle'](parent, child)
        statement = json.loads(bundle['statement'])
        statement.update(tip_height=info['blocks'], tip_hash=info['bestblockhash'])
        # Seal/issuance/checkpoint locators remain synthetic checker inputs. This
        # run proves service + live names/tip, not the deferred seal/issuance gates.
        request = {k: json.loads(bundle[k]) for k in ('parent', 'child', 'parent_contract', 'child_contract', 'request')}
        request['statement'] = statement
        strict = json.loads(bundle['policy'])

        def check_case(label, policy, presented, expected):
            nonlocal serving
            policy_path = work / (label + '-policy.json')
            policy_raw = octets(policy)
            write_private(policy_path, policy_raw)
            presented = copy.deepcopy(presented)
            presented['policy_reference'] = hashlib.sha256(policy_raw).hexdigest()
            service_port = port()
            config = dict(listen=f'127.0.0.1:{service_port}', key_file=str(key_path),
                          rpc_endpoint=f'http://127.0.0.1:{rpc_port}', rpc_credential_file=str(cookie),
                          deployment_policy_file=str(policy_path), limits=dict(request_bytes=65536,
                          requests_per_second=10, burst=10, timeout_ms=3000, concurrent=2))
            config_path = work / (label + '-config.json')
            write_private(config_path, octets(config))
            serving = subprocess.Popen([str(service), 'serve', '-config', str(config_path)], stdout=log, stderr=log)
            (work / (label + '.pid')).write_text(str(serving.pid) + '\n')
            for _ in range(100):
                if serving.poll() is not None:
                    raise RuntimeError('service exited during startup')
                try:
                    with socket.create_connection(('127.0.0.1', service_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            req = urllib.request.Request(f'http://127.0.0.1:{service_port}/v1/attest', octets(presented), {'Content-Type': 'application/json'})
            try:
                with opener.open(req, timeout=5) as response:
                    result = json.load(response)
            except urllib.error.HTTPError as error:
                result = json.load(error)
            assert result['decision'] == expected, label + ': ' + result['decision']
            if expected == 'ATTEST':
                envelope = result['signed_attestation']
                attestation = envelope['attestation']
                digest = ref.sha(b'swarma-notary-v1' + octets(attestation))
                assert ref.verify(notary_public, digest, envelope['signature']), 'BIP-340 signature'
                aid = ref.sha(octets(envelope))
                commitment = ref.sha(b'swarma-attest-v1' + bytes.fromhex(aid) + bytes.fromhex(policy['child_grant_id']) + bytes.fromhex(policy['parent_grant_id']))
                assert result['anchor_frame'] == '6a03534c044201' + commitment + '01' + aid, 'anchor frame'
            else:
                assert set(result) == {'decision'}, 'refusal returned signed fields'
            results.append(dict(case=label, decision=result['decision'], signature_verified=expected == 'ATTEST'))
            print(label + ': ' + result['decision'], flush=True)
            stop(serving)
            serving = None

        check_case('positive-strict', strict, request, 'ATTEST')
        mismatch = copy.deepcopy(request)
        mismatch['statement']['tip_height'] += 1
        check_case('mismatched-tip', strict, mismatch, 'NODE_TIP_MISMATCH')
        absent = dict(strict, notary_name='id/unregistered')
        check_case('unregistered-name', absent, request, 'NODE_NAME_UNREGISTERED')
        same = dict(strict, mode='mvp-pair-owned-notary')
        check_case('same-owner-mvp', same, request, 'MVP_MODE_PAIR_REQUIRED')
        pair = dict(strict)
        pair['delegator_owner'] = owner('delegator_owner')
        pair['agreed_by'] = sorted([pair['issuer_owner'], pair['delegator_owner']])
        pair['mode'] = 'mvp-pair-owned-notary'
        identities = sorted([dict(owner=owner(role), name=name, registration=registrations[name]) for role, name in
                             [('issuer_owner', 'id/owner-a'), ('delegator_owner', 'id/owner-b')]], key=lambda v: v['owner'])
        digest = ref.sha(b'swarma-notary-local-policy-v1' + octets(pair) + octets(identities))
        role_by_owner = {owner(role): role for role in ('issuer_owner', 'delegator_owner')}
        pair['mode_approvals'] = [dict(identity, signature=sign(keys[role_by_owner[identity['owner']]], digest)) for identity in identities]
        check_case('two-owner-mvp', pair, request, 'ATTEST')
        (work / 'results.json').write_bytes(octets(dict(core='28.0', chain='regtest', peer_count=0, cases=results)) + b'\n')
    finally:
        stop(serving)
        stop(node)
        log.close()
        shutil.rmtree(data)
        if (work / 'attestation.key').exists():
            (work / 'attestation.key').unlink()
        # Configs contain machine-local locations and must not be published.
        for pattern in ('*-config.json', '*-policy.json'):
            for path in work.glob(pattern):
                path.unlink()
        (work / 'cleanup.json').write_bytes(octets(dict(node_stopped=node is None or node.poll() is not None,
                                                       service_stopped=serving is None or serving.poll() is not None,
                                                       datadir_removed=not data.exists(), key_removed=not (work/'attestation.key').exists())) + b'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namecoind', required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--work-dir', required=True)
    try:
        run(parser.parse_args())
    except Exception as error:
        # Never print RPC responses, credential content, process argv or keys.
        print('REGTEST_FAILED ' + type(error).__name__ + ': ' + str(error) if isinstance(error, (AssertionError, RuntimeError)) else 'REGTEST_FAILED ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
