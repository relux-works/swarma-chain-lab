#!/usr/bin/env python3
"""Offline mandatory-DANE header control; never starts a Postfix service.

Run in the source-check sandbox with a hash-verified, extracted pinned Postfix
source tree and its postconf binary. The compiled excerpt uses exact upstream
macro/policy text with minimal types and a global dane-only policy stub. It
checks policy selection before DANE initialization, not delivery or cleanup.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--upstream', type=pathlib.Path, required=True)
parser.add_argument('--postconf', type=pathlib.Path, required=True)
parser.add_argument('--out', type=pathlib.Path, required=True)
args = parser.parse_args()
args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
receipt = {'started_at': now(), 'scope': 'offline effective configuration and exact upstream policy prefix; no runtime qualification',
           'commands': [], 'roles': {}}


def run(argv):
    started = now()
    result = subprocess.run([str(a) for a in argv], text=True, capture_output=True, timeout=20)
    record = {'argv': [str(a) for a in argv], 'started_at': started,
              'ended_at': now(), 'exit': result.returncode,
              'stdout': result.stdout, 'stderr': result.stderr}
    receipt['commands'].append(record)
    print(json.dumps(record), flush=True)
    if result.returncode:
        raise RuntimeError(f'command failed: {argv[0]} exit {result.returncode}')
    return result.stdout


try:
    here = pathlib.Path(__file__).resolve().parent.parent
    sources = {p: (args.upstream / p).read_text() for p in [
        'src/global/mail_params.h', 'src/global/sendopts.h', 'src/tls/tls.h',
        'src/smtp/smtp.h', 'src/smtp/smtp_tls_policy.c', 'src/cleanup/cleanup_message.c']}
    receipt['upstream_sha256'] = {p: hashlib.sha256(s.encode()).hexdigest() for p, s in sources.items()}
    receipt['postconf_sha256'] = hashlib.sha256(args.postconf.read_bytes()).hexdigest()
    assert re.search(r'#define DEF_TLSREQUIRED_ENABLE\s+"yes"', sources['src/global/mail_params.h'])
    assert 'if (hdr_opts->type == HDR_TLS_REQUIRED && var_tls_required_enable)' in sources['src/cleanup/cleanup_message.c']
    assert 'state->sendopts |= SOPT_REQUIRETLS_HEADER;' in sources['src/cleanup/cleanup_message.c']
    macro = re.search(r'#define STATE_TLS_NOT_REQUIRED\(state\).*?\n#endif', sources['src/smtp/smtp.h'], re.S).group().removesuffix('\n#endif')
    policy = sources['src/smtp/smtp_tls_policy.c']
    start = policy.index('    tls->level = global_tls_level();')
    end = policy.index('    } else if (tls_policy)', start)
    prefix = policy[start:end] + '    }\n'
    definitions = []
    for source, names in [
        ('src/global/sendopts.h', ['SOPT_REQUIRETLS_HEADER', 'SOPT_REQUIRETLS_ESMTP']),
        ('src/tls/tls.h', ['TLS_LEV_NOTFOUND', 'TLS_LEV_MAY', 'TLS_LEV_ENCRYPT', 'TLS_LEV_DANE_ONLY'])]:
        for name in names:
            definitions.append(re.search(r'^#define\s+' + name + r'\s+[^\n]+', sources[source], re.M).group())
    c = '''#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
''' + '\n'.join(definitions) + '\n' + macro + '''
struct Request { int sendopts; };
struct State { struct Request *request; };
struct Iterator { struct State *parent; };
struct TLS { int level; };
int var_tls_required_enable, var_reqtls_enable = 1;
int var_smtp_tls_wrappermode = 0, msg_verbose = 0;
#define msg_info(...) ((void)0)
static int global_tls_level(void) { return TLS_LEV_DANE_ONLY; }
static int select_prefix(int flags, int enable) {
    struct Request request = {flags};
    struct State state = {&request};
    struct Iterator iterator = {&state};
    struct Iterator *iter = &iterator;
    struct TLS tls_data = {0}; struct TLS *tls = &tls_data;
    int site_level;
    var_tls_required_enable = enable;
''' + prefix + '''
    (void)site_level;
    return tls->level;
}
int main(int argc, char **argv) {
    assert(argc == 2 && argv[1][0] == '0' && argv[1][1] == '\\0');
    int effective_enable = atoi(argv[1]);
    assert(select_prefix(0, 1) == TLS_LEV_DANE_ONLY);
    puts("PASS upstream default without header: dane-only retained");
    assert(select_prefix(SOPT_REQUIRETLS_HEADER, 1) == TLS_LEV_MAY);
    puts("PASS upstream default with TLS-Required:no: causal downgrade to may");
    assert(select_prefix(SOPT_REQUIRETLS_HEADER, effective_enable) == TLS_LEV_DANE_ONLY);
    puts("PASS effective candidate with header: dane-only retained");
    assert(select_prefix(0, effective_enable) == TLS_LEV_DANE_ONLY);
    puts("PASS effective candidate without header: dane-only retained");
    assert(select_prefix(SOPT_REQUIRETLS_HEADER|SOPT_REQUIRETLS_ESMTP, 1) == TLS_LEV_DANE_ONLY);
    puts("PASS upstream ESMTP REQUIRETLS: header downgrade suppressed");
    assert(select_prefix(SOPT_REQUIRETLS_HEADER|SOPT_REQUIRETLS_ESMTP, effective_enable) == TLS_LEV_DANE_ONLY);
    puts("PASS effective candidate ESMTP REQUIRETLS: dane-only retained");
}
'''
    cpath = args.out / 'policy-prefix-control.c'
    cpath.write_text(c)
    executable = pathlib.Path('/private/tmp/policy-prefix-control')
    run(['/usr/bin/gcc', '-std=c99', '-Wall', '-Wextra', '-Werror', cpath, '-o', executable])
    rendered = args.out / 'rendered'
    run([sys.executable, here / 'checks/render_config.py', here / 'config', rendered])
    for role in ['A', 'B', 'Bprime']:
        directory = rendered / role
        main = directory / 'main.cf'
        main.write_text(main.read_text().replace('config_directory = /lab/config', f'config_directory = {directory}'))
        def query(*options):
            return run([args.postconf, '-c', directory, *options]).strip()
        assert query('-d', '-h', 'mail_version') == '3.11.7'
        assert query('-d', '-h', 'tls_required_enable') == 'yes'
        value = query('-h', 'tls_required_enable')
        assert value == 'no', (role, value)
        assert query('-h', 'smtp_tls_security_level') == 'dane-only'
        assert query('-h', 'smtp_dns_support_level') == 'dnssec'
        query('-n')
        query('-M')
        overrides = query('-P')
        assert not re.search(r'/tls_required_enable\s*=', overrides), overrides
        assert not re.search(r'/smtp_tls_security_level\s*=', overrides), overrides
        run([executable, '0' if value == 'no' else '1'])
        receipt['roles'][role] = {'tls_required_enable': value, 'smtp_tls_security_level': 'dane-only',
                                 'upstream_default': 'yes', 'policy_control': 'PASS'}
    receipt['status'] = 'PASS'
except Exception as error:
    receipt['status'] = 'FAIL'
    receipt['error'] = str(error)
    raise
finally:
    receipt['ended_at'] = now()
    (args.out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
