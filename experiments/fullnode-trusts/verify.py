#!/usr/bin/env python3
"""Read-only verifier: no signer import, wallet/cookie access or signing RPC."""
import argparse
import json
import sys
from protocol import ReadRPC, load, verify

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--capability', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--request', required=True)
    parser.add_argument('--signature', required=True)
    parser.add_argument('--pins', required=True)
    args = parser.parse_args()
    try:
        pins = load(args.pins)
        result = verify(ReadRPC(load(args.capability)), load(args.fixture), load(args.request),
                        load(args.signature), pins['issuer'], pins['grantee'])
    except (OSError, ValueError, KeyError, TypeError):
        result = {'decision': 'refuse', 'reason': 'MALFORMED_INPUT_OR_CAPABILITY'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['decision'] == 'admit' else 1

if __name__ == '__main__':
    sys.exit(main())
