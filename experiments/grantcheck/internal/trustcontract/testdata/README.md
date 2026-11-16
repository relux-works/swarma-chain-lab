# LIP-0013 contract vectors

`lip-0013-contract-vectors.json` is derived from
`vectors/LIP-0013/trust-vectors.json` of swarma-link-spec at commit
`bd3bc80e5543d8a563343ec05abd1a5f3f67284c` (v0.1.51), whose SHA-256 is
`9c29cddd739d56c5d15f4663c3cc923c6ea016730fc62634bff4b4214bf27ff8`.

The derivation removes the last member, `envelopes`, and changes no other
byte: the file is the upstream octets before `,\n  "envelopes": [`, followed by
`\n}\n`. It keeps every contract vector: 4 valid contracts, 32 invalid
contracts, 15 bindings and the 3 grants of the envelope section. Its SHA-256
is recorded in `lip-0013-contract-vectors.json.sha256` and checked by
`TestVectorFilePinned`.

The 26 envelope vectors are left out for two reasons. This module admits no
kind-8185 instruction envelope, so it has no code that they would test. And
they hold Matrix user IDs on the host `matrix.example`, which the repository's
public-hygiene check does not list as an example domain, so a verbatim copy
fails that check.

To reproduce the file from the upstream one:

```sh
python3 - trust-vectors.json lip-0013-contract-vectors.json <<'PY'
import sys
up = open(sys.argv[1], 'rb').read()
marker = b',\n  "envelopes": ['
assert up.count(marker) == 1
open(sys.argv[2], 'wb').write(up[:up.index(marker)] + b'\n}\n')
PY
```

The keys in the vectors are the published BIP-340 test keys, never real keys.
