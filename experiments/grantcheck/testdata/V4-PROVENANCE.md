# Grant v4 fixture provenance

`grant-v4.json` is unchanged from `swarma-link-spec` 0.1.53, commit
`3bef542fc8c0a5dedeeaaa990bd7f93abe194813`,
[vectors/LIP-0020/grant-v4.json](https://github.com/relux-works/swarma-link-spec/blob/3bef542fc8c0a5dedeeaaa990bd7f93abe194813/vectors/LIP-0020/grant-v4.json).
SHA-256: `66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106`.

`b4a-grant-v4.json` is the B4a issuer's exported encoding corpus at
`swarma-identity` commit `e7c68ce46be00fb0a03f6c1edf2e02d04ca92fc9`.
SHA-256: `227c20bc5017d67b7d87384e7e3559db4b736affeb481e682bd264639b577b28`.
It is generated from that exact clean source with Go 1.26.10:

```sh
GOTOOLCHAIN=local GRANTV4_OUTPUT=/absolute/task-scratch/b4a-grant-v4.json \
  go test -count=1 -run '^TestVectors$' ./internal/grantv4
```

The [export implementation](https://github.com/relux-works/swarma-identity/blob/e7c68ce46be00fb0a03f6c1edf2e02d04ca92fc9/internal/grantv4/grant_test.go)
independently drafts and attaches the signature for all 11 valid vectors.
It retains the 84 invalid, 13 compound and four undetermined rows as corpus
inputs; the differential does not claim the issuer produces those grants.

Both files are derived from public specification test data licensed under
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
The [upstream copyright notice and creator credits](https://github.com/relux-works/swarma-link-spec/blob/3bef542fc8c0a5dedeeaaa990bd7f93abe194813/LICENSE.md)
remain attributed to that exact revision. The repository's Apache-2.0 license
does not relicense these fixtures. No endorsement is implied. All keys are
published synthetic fixture material; these bytes establish no live authority.
