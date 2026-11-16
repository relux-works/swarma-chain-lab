# Regtest only: private VM installation pack

**Regtest only. The binding exists only on the VM's private regtest chain.
No mainnet name binding; nothing is published. The public key is recorded in
the private installation receipt only, never in published evidence.** The
required VM-local name value necessarily contains the key; no external name
binding, response, receipt, wallet or node-state publication is authorized.

This directory is a reviewable **installation pack**, not an installer to run
on a development host. It supplies no private key, seed or password. Only the
authorized target operator generates the retained key on the VM; keygen's sole
stdout line goes directly to the protected receipt. Producers install nothing,
start nothing, and run only offline checks.

Read [INSTALL.md](INSTALL.md) completely before an approved target operation,
including every check/abort point, [accounts.md](accounts.md) for custody, and
[ROLLBACK.md](ROLLBACK.md) for default KEEP rollback. The required isolated
release verifier is chain-lab PR #152 at immutable head
`c96392594f5296bf546e9e63da1bf6db6c92bc6b` once landed and accepted. Until
then installation is gated; clean-directory, `python3 -I` and cleared Git
configuration/environment precautions remain mandatory, not a replacement
for that verifier.

## Bounded smoke acceptance

The target-only [smoke.py](smoke.py) uses the installed node/service, never a
second test daemon or injected name source. Its [binding template](smoke-binding.json)
names the shipped policy's `id/certifier` and exact canonical
`{"swarma":{"notary":{"attest":"<receipt-public-key>"}}}` value. The reviewed
[commissioning.conf](commissioning.conf) temporarily permits a throwaway local
wallet, without changing loopback/no-peer/sandbox settings. The operator
removes this override and restores wallet-disabled production settings and
the shipped fixture policy before enablement.

The helper mines local regtest coinbase maturity, performs name_new / 12 blocks /
name_firstupdate / confirmation, and builds a fresh pair-bound strict D8 Grant
v3 `/2` depth-1 request. It submits one positive request, independently checks
HTTP 200 / ATTEST, BIP-340 and the exact 72-byte anchor frame, then removes the
same name's authority binding with `{}` and confirms the adjacent exact HTTP
422 / `NOTARY_KEY` refusal with no signed fields. It restores the local binding
without a second positive request. Both outcomes go into the private receipt;
responses and the public key are never printed by the helper. No anchor is
broadcast. Issuance, seal and checkpoint locators remain synthetic; this is
not live-admission qualification or authenticated D8 owner provisioning.

## Offline checks (disposable environment, no node or host installation)

From `experiments/notary-checker`, with Go 1.26.10 and already cached modules:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -timeout 120s ./...
python3 -I deploy/notary1/test-smoke.py
```

Existing config/policy/custody and systemd unit tests are retained unchanged.
New pack tests invoke the service's actual checker/name parser with the smoke
value and adjacent negatives, test the Python helper entirely offline, and
verify both production and temporary commissioning unit forms under a private
offline systemd root. No fixture executable or service is started. The normal
notary-checker hosted workflow discovers the new Go package/tests on the next
submitted head; local results do not claim a hosted-CI run.
