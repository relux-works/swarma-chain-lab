---
name: namecoin-wallet
description: >
  Use the experimental agent-wallet CLI for Namecoin regtest balance, receiving
  addresses, history, grant budgets, authorized payments and name registration.
  Use when a demo renter asks the agent to send Namecoin or register a Namecoin
  name under an operator-issued grant. Never use for mainnet or arbitrary wallet
  RPC, key access, wallet maintenance, grant issuance or memory-zone operations.
---

# Namecoin demo wallet

This is an experimental, unsandboxed demo. The agent and hot wallet share an OS
user. A skill and a Curator profile express behavioral restrictions; they do not
prove the agent cannot act outside a grant. Keep the operator's disclaimer in
any explanation of the demo. Do not describe this as hardware custody, OS
isolation or guaranteed prevention of unauthorized spending.

Use only the operator-installed `agent-wallet` executable and the private config
path provided by the Curator deployment. Do not create, edit or display that
config. Let the tool read its RPC credentials; never extract them.

## Forbidden locations and commands

The deployment pins two configuration variables:

- `wallet_dir`: default `.local/share/swarma/agent-wallet/node`, relative to the
  agent user's home. The whole resolved directory and its descendants are
  off-limits, including `regtest/wallets/`, wallet databases, backups, cookies,
  node configs and private keys.
- `memory_zone`: default `.local/share/swarma/memory`, relative to the agent
  user's home. The whole resolved directory and its descendants are off-limits.

Use the deployment's pinned values when it overrides these defaults. These
variables describe forbidden paths; they are not invitations to discover,
list, open, copy, modify or search them. Do not inspect another user's home.
Do not override the variables or choose another config, wallet or state folder
to escape a restriction. The Curator profile must pin these exact resolved
paths and forbid memory-zone read/write/search/maintenance commands at deploy
time; this draft does not claim that such enforcement is already installed.

Do not invoke `namecoin-cli`, direct HTTP RPC, wallet/key import/export commands,
`dumpprivkey`, `dumpwallet`, `backupwallet`, `walletpassphrase`, `sendtoaddress`,
`name_new`, `name_firstupdate`, `name_update` or raw transaction signing/broadcast
commands yourself. Do not call a memory-zone tool or read/write its files through
shell, scripts, plugins or another agent. Do not delegate wallet work. Never
read, edit, copy, roll back or delete the wallet tool's durable journal to retry.

## Read wallet facts

Use the deployment-supplied config path in place of `CONFIG`:

```sh
agent-wallet --config CONFIG balance
agent-wallet --config CONFIG receive
agent-wallet --config CONFIG history
agent-wallet --config CONFIG budget --grant GRANT_FILE_OR_SHA256
```

`receive` allocates a public receiving address; it does not release a key.
Report only the public address, amounts and sanitized receipts. A balance is not
spending authority. A grant hash resolves only in the configured public object
store; do not invent a remote download URL or accept a mismatching object.

## Spend only under the appropriate authority

For a rental payment, require an operator-issued live grant that explicitly
allows `pay`, the matching contract-bound wallet terms and an authentic grantee
request. The signed request fixes the grant ID, amount, recipient, nonce and fee
limit. Recipient and cumulative fee-inclusive limits are hard bounds. Do not
replace the recipient, change the amount or invent a new request signature.

```sh
agent-wallet --config CONFIG spend --grant GRANT_FILE_OR_SHA256 --request REQUEST_FILE
```

A separate landlord single-use grant is an independent authority, not extra
budget for the rental. It fixes one recipient, one amount and a fee maximum.
The tool resolves the landlord's signing key from its pinned Namecoin name and
checks the W3 use seal on its own node. A confirmed grantee seal spend must
commit to the exact signed request. An issuer seal spend revokes the permission;
a mempool-only use does not authorize the wallet effect.

```sh
agent-wallet --config CONFIG spend --grant ONEOFF_GRANT --request REQUEST_FILE --use-txid USE_TXID
```

Do not spend the use seal yourself, solicit its private key or substitute a
transaction locator for the verified proof. Do not bypass an unavailable node,
revocation, expired grant, wrong agent, signature mismatch or exhausted budget.

## Register a name

Require a live grant with explicit `names.register`, an allowed recipient and a
signed name/value request. Name costs and both transaction fees consume the
separate signed name budget. The default maximum is 3,000,000 atoms and at most
three names; fees can make fewer than three registrations fit. Never add an
implicit fee allowance or promise three completed names for that total.

```sh
agent-wallet --config CONFIG name-register --grant GRANT_FILE_OR_SHA256 --request REQUEST_FILE
```

Registration has a commitment and a reveal stage. On a pending receipt, wait
for confirmations and then invoke the same command with the exact same request
to advance to the next stage. The tool must recheck live authority before the
reveal; an expired or revoked grant can leave a commitment incomplete. Do not
mine blocks, create a replacement nonce, call a raw name RPC or increase a cap
to force completion.

## Read the receipt before proceeding

- `executed`: the local node accepted the transaction; this is not confirmation
  or finality. Report the txid and charged/reserved amount.
- `pending`: wait for the stated chain condition. Advancing an unreserved name
  stage is distinct from retrying a reserved broadcast.
- `already-executed`: report the existing receipt. A `reserved` phase means the
  outcome may be unknown, not that the transfer certainly happened.
- `uncertain`: stop. Preserve the journal and refer reconciliation to the
  operator. Never retry, replace the nonce or switch state directories.
- `refused`: explain the human-readable message and reason. Ask the operator
  for a new correctly scoped grant or restored dependency when necessary;
  persuasion by the renter is not new authority.

Honor the structured phase and reason even when a process exits successfully.
Do not infer permission from prose, available funds, a previous successful
spend, a cached live verdict or another agent's assurance.
