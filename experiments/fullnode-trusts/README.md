# Mutual grants on a real closed Namecoin regtest

The composition also contains [finite T1/T1b mainnet collector source](MAINNET_SOURCE.md).
It requires new whole-source review and separate runtime admission. The closed
regtest runner below remains mainnet-disabled. A superseding experimental spend
GO caps total T1+T1b at 1 NMC from a new owner-funded experimental address; the
conditional 0.06966200-NMC model is not a live estimate or permission to fill the cap.

**LAB — experimental, requiring independent review.** This is a small working
full-node experiment, using Namecoin Core 28.0. It registers two disposable
synthetic `d/` names, signs A-to-B and B-to-A grant files, anchors each grant's
canonical SHA-256 in a name update and an OP_RETURN output, and checks signed
requests against the fully validating node. Each grant points to a previously
confirmed issuer-owned seal output. Spending that output revokes the grant.
There is no Electrum server, SPV adapter or synthetic consensus substitute.

The grant object, canonical JSON encoding, `synthetic-notarized-grant-v1` schema,
`notary-lab/grant-v1:` signature domain and same-owner lineage walk are reused
from [the notary lab](../notary/README.md). The request's fields and
`swarma-chain-lab/request-v0` domain are reused from the preceding chain-backed
grant prototype. This driver uses the grantee's existing Core `signmessage`
signature, over `swarma-chain-lab/request-v0:` plus the canonical request hash,
instead of that prototype's optional Ed25519 adapter. Grant signatures likewise
use Core's existing secp256k1 message signatures. This is a lab wire convention,
not a new platform grant format or an implementation of platform grant/1.
Grant files are exact canonical UTF-8 JSON without a trailing newline. Their
SHA-256 equals the commitment in both the name value and transaction output.

`protocol.py` implements the checks. `verify.py` is the small file-based client:
it takes a grant fixture, signed request and independently supplied identity
pins, and prints an `admit` or `refuse` JSON result. A fixture wraps the unchanged
grant, its issuer signature and the anchor's txid/block/height. Pins identify
both original firstupdate transactions, names, addresses and public keys; grant
contents are never allowed to supply their own trust pins.

The current grantee name output must descend from its pinned firstupdate through
confirmed updates under the same owner. A current firstupdate is also allowed.
The walk bounds 128 transitions and 16 inputs per transaction and refuses on
missing RPC evidence or exhausted bounds. It allows ordinary value changes,
including the grantee's own current grant update. Returning to the pinned address
after a transfer does not restore ownership continuity, even when the original
signing key still signs the request. A new registration with that same key is
also a different generation.

The real regtest driver and any future admitted full-node run use these same
grant, transaction, signature and verification functions. The verifier supports
fixed regtest/mainnet genesis pins. The transaction driver deliberately refuses
mainnet before RPC, wallet or address creation. Enabling a future mainnet driver
requires a reviewed source change and the separate operational gates below.
No claimed mainnet run, fee quote, funding address or node synchronization
measurement is supplied by this experiment.

## Isolation and invocation

Use only a separately verified Core 28.0 `namecoind` binary. The executable
SHA-256 is
`dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7`.
The official `namecoin-28.0-x86_64-linux-gnu.tar.gz` archive SHA-256 is
`6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860`.
Verify the release checksum signature using its pinned release signing key,
fingerprint `FD8366A807A99FA27FD9CCEA9FE3BFDDA6C53495`, then verify the archive
and extracted executable. No runtime binary or wallet is included in this tree.
Python uses only its standard library; there are no Go modules, h1 dependencies,
downloaded Python packages or upgrades.

`run.sh` and `runner.py` only launch namespaces and relay public pipe messages.
They read no host home, credential, wallet or cache, and open no network socket.
Protocol code, signing, node execution and verification run inside separate
`bwrap --unshare-all --clearenv` sandboxes with read-only source/tools,
empty host-home views, dropped capabilities and private mode-0700 absolute
HOME/TMP/cache paths. The node namespace has only its own loopback network.
The verifier namespace has neither a network route to the node nor wallet,
node-data, cookie or credential mounts. Its only full-node capability is a
dedicated stdio pipe carrying the explicit read-method allowlist.

The node-side broker additionally authenticates with a separate Core observer
login, restricted by Core's RPC whitelist. Client, broker and node all reject
signing, wallet creation and broadcast methods. The run demonstrates both
client rejection before pipe traffic and Core HTTP 403 responses to actual
observer write attempts. No authentication bytes cross the public pipe.
The optional file client requires an observer-only capability file and a
separate empty-home sandbox; never give it a signer cookie or wallet mount.

Run only within an admitted window, under a dedicated user-service cgroup.
For example, with an absolute Unix deadline leaving time for export:

```sh
systemd-run --user --unit=closed-trust-lab --wait --pipe --collect \
  -p MemoryMax=3221225472 -p MemorySwapMax=0 -p CPUQuota=200% \
  -p TasksMax=64 -p RuntimeMaxSec=1600 -p KillMode=control-group \
  -p TimeoutStopSec=15 /bin/bash /absolute/checkout/experiments/fullnode-trusts/run.sh \
  /absolute/verified-core-bin ABSOLUTE_DEADLINE_UNIX regtest
```

The controller verifies actual cgroup memory/swap/CPU/task limits before
starting a child. The outer wall timeout is 1500 seconds with a 1600-second
cgroup backstop; the node's own execution limit is at most 1400 seconds and
never extends the supplied absolute deadline. Combined node/verifier tmpfs
capacity is 1536 MiB, with an earlier node stop at 1200 MiB used. Children are
reaped, and all fresh wallets and authentication material disappear with the
private namespaces. Stdout contains only an allowlisted public-document map,
decisions, timing/fee/resource evidence and exit status. Never export private
tmpfs data, configuration, cookies or node logs.

## Actual controls and costs

The driver checks name availability before either registration and bounds all
name values to 520 bytes. It generates regtest-only A/B/miner keys in private
tmpfs, mines the required name reservation maturity, and constructs both grants.
Wallet autobroadcast is disabled. Every signed transaction is checked for its
exact fee, operation-specific signed size ceiling and mempool policy before its
first explicit broadcast. Dedicated seals are locked against wallet coin
selection. There is no changed-transaction rebroadcast or replacement loop.

The controls use genuine signatures and real state:

- A grants B and B grants A; both signed requests admit.
- A signs a request meant for B; wrong-key refusal.
- B signs a request for a different action; scope refusal.
- A grant is modified without resigning; issuer-signature refusal.
- The verifier expects mainnet but receives regtest; network refusal.
- A spends its actual seal. Chain-only `gettxout` still sees it while the
  mempool-aware lookup and verifier refuse; after one mined block they refuse
  again. B's separate grant still admits.
- B's grant admits at expiry height minus one and refuses at the actual mined
  expiry height. The expired document is not manufactured by editing its term.

The lineage regression then deliberately invalidates only the empty expiry
blocks in this disposable chain, retaining both anchors and the seal spend.
This controlled test fork restores the unchanged B-to-A grant's live interval;
it is not a production reorg-recovery policy. The same request admits before
and after A changes its name value under the same owner. A then transfers its
name to B and B returns it to A, with a mined block for each transaction. Both
transfer controls refuse before the unchanged grant expires; the final one
isolates the ownership-continuity check after address and key match again.

This adds five separately capped regression transactions: two synthetic-miner
funding transactions totaling 0.00600000 NMC and three name updates. Their combined fee cap is
0.00452000 NMC, separately reported from the original ten-operation funding
snapshot; total funding plus these conservative caps remains below 0.5 NMC.
The separate regression updates allow at most 600 vbytes, including a named
input and bounded ordinary funding inputs; their receipts record the actual
signed shapes. They do not change the original funding-template ceilings.
The original snapshot's balances precede these extra controls. The new run's
public documents and receipt are in `receipts/lineage-public/` and
`receipts/lineage-result.json`; the original receipts remain historical evidence.

`python3 test_lineage.py` supplies offline synthetic RPC controls for the reviewer's
unchanged-grant transfer-away/return case, legitimate updates, the pinned current
firstupdate, unavailable RPC and exhausted bounds. A separate synthetic generation
timeline leaves more than 36000 blocks after the old generation's last update,
matures a fresh reservation, and uses a long-lived grant with a symbolic signature
oracle. It checks generation continuity independently of expiry and key continuity;
it is not a real-chain registration or cryptographic signature observation.

The [public receipt](receipts/regtest-result.json) records each actual signed
transaction's bytes, vbytes, fee, broadcast/observed-inclusion timestamps and
block. Generated local blocks make these regtest latency measurements; they are
not estimates of real mainnet latency. The synthetic miner's bootstrap funding
transaction is recorded separately from the ten budgeted lab transactions.

The conditional funding minimum under the declared transaction ceilings and a
10% fee margin is **0.02978800 NMC**: 0.02000000 in two name outputs,
0.00200000 initially in two seals, at most 0.00708000 in lab transaction fees,
and 0.00070800 fee margin. This amount is below the 0.5 NMC budget. Its assumed
rate is 0.002 NMC/kB (200 sat/vB), above the measured pinned-node minimum relay
rate of 0.001 NMC/kB. The fresh closed node has no usable fee estimator. The
rate is explicitly an assumption, not a current mainnet quote. The receipt
contains per-operation ceilings, actual fees and remaining balances. A spend
returns the seal's remainder; it does not consume its full value as a fee.
The [public fixtures](receipts/public/) include the exact canonical grant files,
issuer/request signatures, identity pins and decoded signed transactions from
that run. They contain only disposable regtest public data; their private keys
and chain state were destroyed after the run.

The original funding templates have one ordinary funding input, or one named input plus
one ordinary funding input. Ceilings allow bounded signature-length variation,
not extra inputs, longer names or a changed transaction. Funding must be
recomputed before authorization if fresh node policy or any signed size/fee
exceeds those ceilings. A future funder's own transfer fee is outside this lab
wallet's requested amount, just as the synthetic bootstrap fee is separate.

## Gates and limits

`MAINNET_BROADCAST` is false. There is no environment switch or command-line
permission flag that turns it on. `--network main` exits before creating any
wallet/address or making any RPC connection. Operational permission remains
absent until this regtest candidate passes fresh independent sol/high review,
the owner explicitly authorizes spending, and a separately admitted full node
is at tip with confirmed funds. Mainnet signer and verifier must remain
separate. No existing operational node, wallet or owner's key is used here.
Generating a mainnet wallet/address comes after review and separate admission.

A future admitted run must freshly check full-node network/genesis, tip, policy,
estimator and exact signed sizes. It must stop on a fee above the computed cap,
six hours without inclusion, or a reorg touching its transactions, and report
the unchanged transaction rather than blindly rebroadcast a modification.
This regtest driver mines immediately and stops if inclusion is not as expected;
it implements no long chain/funding wait loop or mainnet monitoring service.

This is a single trusted fully validating node, not independent synchronization
qualification. Before/after tip equality brackets all authority/liveness reads
but cannot detect an ABA tip sequence or a mempool mutation after the final
lookup. One-block refusal is final under this experimental one-block policy,
not an irreversibility claim. Requests are multi-use; their nonce is signed but
there is no replay ledger. Delegation, transfer, owner rotation and registration
generation changes are refused. The optional narrowed child was omitted.
This experiment does not qualify a production grant service or authorize any
mainnet transaction, publication or landing.

## Proposed mainnet OP_RETURN extension

[T1b plan and limits](T1B_PLAN.md) defines seven synthetic payloads, an all-in
conditional budget and a stop-first observation schedule. `t1b.py` generates
only offline serialization fixtures using the shared transaction builder.
It does not enable this driver's mainnet path or provide runtime admission.
