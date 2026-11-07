# Finite T1 + T1b source, pending whole-source review

This composition preserves the current grantee ownership-lineage repair and the
closed-regtest runner. Component reviews do not accept the composition. This
source preparation executes no node, wallet, address/key creation, signature,
grant publication or transaction broadcast. The old `lab.py --network main`
still refuses before RPC. The new modules have no CLI, credential discovery,
HTTP client, wallet loader, node startup, mining, manual relay or retry path.

`mainnet.Collector` supplies finite transaction collection and `mainnet_t1.Workflow`
supplies the exact experiment. An independent admitted launcher must provide
separate RPC capabilities, an authenticated admission verifier, durable public
journal, immutable clocks and a separately authorized peer observer. These are
required external integrations, not source preparation's runtime authorization.
Python allowlists are defense in depth; Core whitelists and process/mount
isolation must independently enforce the same separation. The verifier retains
the original narrower read-only method set and receives no signing capability.

Before any future use:

1. Obtain fresh independent review and a new Meta source marker for this whole
   exact head/tree, including the collector, workflow, changed fixtures and plan.
   Revalidate the complete closed-regtest experiment after the shared-builder
   extraction; historical component receipts do not attest this new source.
2. Separately admit the experimental seeded node at tip. Compare current tip and
   headers with approved public peers; record bounded `verifychain` results,
   seed provenance and gaps. Owner-seeded chain state is not validation from
   genesis. This source neither reads the seed nor opens any existing node.
3. **Only after review and node readiness**, admit creation of NEW local
   experimental wallets A and B and their legacy addresses/keys in a private
   node namespace. Never read, mount, import, list or reuse an owner wallet,
   owner key, prior wallet, host-home key, cookie or credential. The separate
   bootstrap launcher creates only these new wallets and supplies exact wallet
   bindings and public addresses/keys/random reservation salts. It is not shipped
   or executed here. Confirm the newly created wallets/signers are usable with
   the pinned Core; an unqualified wallet backend is a stop, not an upgrade.
4. Recompute the smallest required funding with fresh policy and estimator,
   exact selected inputs, signed sizes, output values, funding-transfer fee,
   locked names/seals, margin and reserve. Return that amount and the NEW
   experimental A address to the funder. Only he transfers funds. Wait for its
   confirmed UTXO. Never request the entire cap just because it is available.
5. The superseding spend GO is **a total maximum of 1 NMC for T1 plus T1b**.
   The model **0.06966200 NMC** is conditional arithmetic, not an actual live
   estimate or a requirement to spend that sum. It includes 0.02000000 locked
   names, 0.00200000 initial seals, 0.00708000 T1 fee caps, 0.03488000 T1b fee
   caps, 0.00046000 funding-transfer fee cap, 0.00424200 fee margin and 0.00100000
   spendable reserve. The 200 sat/vB assumption is not an estimator quote.
   The runtime admission binds a freshly recomputed minimum, not larger than
   this reviewed model, and source ceilings never increase automatically. If
   the model ceases to fit, stop and get a new calculation/review/admission.
6. Configure independent Core-whitelisted observation, construction, new-wallet
   signing and single-send broadcast roles. Construction uses raw APIs only;
   wallet `sendtoaddress`, `name_new`, `name_firstupdate`, `name_update` and queue
   helpers are prohibited because they can broadcast before raw-byte admission.
   No key export/import, wallet discovery, node control, policy changes, peer
   management, generation or automatic transaction queue is available.
7. Consume a unique runtime admission durably, with original start and UTC plus
   monotonic deadlines, transport timeouts <=10 s, 2100 RPC-call bound and a
   public journal <=24 MiB. The launcher must reject reused admissions and any
   attempt to resume a run with a broadcast attempt in its journal. Namespace
   isolation, RPC transport and admission authentication remain launcher duties.
   There is no dynamic environment flag that grants runtime admission here.

The source operation order is fixed:

`fund_B`, A/B reservations, A/B firstupdates after both reservations have 12
actual active-chain confirmations, A seal and A-to-B anchor, B seal and B-to-A
anchor, A seal revoke; then, only after core controls pass, exactly one synthetic
OP_RETURN transaction each for **80, 100, 200, 520, 1000, 4000, 10000** bytes.
The extra transfer/return regression transactions are closed-regtest controls;
they are not extra mainnet operations. Grant/request formats and domains remain
the existing experiment's; no platform grant format or product contact scheme
is introduced. Protocol contact is on chain. Optional client offchain contact
has no chain evidence and cannot be recovered by other clients.

Raw construction reuses `transaction.build_signed`, with fixed operation size
and fee ceilings. Explicit inputs/outputs/name values, funding input count,
wallet-owned change, reservation commitment and nonce are checked again after
signing. Seal revocation uses only its locked selected input and exact 50000-sat
fee; normal funding must not consume the other live seal. Before **each** send,
the authenticated Meta gate must inspect the exact raw hex, all name values,
payload, inputs/change, signed size/weight, fee, source and policy snapshot.
Any change, including size, name, payload, change or fee, needs another admission.
The same immutable raw bytes are journaled before the single broadcast call.
An RPC error is ambiguous and terminal. There is no rebroadcast, replacement,
double spend, standardness change or direct miner/peer bypass.

Local `testmempoolaccept` refusal/unknown stops before send. Local mempool and
successful send are recorded separately from remote peer acceptance. The remote
observer must produce authenticated exact txid/raw-hash evidence of its mempool
or block observation; outgoing inv/getdata and local presence do not qualify.
Unknown or refused peer evidence, timeout, missing exact-byte inclusion or a
relevant reorg stop the run before the next operation/size. Inclusion requires
the exact raw bytes in the active block, and records header/time/height/hash,
fee/vsize/weight, coinbase and available AuxPoW. Coinbase labels and AuxPoW do not
establish authenticated miner identity. Missing attribution stays UNKNOWN.

The source uses 60 seconds for transaction preparation/admission, <=120 for peer
evidence and <=1320 for inclusion, with a 1500-second operation bound. T1b has a
10500-second series bound; the original T1+T1b clock is <=21600 seconds. Maturity
and expiry observation each have finite 7200-second sub-bounds inside that same
clock. Waiting never restarts a clock. A slow Meta decision or chain stops safely.
The request and byte limits may stop earlier than wall limits. Tip checks retain
all prior inclusion anchors; any observed rollback/changed ancestor refuses.
ABA/post-read races and single-node trust are retained limitations, not solved
by this collector. No automatic reorg recovery or resumption is implemented.

T1 controls require valid mutual requests, genuine wrong-key/wrong-scope and
tampered-grant refusal, actual mempool seal-spend suspension, one-block refusal,
the unaffected reverse grant and expiry boundary observations. If the mempool
phase or exact pre-expiry height is missed, the source stops instead of claiming
that it observed it. First block finality is the experimental policy and remains
reversible by reorg. Multi-use requests still have no replay ledger.

All source tests here use explicitly synthetic in-memory RPC controls. They
open no socket, use no wallet/key and do not attest any mainnet/Core behavior.
The raw naming API schema is checked against the pinned upstream Core 28 source
(`src/rpc/names.cpp`, release `nc28.0`); this is documentation evidence, not a
new executed dependency. Python execution uses only its standard library.
