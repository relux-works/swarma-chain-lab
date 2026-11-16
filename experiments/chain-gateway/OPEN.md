# Questions for consumer and owner

All answers must identify the accepted contract head. These questions are not
silent defaults; proposed v1 rules remain reviewable until Source accepts them.

| ID | Decision/input needed | Owner | Gate |
| --- | --- | --- | --- |
| Q1 | Accept the protocol, SJ1 canonical profile, enums, numeric limits, base64 encoding, per-call consistency and cross-call limitations? Identify the consumer acceptance head. | Source | Both builds |
| Q2 | Accept `not_in_utxo_set` instead of the misleading `spent` requested in consumer item (3)? Does absence trigger only per-command DEVICE_REVOKED refusal, or permanent closure too? Never-created output and actual spend are indistinguishable without added evidence; a proof/watcher is outside this method set. | Source and policy owner | Enforcement; spec clarification PR |
| Q3 | Which exact node/version/read adapter can witness coherent name/UTXO/tip reads, including hidden A→B→A tip transitions and mempool-inclusive gettxout? Supply feasibility evidence; ordinary before/after RPC is insufficient. Otherwise unavailable is required. | Gateway implementer and node owner | Live build qualification; no workaround by weakening the claim |
| Q4 | Supply D29's actual accepted ChainView and snapshot schema at its exact head. Does it accept this proposed file, including full value bytes, name block hash, tip hash, watch-set and written_at? If not, agree a schema revision before helper/adapter builds. Only the brief and U2a schema were available here. | Source | Snapshot compatibility; not claimed drop-in |
| Q5 | Accept 30-second heartbeat and 60-second label thresholds, and define the consumer's live-node freshness/lag policy and independent-tip source? A getblockcount reply alone cannot detect a node lagging peers. | Source and node owner | Operational profile, observe labels and enforcement |
| Q6 | Supply protected install settings: socket/snapshot paths, exact allowed UIDs and UID retirement procedure, server/service IDs, network/genesis/node endpoint, watched names/outpoints and reader group. Review root-owned 0640 credential/exclusive service group and 0644 snapshot ancestry/ACL model. | Host owner / infrastructure | Install only; no installation in this unit |
| Q7 | Confirm root helper custody while (a) does not yet exist, serialization of helper writers, and handling of cookie rotation. Accept root helper via explicitly allow-listed UID after gateway install. | Host owner / infrastructure | Helper build/install |
| Q8 | Assign the book PR for the new chain-read service/wire/snapshot profile and spec PR for coherent observation and UTXO-absence semantics. No current book rule is overridden. | Lead and documentation/spec owners | Production adoption |
| Q9 | Confirm LIP-0010 §11 SH3/SH5/SH6 draft interpretation against LIP-0029 §3.3/§11, including confirmed-only heads, reorg rollback and permanent refusals. Draft/co-author status stays visible; gateway transports opaque bytes. | Source and policy owners | Consumer admission policy |
| Q10 | How will D29 continuously observe seal spends and persist closure outside agent write authority before enforcement? Per-command gettxout polling cannot retain an evicted, never-observed spend or prove its transaction. | Source | Enforcement qualification |

U2a filesystem rules were readable and cited, so their constraints are reused
rather than guessed. They do not establish the unprovided D29-specific schema.
Enforcing over snapshot (b) remains prohibited without a new owner decision.
