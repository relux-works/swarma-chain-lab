# Rule and case map

This map was specified before implementation in the producer report, then
bound to the tests below. The normative input for this experiment is the pinned
**Draft** [LIP-0028 v0.1.49](https://github.com/relux-works/swarma-link-spec/blob/v0.1.49/lips/LIP-0028-sessions.md).
Every T-rule remains **proposed**. Where a row carries J13, that decision has
one owner's acceptance and awaits the co-author; the additional rule is still
a proposal. No row is an adopted v4 profile.

## Decision parts

| J13 part | State | Mapping |
| --- | --- | --- |
| 1 client cannot sign; service admits session | decided, co-author pending | explicit Draft gate; T1.1 |
| 2 origin/use table; signed open states path, executor, slot, window, limits | decided, co-author pending | external key-holder gate; T2.1–T2.5; K3 bounds visibility |
| 3 service verification including comparison observation; random 32-octet bearer bound in journal | decided, co-author pending | verified facts; DrawToken; T3.1–T3.4; actual journal excluded |
| 4 uid or network address slot | decided, co-author pending | T6.1–T6.3; verified connection facts |
| 5 stable bearer; signed one-hour extensions | decided, co-author pending | T5.1–T5.3; relative-to-now reading is proposed |
| 6 end sessions when grant seal is observed spent | decided, co-author pending | T5.6; validated closure and ancestor handling proposed |
| 7 harness gets base URL and token only | decided, co-author pending | actual harness handoff excluded; token response modeled |
| 8 same grant authority as per-request signature; signed profile remains possible | decided, co-author pending | T4.5–T4.6; K1–K4 expose copied-bearer/origin/address limitations |

## Every T-rule

Vector names below are subtests of `TestVectors` and independent Python
scenarios. A row with several assertions has both accepted and refused adjacent
controls. Named `Test…` entries are direct Go tests. T7 rules belong to the key
holder, which §7 explicitly says the service cannot observe; they have **no
service positive/negative enforcement test**. Their observed limits are tested
without inventing an origin/run flag. This is the declared out-of-contract
boundary of row 1, not coverage of the excluded signer implementation.

The `write-commit-order`, `write-reserve-boundary` and
`write-observation-boundary` references below cite the fixtures landed in
[PR #135](https://github.com/relux-works/swarma-chain-lab/pull/135), present on
main `5d8352824661c8096f0c7da2e11763e1eb205c42` in `testdata/lifecycle.json`.
This follow-up adds citations only; the reducer and those fixtures are unchanged.

| Rule | Function / fact boundary | Positive evidence | Negative / boundary evidence | Status detail / limit |
| --- | --- | --- | --- | --- |
| T1.1 | Apply/gate | S13-1 | profile-zero; profile-all-entries | J13.1; type commands proposed |
| T1.2 | Apply/open; path/executor lookup | S13-1 | S13-14; S13-22 | J13.2–4 |
| T1.3 | CheckUse/verify | S13-K1 | S13-6; S13-10 | signed-command restriction proposed |
| T2.1 | verify signed facts | S13-1 | fact-recipient; invocation-time | J13.2; invocation form proposed |
| T2.2 | Apply/open record | S13-1 | S13-5; S13-14 | J13.2; no encoding |
| T2.3 | validWindow | S13-1; window-integer-boundary | S13-3; window-overflow-reject | proposal 2: end relative to now |
| T2.4 | validLimits | S13-1; operator-ceiling | S13-4; limit-kinds; operator-ceiling | grant/zero J13.2; operator/unique proposed |
| T2.5 | verify | S13-1 | S13-6; missing-facts; fact-path | J13.3; command allowance proposed |
| T2.6 | replay; seen identities | S13-1; S13-21 | S13-2; extend-replay | replay proposal |
| T2.7 | validBinding | S13-1; binding-address | S13-5; binding-address | J13.4; canonical-IP interpretation |
| T3.1 | DrawToken; Apply/open | S13-1; TestTokenCustody | entropy-failure | J13.3; random source is a fact in reducer |
| T3.2 | Apply/open; record | S13-1; TestTokenCustody | write-failure; entropy-failure; write-commit-order; write-reserve-boundary; write-observation-boundary | J13.3; hash-only storage proposed |
| T3.3 | Apply/open; Result | S13-1 | S13-2; S13-23; write-failure; write-commit-order; write-reserve-boundary; write-observation-boundary | one reply/hash proposal; protected channel proposed |
| T3.4 | tokenDigest; CheckUse | S13-7 | S13-8 | hash lookup proposed |
| T3.5 | replay; abstract restart | lost-opening-reply | S13-2; lost-opening-reply | no lost-answer replay proposed |
| T4.1 | CheckUse | S13-7 | S13-8; S13-23 | unsigned bearer J13; channel/lookup proposed |
| T4.2 | peerMatches | S13-7; S13-K4 | S13-7; peer-provenance | J13.4; collection excluded |
| T4.3 | live; Reserve | S13-9 before end | S13-9; final-expiry-plus-one | window J13.5; final end proposed |
| T4.4 | CheckUse action class | S13-7 | S13-10 | signed commands only proposed |
| T4.5 | verify; Reserve boundary | S13-16; S13-18 after extension | S13-16; S13-18; final-boundary; final-clock-rollback | proof/key recheck proposed; verified facts only |
| T4.6 | Reserve; fits | S13-17; row-account; unsigned-retry | S13-17; two-key-atomic; counter-overflow; S13-24 | session accounts/atomic end reads proposed |
| T4.7 | ordered CheckUse/Reserve | S13-7 | order-use; consumption-order; two-key-atomic | ordered first refusal proposed |
| T5.1 | digest unchanged on extend | S13-11; TestTokenCustody | S13-2; entropy-failure | J13.5; token cannot be reminted for retry |
| T5.2 | Apply/extend; max end | S13-11; S13-12; S13-18 | window-extension; S13-13; write-failure | J13.5; relative window/no shortening proposed |
| T5.3 | path/executor lookup; live | S13-11 | S13-13; S13-14; unknown-session | lookup/live requirement proposed |
| T5.4 | live; close; recordClosure | S13-19; S13-15 | S13-13; checked-close; S13-24 | final end proposed |
| T5.5 | Apply/close | S13-19 | order-close; write-failure | signed/idempotent close proposed |
| T5.6 | recordClosure; Reserve | S13-15; ancestor-closure | S13-24; unvalidated-spend; unvalidated-observation | J13.6; any ancestor/validated record proposed |
| T5.7 | verify refusal preserves live state | S13-16 after recovery | S13-16; fact-names; unvalidated-spend | no-closure refusal does not end proposed |
| T5.8 | Lost; StartAnew; replay | S13-20 intact; S13-21 new signature | S13-20 new journal; S13-21 fence; journal-unavailable | recovery/fence proposed; actual recovery excluded |
| T6.1 | validBinding | S13-1; S13-K4 | S13-5; binding-address | J13.4; strict address interpretation |
| T6.2 | peerMatches verified local fact | S13-7; S13-K2 | S13-7; peer-provenance | J13.4; no socket collection |
| T6.3 | peerMatches verified address fact | S13-K4 | S13-K4 different address; binding-address | J13.4; no socket collection |
| T6.4 | secure | S13-1; S13-K4 | S13-23; order-use | protected-channel proposal |
| T7.1 | external key-holder origin/use gate | S13-K1/K3 show service admission | S13-6 bounds action; K3 shows origin failure is invisible | external; no service enforcement claim |
| T7.2 | external key-holder construction/slot record | S13-K3 illustrates same-slot acceptance | peer-provenance rejects unverified peer facts, not origin | external; no signer implemented |
| T7.3 | external harness handoff; Token redaction | TestTokenCustody; S13-K2 | S13-2; S13-23; K2 other uid | handoff external; bearer limitations explicit |
| T7.4 | external one-run-one-session rule | S13-15 separate sessions | S13-K2/K3 show receiver cannot distinguish copied tokens | external; no run identity invented |
| T7.5 | external signer-clock bound | S13-1 illustrates service bound only | S13-3 checks service clock only | external signer clock not supplied or inferred |
| T7.6 | external run-lifetime extension/close rule | S13-11; S13-19 model requested effects | S13-13 forbids late reopening | external run liveness not observed |
| T7.7 | external single-origin-per-slot rule | S13-K1/K2 same-slot authority | S13-K3/K4 deliberately accept indistinguishable copies | external; known limitation, not rejected origin |
| T8.1 | Apply/open pipeline | S13-1 | order-open; write-commit-order; write-reserve-boundary; write-observation-boundary | proposal; channel before upstream checks |
| T8.2 | Apply/extend/close pipelines | S13-11; S13-19 | order-extend; order-close | proposal; close has no ended/window check |
| T8.3 | CheckUse/Reserve pipeline | S13-7 | order-use; consumption-order; write-commit-order; write-reserve-boundary; write-observation-boundary | proposal; channel precedes token |
| T8.4 | no session refusal creates closure | S13-16 live recovery | unvalidated-spend; unvalidated-observation | proposal; separate validated closure fact required |

## §8 vocabulary and pipelines

`TestProfileGate` pins the printed order of all eleven codes:
`SESSION_CHANNEL`, `SESSION_REPLAY`, `SESSION_BINDING`, `SESSION_WINDOW`,
`SESSION_LIMITS`, `SESSION_UNKNOWN`, `SESSION_TOKEN`, `SESSION_PEER`,
`SESSION_ENDED`, `SESSION_COMMAND`, `SESSION_LIMIT_OVER`.

The `order-open`, `order-extend`, `order-close` and `order-use` compound
scenarios pin the distinct T8.1–T8.3 pipelines, including upstream refusals
between session checks. `consumption-order` checks that accounts are considered
per key, with own/row before session. `S13-24` binds the current ended-before-
closed order at the atomic boundary. `TestCaseAndRuleCoverage` rejects missing
§9 case IDs and missing service T-rule vector references.

## Every §9 case

These are logical facts with expected outcomes derived from the pinned text;
they are not protocol invocation vectors. Every case runs in both readers.

| Case / test | Claim |
| --- | --- |
| S13-1 | Exactly one hour opens one session and returns one token after the write. |
| S13-2 | Repeating an admitted open, including after its reply is lost, never mints or returns a token. |
| S13-3 | An open end at now or now plus 3601 is rejected; no session exists. |
| S13-4 | Grant+1, absent grant key and duplicate requested limit keys all reject. |
| S13-5 | A third binding form rejects before a valid uid binding opens. |
| S13-6 | Model-action authority alone supplies no open-command authority. |
| S13-7 | A different uid refuses without charging; the bound uid succeeds. |
| S13-8 | Unknown 32-octet token refuses, while the minted token succeeds. |
| S13-9 | The second before expiry admits; expiry itself records a final end. |
| S13-10 | A token cannot open, extend or close a session. |
| S13-11 | An extension at +1800 accepts a new end exactly 3600 ahead with the same token. |
| S13-12 | A shorter but future proposed end never moves the current end back. |
| S13-13 | An extension at expiry cannot resurrect; later clock rollback cannot reopen it. |
| S13-14 | A different proof path or executor does not identify the session. |
| S13-15 | A discovered validated closure ends all sessions of the grant and leaves another grant untouched. |
| S13-16 | Stale observation refuses without ending or debiting, then a healthy observation succeeds. |
| S13-17 | Session exhaustion and grant exhaustion refuse atomically with their respective codes. |
| S13-18 | A changed recipient key refuses until a signed extension updates the last authenticated key. |
| S13-19 | Close records a final end; another close is harmless, while the same close identity replays. |
| S13-20 | An intact restart retains token and accounting; starting anew loses the token. |
| S13-21 | Recovery fences iat at equality and below, while a freshly signed open after the fence succeeds. |
| S13-22 | A different executor journal knows no token and refuses an invocation naming the first executor. |
| S13-23 | An unprotected channel rejects both open and token requests before later defects. |
| S13-24 | A closure between checks and the atomic reservation prevents any debit by the checked request. |
| S13-K1 | A bearer holder in the slot can consume all allowed session authority, and no more. |
| S13-K2 | A copied token from the same uid works; a different uid fails. |
| S13-K3 | The service cannot distinguish origins behind one uid; the external key-holder origin gate remains necessary. |
| S13-K4 | Same-address peers, including shared translation, are indistinguishable; a different address fails. |

## Prerequisites and excluded rows

- LIP-0008 §§2/4/5/5.1/12: ordered verified name, recipient, observation,
  path/action/executor and resource facts; signed invocation times; permanent
  closure only from validated issuer-spend facts. No signature or chain code.
- LIP-0013 §3.6 and LIP-0028 §7: the origin/use table, caller/run construction,
  token handoff and single-origin slot remain external, as J7.7 requires.
- LIP-0006 §§1/4: verified connection uid facts; no replayed token receipt.
- LIP-0007 §1 and LIP-0020: logical operation classes, no assigned command
  spellings, invocation schema or serialized signed bytes.
- LIP-0022 §§1–3: healthy/final observation and clock facts. This package
  does not calculate health, tip age, name reads or comparison-node agreement.
- LIP-0025 §§3–5: completed abstract write and intact/lost/fenced recovery facts;
  no entry form, durable commit, outside record or rollback proof.
- LIP-0026 §5: own and optional row accounts before session, per key; atomic
  debit, single service request identity and nondecreasing exposure.

The assignment supplies no formal surface table. This rule map is the explicit
coverage artifact for its stated lifecycle scope; it claims no integration,
cryptography, persistence or deployment coverage. No previous reviewer tests
exist in this newly introduced package. Existing proxy tests are preserved.
