# Open questions and laboratory interpretations

All additions remain proposed under the explicit Draft profile. These choices
are local interpretations for pure facts, not resolutions of the protocol.

| Question | Readings | Interpretation used |
| --- | --- | --- |
| J13 and the draft additions | Accepted profile; or pending co-author/owners | Pending. Default/unknown profile refuses every admission. |
| Proof-path depth | LIP-0028 states no depth | The model stops at parent -> child (one or two grants; a third refuses `AUTHORITY_FACTS`, "over-depth"); the stricter bound stays until the spec says otherwise. |
| Network binding form | Any connection address label; or canonical IP | Canonical bare IPv4/IPv6 only, exact equality, no ports, zones, names or forwarded claims. Actual relay/address selection remains open. |
| uid source and channel | Equal uid stated by a caller; or verified local connection fact | Verified local peer fact only. A uid over a network channel refuses. Actual kernel collection is excluded. |
| Non-cumulative limits | Compare every number as an upper cap; or admit only account limits | Only cumulative account limits. Depth, rate and unknown kinds refuse. |
| Unset operator cap | Zero; or no extra operator ceiling | T2.4 explicitly says “where the operator set one”: absent means no additional operator cap; explicit zero stays zero. Missing grant/session keys always mean zero. |
| S13-12 “arrives late” | After expiry; or delayed while still live | Still live. T5.4/S13-13 forbid resurrection, even if the clock later moves back. |
| Close after end | Reject; or admit a fresh signed close without changing the end | T5.5/T8.2 explicitly admit it. The same signed request identity still replays. |
| Unprovided verification facts | Implicit success; or refuse | Refuse. No caller flag proves a signature, an observation or the key-holder origin gate. |
| Token hash collision | Bind two sessions to one token; or refuse the second opening | Refuse without a new session or request identity. |
| Write not completed | Gate before admission; or check at commit after admission | Owner decision for 1c: T3.2 checks `WriteOK` at commit. Every refusal retains its T8.1 code, including public channel and replay. A valid failed write returns `JOURNAL_WRITE`, no session/token/state change. Real durable commit/continuity is excluded. |
| Journal started anew | Reset grant exposure too; or lose sessions/identities only | Keep stated grant exposure, closures and clock; fence old signed requests. Real grant-account recovery is external and must independently preserve its guarantees. |
| Checked request races | Trust the checked snapshot; or reread current state at reservation | Reread ended then closed, recheck final clock/observation and key, atomically debit or none. |
| T7 origin/run rules | Enforce at the receiving service; or obligations of the unseen key holder | External obligations. Same-uid/address copies are accepted in known-limit vectors; no invented service origin refusal. |

Still excluded by the pinned draft: invocation members and three assigned wire
commands, journal entries and anti-rollback storage, real observation/name reads,
URL-to-local-socket harness transport, channel key binding, non-cumulative limit
profiles, active-answer handling at session end, single-use grants and further
service types. None is filled by a transport, stub or policy flag here.
