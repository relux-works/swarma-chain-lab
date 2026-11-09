# CG1 integration questions

Proposed integration defaults are in DESIGN.md. Feedback may refine:

1. Accept the precise live/refused/exchange decision table in DESIGN.md section4,
   including no exchange fallback on read errors or pending identity transitions.
2. Confirm a checker bound to the authenticated per-identity engine, with no
   per-call identity/connection/store selector, matches the settled engine seam.
3. Confirm S1 resolution supplies a full presentation (signed grant plus separate
   issuance locator), and explicit lookup failure is not represented as absence.

The task requires forwarding the design before code, not an additional owner
approval. Unless corrected, use the documented defaults after forwarding.

No Courier-internal code is authorized in this module. Integration belongs to
its source owner after the engine boundary settles. No E1 implementation dependency.
