# Grant check boundary for Courier (CG1)

Design-stage regtest module. [DESIGN.md](DESIGN.md) defines the proposed narrow
library over the landed K1 v3 kernel and M2-05 kernelbind. No Go implementation,
Courier integration or deployed service is claimed at this stage.

## Tools and artifacts

- Read `DESIGN.md` for the proposed API, decision codes, proof/cache boundaries
  and fixture plan. Integration questions are tracked in
  [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).
- `git diff --check -- experiments/grantcheck` checks documentation whitespace.
- Subsequent Go controls and opt-in genuine-Core fixture generation will be
  documented here when implemented. Task-local probes/logs belong under `.temp/`.
