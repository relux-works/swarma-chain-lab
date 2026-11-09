# M5 deploy preparation (DK1)

Survey-stage release kit for the landed service binaries. Read
[SURVEY.md](SURVEY.md) for actual CLI/runtime support and the gateway runtime
gap. No build tool, installable templates or deployed service is claimed yet.
The scope is regtest preparation, with no product changes or host installation.

## Tools and artifacts

- `go build -trimpath` builds the surveyed CLI packages; exact packages and flags
  are recorded in SURVEY.md. Local survey binaries/help output live in the
  repository's `.temp/DK1-01/` and contain no deployment credentials.
- `git diff --check -- deploy` checks documentation whitespace.
- `limactl list --json` inspects existing local Linux VM availability. The survey
  found none; systemd verification is explicitly not run.

Implementation and smoke commands will be documented when the kit is delivered.
Remaining scope decisions are in [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).
