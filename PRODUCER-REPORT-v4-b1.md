BLOCKED no grant member schema or J12 group octets in the pinned spec/lab

# V4-B1 producer report

The report skeleton was written before source investigation. B1 stopped at
the first missing contract: the requested VALID `swarma-grant/4` object has
no members in either specified spec revision, and the lab does not admit it.
No lab behavior, fixture or test was changed. No review or merge was performed.

## Citations
The full [citation list and source analysis](experiments/grant-v4/vectors/VECTORS.md#book-and-specification-sources)
records exact sections and immutable commits:

- Book: swarma-docs `b57a9be633c245373b448c3786bcbd49d636fe8a`, chapter 6
  “Гранты и полномочия”, “Общая модель и брокер v0”, lines 13–24. The broker
  and general grant models are separate; no v4 grant schema is supplied.
- Spec release: v0.1.51 `bd3bc80e5543d8a563343ec05abd1a5f3f67284c`.
  LIP-0020 Summary, buildability table, §3 W3.1–W3.2 and registry,
  §4 arithmetic example, §9 W9.4 step 1; LIP-0026 buildability table,
  §1 R1.1, §8 J12/R8.1–R8.4 and open octets, §§9–10 J10/J9, §11;
  LIP-0014 §8.3 J9.1–J9.4.
- Wire-pinned draft: `adae6e7669601f271f7d0d9cdd91ecee7d19bf02`, LIP-0020
  same Summary, buildability, §3 W3.1, §4 and §9 W9.4 constraints.
- Lab base: `8a47f1a984cd93864402f7fdc09d2eba0d890b90`, wire README
  “Composed issuance on stated inputs”/“Source pin and vector scope”,
  `canonical.go`, `crypto.go`, `objects.go`, `composed.go` and
  `TestV4ComposedDispatchBoundary`; identity `R1-DECISIONS-051.md`
  “OPEN QUESTIONS” Q1–Q4, `r1_profile.go` and `r1_groups.go`.

## Coverage
“Grant-member” maps to the `swarma-grant/4` payload and its nested JSON
members, including the conceptual row/group/template/range structures of
LIP-0026 §§1/8, inside LIP-0020 W5.3's signed wrapper. It introduces no
additional registry type. The exact member names and wire forms are absent.

The [coverage table](experiments/grant-v4/vectors/VECTORS.md#requested-outputs-and-current-coverage)
explicitly marks every requested B1 output unimplemented. No `vectors.json`,
Go regeneration test, Python implementation, deterministic signing fixture,
or one-byte drift control was produced. Existing assent/consent/preparation
support cannot substitute for VALID grant bytes. Delegation and re-delegation
bytes are B5 and B6, out of scope.

The brief supplied no formal surface table. There is no producer handoff of
code or coverage-map claim. No prior reviewer tests were altered; the full
unchanged wire suite passed as baseline evidence only.

## Findings and spec ambiguities
F1 — missing wire contract, not a discovered lab/spec disagreement.
LIP-0020 W3.1 requires unsupported memberless grant types to refuse
`WIRE_TYPE`. `ReadSigned(..., Grant)` does so; `TypedDigest` accepts the
registry name only for arithmetic. `EncodeDocument` is a generic canonical
encoder, not a grant encoder. `CheckIssuance` consumes `GrantFacts`, not
authenticated grant bytes. The raw-grant negative path already has a named
regression in `TestV4ComposedDispatchBoundary`.

The released spec, wire-pinned draft, book, generic encoder and R1 fact
structures were checked as clean paths. None yields a valid grant schema.
Copying Go field names into JSON, copying broker bytes or signing a type-only
payload would invent a protocol and mislabel arithmetic as a valid grant.

The spec seat must pin the candidate member schema, J12 octets, integer/key
forms, no-certifier representation, size/count bounds and refusal precedence;
then the lab's grant reader needs separately authorized behavior support.
Alternatively, the owner can narrow B1 explicitly to arithmetic primitives,
which would leave the present VALID grant requirement unresolved. See the
[decision list](experiments/grant-v4/vectors/VECTORS.md#decisions-needed-from-the-spec-seat).

No Python/Go disagreement was tested or claimed. No spec or lab behavior was
modified toward an expected answer. No cryptographic findings are asserted.

## Evidence
Baseline commands ran directly, without pipelines, using Go 1.26.10,
`GOTOOLCHAIN=local`, `GOWORK=off`, `GOFLAGS=-mod=readonly`, and isolated
absolute HOME/config/cache paths with a short task-owned TMPDIR. Dependencies
were downloaded before offline validation. Test checkout and tool state were
inside task-owned scratch. Source/test/config identity is unchanged from the
lab base above.

| Command | Exit | Scope |
| --- | --- | --- |
| `go -C experiments/grant-v4/wire mod download` | 0 | Pinned public dependency acquisition. |
| `go -C experiments/grant-v4/wire test -count=1 ./...` | 0 | Entire existing wire suite, including canonical vectors and unsupported-grant regression; no B1 vectors. |
| `go -C experiments/grant-v4/wire vet ./...` | 0 | Existing wire package. |
| `python3 -I` independent B1 re-derivation | Not run | No B1 file/schema or reader; blocked before implementation. |
| Go/Python one-byte drift plants | Not run | No B1 vector file or checking implementations. |
| `python3 -I .github/scripts/check-public-hygiene.py` | 0 | Tracked-tree publication check, after staging this documentation. This scanner checks Matrix identifiers, not arbitrary secrets. |
| `git diff --cached --check` | 0 | Documentation whitespace. |

Logs: task scratch `.temp/v4-b1/go-download-01.log`,
`go-test-01.log`, `go-vet-01.log`; these are private local evidence, not
committed artifacts. The bounded scanner and inspection of the publication
diff found no keys, secrets, host paths or runtime/session identifiers.
Both started validation processes exited; no process was killed. Task-owned
test HOME, config, dependency/build caches and TMPDIR were removed after
`chmod -R u+w` (78,328 KiB allocated before cleanup; removal verified).

## Publication

Branch `v4-vectors-b1` was cut from fetched current `origin/main` at the lab
base above. A pre-existing unrelated untracked report was preserved by using
an isolated task worktree. The delivery channel is a signed feature commit
and a draft PR titled `grant-v4: candidate v4 vector set (B1)`; its URL and
exact head are recorded by the hosting platform. No platform review or
landing is authorized. This is a blocked evidence delivery, not
READY_FOR_REVIEW and not an accepted vector set.
