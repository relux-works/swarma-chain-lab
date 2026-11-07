# Offline experiment CI

The workflow runs the existing Python standard-library controls in
`fullnode-trusts`, `notary`, `utxo-age` and `thin-regtest-assembly`, plus `go vet`
and `go test` for the sole Go module, `sealwatch`. Python discovery includes
every `test_*.py` in those four experiment directories. Notary additionally
runs both documented symbolic counterexample commands. There are no test
filters, substituted fixtures or allowed failures.

CPython is pinned to 3.14.4 and Go to 1.26.8. The module's declared language
version remains 1.26.0. These suites use only their standard libraries and
committed public inputs: no pip install, module acquisition or dependency
upgrade occurs. External Go canonical h1 verification is inapplicable because
the module has no external dependencies. Automatic Go toolchain acquisition,
module proxy access and cgo are disabled. Official actions use full commit pins;
the Ubuntu 22.04 launcher package is pinned to bubblewrap 0.6.1-1ubuntu0.3 from
the authenticated Ubuntu package archive. The hosted OS image and system
libraries remain GitHub-managed and are not bit-reproducible inputs.

Each suite gets a fresh `bwrap --unshare-all --clearenv` namespace with read-only
source/tools, an empty home view, no host keys or agent sockets, and private
mode-0700 absolute HOME, TMPDIR and cache paths. No host cache is restored.
Each job has a ten-minute limit and its test namespace a six-minute wall limit,
240-second per-process CPU limit, 256-MiB per-file limit and 256 open-file limit.
The source is read-only; only the disposable private scratch is writable.
The shell helper must run inside this namespace. Namespace admission failure
fails CI; it never falls back to execution on the runner host.

This deliberately excludes runtime/lifecycle launchers, Core, wallets, providers,
funds, live-chain access, native reference builds and the Electrum preparation
pipeline. The Electrum checks import pinned third-party ElectrumX modules and
the documented build also needs native LevelDB/plyvel inputs; this minimal job
does not download or fabricate that environment. The UTXO tests read the
committed native-reference outputs without executing the native encoder.

Full-node tests use the genuine, hash-checked historical builder at
[`test-inputs/original-lab.py.txt`](../experiments/fullnode-trusts/test-inputs/original-lab.py.txt).
The [input record](../experiments/fullnode-trusts/test-inputs/README.md) gives its
original commit/blob, SHA-256, licensing and AST-only use. No external `/inputs`
directory or private artifact is required by a public checkout.

The full-node job preserves the original sibling namespace topology: discovery,
the Go stdio relay, and each real verifier run in separate offline namespaces.
The host shell only launches/reaps namespaces and connects private FIFOs to
anonymous stdio pipes; it executes no product or verifier algorithm. The relay
is compiled offline using only Go's standard library and a fresh private cache.
The original verifier environment, source visibility, namespace, descriptor,
capability-object and denied-method assertions remain unchanged. The launcher
mounts fresh mode-0700 verifier HOME/TMP/cache directories read-only: zero
writable private bytes, within the historical 16-MiB ceiling. This avoids the
unsupported `--size` option in the pinned bubblewrap 0.6.1 without upgrading it.
The verifier needs no filesystem writes; its original startup assertions pass.
The launcher
checks the historical and verifier hashes before compilation/execution. Four
fresh verifier slots cover the complete existing discovery suite; exhaustion is
a hard error. The relay has an immutable 110-second cutoff and 2101-request /
8-MiB-line bounds in addition to the unchanged job/process limits. It forwards
actual verifier exits and decisions and supplies no mock admission. Nested
namespace creation or a host-executed relay is not required. A red result must
not be represented as runtime qualification.

CI does not promote the Python experiment exception into reusable tooling or
remove the Go promotion board gate. Passing checks do not admit a node/runtime,
spending, deployment or landing. Fresh independent exact-head review and the
Meta marker remain required before any landing.
