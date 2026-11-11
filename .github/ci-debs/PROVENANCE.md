# Pinned Ubuntu bubblewrap for offline CI

The Ubuntu 22.04 amd64 workflow installs the unmodified Ubuntu package below.
The install step verifies its SHA-256 before invoking `dpkg --install`, then
asserts the installed version. It performs no APT update or download. Missing
dependencies cause installation to fail; CI does not repair them or relax the
pin. The package depends on `libc6 (>= 2.34)`, `libcap2 (>= 1:2.10)` and
`libselinux1 (>= 3.1~)` from the runner image.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `bubblewrap_0.6.1-1ubuntu0.3_amd64.deb` | 46314 | `706763714e5d19fc7ab2572a6418506e3a4a5d5960e99309707b58117e6b40cb` |
| `source/bubblewrap_0.6.1.orig.tar.xz` | 145500 | `9609c7dc162bc68abc29abfab566934fdca37520a15ed01b675adcf3a4303282` |
| `source/bubblewrap_0.6.1-1ubuntu0.3.debian.tar.xz` | 13500 | `463b0376becac1bb6c0e3068e5a4f5e129715cd29a7d0f585e86d5fa047b81cd` |
| `source/bubblewrap_0.6.1-1ubuntu0.3.dsc` | 2280 | `5859fe8b6214d4fe4315641ad72d6ee6c3e714a45f509e5223f7ff0811f80522` |

All four original files come from the
[Ubuntu bubblewrap pool](https://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/).
The source archives contain the corresponding upstream source and Ubuntu/Debian
patches and build instructions; the `.dsc` describes their assembly. They are
provided alongside the binary, not built or executed by CI. `COPYRIGHT.bubblewrap`
is the package's unmodified copyright notice and `COPYING.bubblewrap` is the
upstream source's complete license. The package is distributed under LGPL-2-or-later,
with the additional file-specific notice recorded in its copyright file.

## Authentication performed on 2026-11-11

The chain was checked independently on agents1 and ivmbp. The latter also checked
the corresponding source artifacts. This records the package's origin; the
workflow's hardcoded SHA-256 pins the reviewed bytes without consulting a mutable
network index at job runtime.

1. Obtain the Ubuntu archive keyring from
   `https://archive.ubuntu.com/ubuntu/project/ubuntu-archive-keyring.gpg`.
   Independently compare the signing-key fingerprint with Ubuntu's
   [Security FAQ](https://wiki.ubuntu.com/Security/FAQ) and
   [archive verification documentation](https://documentation.ubuntu.com/security/software-integrity/archive-verification/).
   The verified signing key is **Ubuntu Archive Automatic Signing Key (2018)**,
   fingerprint `F6ECB3762474EDA9D21B7022871920D1991BC93C`.
2. Verify `https://archive.ubuntu.com/ubuntu/dists/jammy-updates/InRelease`
   with `gpgv --keyring /absolute/path/to/ubuntu-archive-keyring.gpg InRelease`.
   The captured release has `Date: Wed, 11 Nov 2026 06:32:56 UTC`; GnuPG returned
   `VALIDSIG` for the fingerprint above, not merely an untrusted key name.
3. Its SHA256 section authenticates these exact compressed indexes:

   | Index | Bytes | SHA-256 |
   | --- | ---: | --- |
   | `main/binary-amd64/Packages.gz` | 4844157 | `1093eb068d829410fae3e91e4c96f9d32a9cd948b8badd88c32edfb835b4a304` |
   | `main/source/Sources.gz` | 759314 | `6c6a89e1c738c768acb78235e2c7478e763508bb3f104a419202921f57e1ddae` |

   Download each via its sibling `by-hash/SHA256/<hash>` URL and verify both
   length and SHA-256 before decompression. This avoids mixing index revisions.
4. The authenticated binary index's `Package: bubblewrap`,
   `Version: 0.6.1-1ubuntu0.3`, `Architecture: amd64` entry supplies the binary
   path, size and SHA-256 above. The corresponding source entry supplies all
   three source-file hashes and sizes. Every vendored file matched those values.

For a future update, repeat this signed-index verification and review the new
version, architecture, dependency list, source and notices together. Update the
workflow's checksum and installed-version assertion in the same reviewed change.
A hosted Ubuntu 22.04 run must install successfully and execute all offline suites;
local shell fixtures alone do not establish package installation compatibility.
