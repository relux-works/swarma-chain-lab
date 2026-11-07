# Exact third-party baseline

This experiment's original files follow the repository's Apache-2.0 license.
Upstream artifacts retain their own licenses; copied license texts are in
`licenses/`, with original paths and SHA256 values in `license-inventory.json`.
Artifacts remain separate from original experiment code.

| Distribution | Version | License |
| --- | --- | --- |
| ElectrumX (`e-x`) | 2.0.1 | MIT |
| aiorpcX | 0.25.0 | MIT |
| aiohttp | 3.14.5 | Apache-2.0 AND MIT |
| aiohappyeyeballs | 2.7.1 | PSF-2.0 |
| aiosignal | 1.4.0 | Apache-2.0 |
| attrs | 26.1.0 | MIT |
| frozenlist | 1.8.0 | Apache-2.0 |
| multidict | 7.2.1 | Apache-2.0 |
| propcache | 0.5.4 | Apache-2.0 (retained notices included) |
| yarl | 1.25.1 | Apache-2.0 (retained notices included) |
| idna | 3.20 | BSD-3-Clause |
| websockets | 17.4 | BSD-3-Clause |
| plyvel | 1.5.1 | BSD-3-Clause |
| LevelDB | 1.23 | BSD-3-Clause |
| setuptools (build only) | 84.2.1 | MIT; bundled dependency notices retained |
| wheel (build only) | 0.48.0 | MIT |
| packaging (build only) | 26.3 | Apache-2.0 OR BSD-2-Clause |

Namecoin Core 28.0 is an external, future node dependency (MIT); no node binary
is built or run here. Relevant exact-commit RPC source is retained separately
in the private evidence packet. The evaluated system Python/compiler/CMake/libc
are system tools: their exact installed versions and binary hashes are recorded
in private receipts, not silently treated as part of a portable wheel lock.
