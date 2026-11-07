# Namecoin snapshot creation-age analysis candidate

This experiment decodes the **Namecoin Core 28.0 version-2 canonical
UTXO snapshot** and exercises an integer-only analysis on synthetic fixtures.
It is ready for independent review. Real-chain analysis is not qualified:
the command line accepts only the documented fixture schema and reports
`SYNTHETIC_FIXTURE_ONLY`, with `global_statistics: null`.

There is no node, RPC client, database adapter, address decoder, wallet,
transaction builder or production integration in this experiment. No current
supply, owner inactivity, lost-coin estimate or real largest-output result is
provided. UTXO **last-creation age is neither owner inactivity nor original coin
age**. Transfers and change create new outputs; name updates do as well.

The decoder follows the pinned Namecoin source, including its native
`CNameScript` coin/name classification. Its metadata, all six compression
tags, native `Coin` round trips, primitive integer encodings and full synthetic
container are checked against a separately compiled native reference. That
reference also computes the serialized UTXO commitment using native field
serialization. These are executable reference checks, not independent review
or consensus validation of a chain.

See [FORMAT.md](FORMAT.md) for the exact bytes and primary source references,
[CONTRACT.md](CONTRACT.md) for the unresolved real-data acceptance gate,
and [REPRODUCE.md](REPRODUCE.md) for offline reconstruction. The only analysis
dependency is the Python standard library. The optional reference build uses
the bundled secp256k1 in the exact source archive; no package or dependency
upgrade is needed. Go module `h1` checks are inapplicable.

Every file under `fixtures/` is explicitly synthetic. The public curve
generator and repeated hash bytes are test encodings, unrelated to any wallet
or observed chain output. Headers have zero work and must fail real-chain
qualification. Fixture values are not network measurements.

## Repository layout and review boundary

This directory is self-contained: mount `experiments/utxo-age/` as `/src`
when following [REPRODUCE.md](REPRODUCE.md). Keep its files together; the
Python imports, fixture paths and native build paths are directory-relative.
No package installation or repository-wide build integration is required.

The standalone component was reviewed for source and synthetic fixtures only.
Its composition into this repository requires a fresh review of the exact
repository candidate. Neither that component review nor fixture success
qualifies real-chain measurements. The validated-chain custody and RPC
conversion adapter described in CONTRACT.md remains unimplemented.

The repository LICENSE and NOTICE are retained. The pinned Namecoin native
reference materials retain their upstream notices; [COPYING.namecoin](COPYING.namecoin)
reproduces the pinned source's MIT license. Building the optional reference
requires the separately verified upstream source described in FORMAT.md;
that source is not vendored here.
