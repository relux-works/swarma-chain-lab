# Third-party material

The original plan, configuration templates and fixture checker code in this
experiment follow the repository's Apache-2.0 license. They do not relicense any
upstream material. No third-party executable is distributed by this experiment.

* Namecoin Core: MIT.
* ncdns: GPL-3.0-or-later. Its exact checked-in dependency graph is in the two
  `pins/ncdns.go.*` files. Preserve every dependency's own license/notice; the
  source-packet evidence includes an archive-member license/notice inventory.
* Postfix: EPL-2.0 OR IPL-1.0, publisher's dual license.
* Unbound: BSD-3-Clause, plus its bundled notices.
* OpenSSL 3.5.5: Apache-2.0.
* LMDB 0.9.31: OpenLDAP Public License 2.8 (OLDAP-2.8).
* Expat 2.7.3: MIT.
* GNU m4 1.4.20, build tool only: GPL-3.0-or-later and bundled notices.
* IFA proposal 0001: CC0-1.0.

See `pins/components.json` for exact canonical origins and digest-verification
scope. An inventory is not a conclusion about redistribution or binary-link
compatibility. Retain complete corresponding sources/notices if binaries are
later distributed; the current packet supplies source/config prerequisites only.
