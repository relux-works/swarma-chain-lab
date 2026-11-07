#!/bin/sh
# Build-only, one bounded stage per invocation: lmdb, expat, m4, postfix, unbound.
# Run in that order with <=180 s wall per stage inside the documented sandbox.
# No Postfix master, ncdns, Unbound daemon, package manager or host installation.
set -eu
umask 077
case "${HOME:-}:${TMPDIR:-}" in /private/home:/private/tmp) ;; *) exit 64;; esac
stage=${1:?choose lmdb expat m4 postfix or unbound}
case "$stage" in lmdb|expat|m4|postfix|unbound) ;; *) exit 64;; esac
work=/private/tmp/mail-c-build
prefix=$work/prefix
mkdir -p "$prefix/include" "$prefix/lib" "$prefix/bin"
python3 - <<'PY'
import hashlib,json,pathlib
pins=json.loads(pathlib.Path('/source/experiments/namecoin-mail-source/pins/components.json').read_text())
for c in pins['components']:
 if 'filename' in c:
  p=pathlib.Path('/upstream')/c['filename']
  assert p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==c['sha256'], c['name']
print('Exact staged source digests verified; no acquisition permitted')
PY
case "$stage" in
 lmdb) archive=lmdb-0.9.31.tar.gz;; expat) archive=expat-2.7.3.tar.xz;;
 m4) archive=m4-1.4.20.tar.xz;; postfix) archive=postfix-3.11.7.tar.gz;;
 unbound) archive=unbound-1.26.2.tar.gz;;
esac
# These are only this invocation's fixed private scratch paths, inside the sandbox.
rm -rf "$work/$stage"
mkdir "$work/$stage"
tar -xf "/upstream/$archive" -C "$work/$stage" --strip-components=1
cd "$work/$stage"
case "$stage" in
 lmdb)
  cd libraries/liblmdb; make -j2 liblmdb.a
  cp lmdb.h "$prefix/include/"; cp liblmdb.a "$prefix/lib/";;
 expat)
  ./configure --prefix="$prefix" --disable-shared --without-xmlwf --without-docbook --without-tests
  make -j2; make install;;
 m4)
  # Existing Clang 21 avoids the recorded GCC 15/glibc 2.43 gnulib conflict.
  ./configure --prefix="$prefix" --disable-nls CC=clang CFLAGS='-O2 -std=gnu17'
  make -j2; make install;;
 postfix)
  export PATH="$prefix/bin:/usr/bin:/bin"
  # Launcher supplies a readonly awk tool link in private /etc/alternatives.
  command -v awk
  export CCARGS="-DNO_NIS -DNO_DB -DHAS_LMDB -DUSE_TLS -I$prefix/include"
  export AUXLIBS="-L$prefix/lib -llmdb -lssl -lcrypto"
  export default_database_type=lmdb default_cache_db_type=lmdb
  make -f Makefile.init makefiles; make -j1
  bin/postconf -d mail_version;;
 unbound)
  ./configure --prefix="$prefix" --without-libevent --with-libexpat="$prefix" --without-pyunbound --without-pythonmodule --disable-dnstap --disable-systemd --disable-flto
  make -j2 unbound unbound-checkconf;;
esac
printf 'Built source stage %s; no service started\n' "$stage"
