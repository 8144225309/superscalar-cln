#!/bin/bash
# Build the superscalar CLN plugin.
#
# Prerequisites:
#   1. CLN (bLIP-56 fork) built at $CLN_DIR with ./configure && make
#   2. SuperScalar built at $SS_DIR with cmake -B build && cmake --build build
#   3. Wally's secp256k1-zkp must have musig module enabled:
#      In $CLN_DIR/external/libwally-core/configure.ac, add [--enable-module-musig]
#      to the AX_SUBDIRS_CONFIGURE secp256k1 args, then rebuild CLN externals:
#        rm -rf $CLN_DIR/external/build-*/libwally-core-build
#        cd $CLN_DIR && make -j$(nproc)
#
# Both SuperScalar and CLN/wally pin secp256k1-zkp to the same commit
# (6152622613fdf1c5af6f31f74c427c4e9ee120ce), so there is ONE secp256k1
# in the binary. No --allow-multiple-definition needed for secp symbols.
#
# The only remaining symbol conflicts are utility functions in
# libsuperscalar (sha256, hex_decode, etc.) which are renamed via objcopy.

set -e

CLN_DIR="${CLN_DIR:-/root/cln-blip56}"
SS_DIR="${SS_DIR:-/root/SuperScalar}"
PLUGIN_SRC="${PLUGIN_SRC:-$(dirname $0)}"

cd "$CLN_DIR"

# Copy plugin sources
cp "$PLUGIN_SRC/superscalar.c" "$PLUGIN_SRC/factory_state.h" \
   "$PLUGIN_SRC/factory_state.c" "$PLUGIN_SRC/persist.c" \
   "$PLUGIN_SRC/persist.h" "$PLUGIN_SRC/nonce_exchange.c" \
   "$PLUGIN_SRC/nonce_exchange.h" "$PLUGIN_SRC/fee_stubs.c" \
   "$PLUGIN_SRC/ceremony.h" plugins/

# --- Step 1: Build slim libsuperscalar (only the 9 files we need) ---
# The full libsuperscalar.a has 106 .o files. 97 of them export symbols
# that conflict with CLN (hex_decode, bolt11_decode, etc). We extract
# only the 9 .o files our plugin actually calls.
SLIM_DIR=$(mktemp -d)
cd "$SLIM_DIR"
ar x "$SS_DIR/build/libsuperscalar.a" \
  factory.c.o musig.c.o dw_state.c.o ladder.c.o \
  tx_builder.c.o tapscript.c.o adaptor.c.o util.c.o shachain.c.o

# Rename the 6 utility-function conflicts in ALL extracted .o files
for obj in *.o; do
  objcopy \
    --redefine-sym sha256=ss_sha256 \
    --redefine-sym sha256_double=ss_sha256_double \
    --redefine-sym sha256_tagged=ss_sha256_tagged \
    --redefine-sym hex_decode=ss_hex_decode \
    --redefine-sym hex_encode=ss_hex_encode \
    --redefine-sym shachain_from_seed=ss_shachain_from_seed \
    "$obj"
done
ar rcs "$SLIM_DIR/libsuperscalar_slim.a" *.o
cd "$CLN_DIR"

# --- Step 2: Compile plugin .o files ---
CFLAGS="-DCLN_NEXT_VERSION=\"v25.12\" \
  -DPKGLIBEXECDIR=\"/usr/local/libexec/c-lightning\" \
  -DBINDIR=\"/usr/local/bin\" \
  -DPLUGINDIR=\"/usr/local/libexec/c-lightning/plugins\" \
  -DCCAN_TAL_NEVER_RETURN_NULL=1 -Wno-error \
  -std=gnu11 -g -fstack-protector-strong -Og \
  -I ccan -I external/libwally-core/include/ \
  -I external/libwally-core/src/secp256k1/include/ \
  -I external/jsmn/ -I external/libbacktrace/ -I external/gheap/ \
  -I external/build-$(uname -m)-linux-gnu/libbacktrace-build \
  -I . -I/usr/local/include \
  -I $SS_DIR/include -I $PLUGIN_SRC \
  -I/usr/include/postgresql \
  -DSHACHAIN_BITS=48 -DJSMN_PARENT_LINKS \
  -DCOMPAT_V052=1 -DCOMPAT_V060=1 -DCOMPAT_V061=1 -DCOMPAT_V062=1 \
  -DCOMPAT_V070=1 -DCOMPAT_V072=1 -DCOMPAT_V073=1 -DCOMPAT_V080=1 \
  -DCOMPAT_V081=1 -DCOMPAT_V082=1 -DCOMPAT_V090=1 -DCOMPAT_V0100=1 \
  -DCOMPAT_V0121=1"

for src in superscalar factory_state persist nonce_exchange fee_stubs; do
  cc $CFLAGS -c plugins/$src.c -o plugins/$src.o
done

# --- Step 3: Link ---
# One secp256k1 (from CLN's wally, with musig enabled).
# Slim libsuperscalar provides factory/musig/DW functions.
# No --allow-multiple-definition needed.
cc -Og -o plugins/superscalar \
  plugins/superscalar.o plugins/factory_state.o plugins/nonce_exchange.o \
  plugins/persist.o plugins/fee_stubs.o plugins/libplugin.o \
  "$SLIM_DIR/libsuperscalar_slim.a" \
  libcommon.a libccan.a \
  -Lexternal/build-$(uname -m)-linux-gnu -lwallycore -lsecp256k1 -ljsmn -lbacktrace \
  -L/usr/local/include -lm -lsqlite3 \
  -L/usr/lib/$(uname -m)-linux-gnu -lpq -lsodium -lz -lcrypto \
  -o plugins/superscalar

rm -rf "$SLIM_DIR"
echo "Plugin built: $(ls -la plugins/superscalar)"
