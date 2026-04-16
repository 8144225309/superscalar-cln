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
# Why this is needed: see comment block at bottom of this script.

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
# that conflict with CLN (hex_decode, bolt11_decode, sha256_double, etc).
# We extract only the 9 .o files our plugin actually calls.
SLIM_DIR=$(mktemp -d)
cd "$SLIM_DIR"
ar x "$SS_DIR/build/libsuperscalar.a" \
  factory.c.o musig.c.o dw_state.c.o ladder.c.o \
  tx_builder.c.o tapscript.c.o adaptor.c.o util.c.o shachain.c.o

# Rename the 6 remaining conflicting symbols in ALL extracted .o files
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
# SuperScalar's secp256k1-zkp (from its FetchContent) provides the musig
# functions with the API that libsuperscalar was compiled against.
# CLN's wally secp256k1-zkp provides all other secp256k1 functions.
# --allow-multiple-definition lets the first definition win for shared
# symbols (context_create, ec_pubkey_parse, etc).
SS_SECP="$SS_DIR/build/_deps/secp256k1-zkp-build/lib/libsecp256k1.a"
if [ ! -f "$SS_SECP" ]; then
  SS_SECP="$SS_DIR/build/_deps/secp256k1-zkp-build/src/libsecp256k1.a"
fi

cc -Og -o plugins/superscalar \
  plugins/superscalar.o plugins/factory_state.o plugins/nonce_exchange.o \
  plugins/persist.o plugins/fee_stubs.o plugins/libplugin.o \
  "$SLIM_DIR/libsuperscalar_slim.a" "$SS_SECP" \
  libcommon.a libccan.a \
  -Lexternal/build-$(uname -m)-linux-gnu -lwallycore -lsecp256k1 -ljsmn -lbacktrace \
  -Wl,--allow-multiple-definition \
  -L/usr/local/include -lm -lsqlite3 \
  -L/usr/lib/$(uname -m)-linux-gnu -lpq -lsodium -lz -lcrypto \
  -o plugins/superscalar

rm -rf "$SLIM_DIR"
echo "Plugin built: $(ls -la plugins/superscalar)"

# ==========================================================================
# WHY THIS BUILD IS COMPLICATED
# ==========================================================================
#
# The SuperScalar plugin links two libraries that both use secp256k1-zkp
# (BlockstreamResearch's fork of libsecp256k1 with MuSig2 support):
#
#   1. libsuperscalar — the SuperScalar protocol library (DW trees, MuSig2
#      ceremony, factory state). Built by SuperScalar's CMake, which
#      fetches secp256k1-zkp via FetchContent at a specific commit.
#
#   2. CLN's libwally-core — Bitcoin primitives (PSBT, signatures, etc).
#      Bundles its OWN copy of secp256k1-zkp as a git submodule, at a
#      DIFFERENT commit than SuperScalar uses.
#
# Both are secp256k1-zkp, but at different commits with INCOMPATIBLE APIs:
#   - SuperScalar's commit: secp256k1_musig_pubkey_agg takes 5 arguments
#   - Wally's commit: secp256k1_musig_pubkey_agg takes 6 arguments
#     (extra scratch_space parameter)
#
# This is NOT a bug in either project. secp256k1-zkp's MuSig2 module is
# experimental and its API changes between commits. Both SuperScalar and
# wally pin to specific commits that work for their respective needs.
#
# The conflict arises ONLY when linking both into one binary (our plugin).
# With two copies of secp256k1 statically linked, the linker must choose
# which version of each function to keep. If it picks wally's
# secp256k1_musig_pubkey_agg (6-arg) but libsuperscalar calls the 5-arg
# version, the 5th argument (n_pubkeys, a count like "2") gets interpreted
# as a pointer → SIGSEGV.
#
# The solution:
#   1. Link SuperScalar's secp256k1-zkp FIRST (via $SS_SECP) so its musig
#      functions win for --allow-multiple-definition
#   2. CLN's secp256k1-zkp (via -lsecp256k1) provides non-musig functions
#      that wally needs (ecdh, surjection, whitelist, etc)
#   3. The slim lib contains only 9 .o files from libsuperscalar (out of
#      106) to minimize symbol conflicts — the other 97 files export
#      functions like hex_decode, bolt11_decode, etc that clash with CLN
#   4. The 6 remaining utility-function conflicts are resolved via objcopy
#      --redefine-sym (sha256 → ss_sha256, hex_decode → ss_hex_decode)
#
# Wally's --enable-module-musig in configure.ac is needed so CLN's own
# secp256k1 build includes the musig headers. Without it, our plugin code
# can't compile against CLN's secp256k1 headers (missing musig types).
# The actual musig FUNCTIONS come from SuperScalar's secp, not wally's.
# ==========================================================================
