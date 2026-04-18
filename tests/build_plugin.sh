#!/bin/bash
# tests/build_plugin.sh — ensure the plugin binary exists before pytest runs.
#
# Thin wrapper around the top-level build-plugin.sh. Exits 0 if the
# binary is already up-to-date, or builds it if missing / stale.
# Called by `make test` and by the CI workflow.
#
# Why this is separate from build-plugin.sh: the top-level script is
# opinionated about CLN_DIR / SS_DIR layout (production VPS paths).
# This wrapper is more forgiving about dev environments and is the
# shim that CI talks to.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLN_DIR="${CLN_DIR:-/root/cln-blip56}"
SS_DIR="${SS_DIR:-/root/SuperScalar}"
PLUGIN_OUT="${SUPERSCALAR_PLUGIN:-$CLN_DIR/plugins/superscalar}"

# Check prerequisites with clear errors rather than letting gcc blow up.
if [ ! -d "$CLN_DIR" ]; then
    echo "build_plugin.sh: CLN_DIR=$CLN_DIR doesn't exist." >&2
    echo "Set CLN_DIR to your CLN bLIP-56 fork checkout." >&2
    exit 2
fi
if [ ! -d "$SS_DIR" ]; then
    echo "build_plugin.sh: SS_DIR=$SS_DIR doesn't exist." >&2
    echo "Set SS_DIR to your SuperScalar library checkout (with build/ populated)." >&2
    exit 2
fi
if [ ! -f "$SS_DIR/build/libsuperscalar.a" ]; then
    echo "build_plugin.sh: libsuperscalar.a missing at $SS_DIR/build/." >&2
    echo "Run: cd $SS_DIR && cmake -B build && cmake --build build" >&2
    exit 2
fi

# Staleness check: if the binary is newer than every source file and
# newer than libsuperscalar.a, skip the rebuild. Saves ~30s per CI run.
needs_rebuild=1
if [ -x "$PLUGIN_OUT" ]; then
    needs_rebuild=0
    for src in "$REPO_ROOT"/*.c "$REPO_ROOT"/*.h "$SS_DIR/build/libsuperscalar.a"; do
        if [ "$src" -nt "$PLUGIN_OUT" ]; then
            needs_rebuild=1
            break
        fi
    done
fi

if [ "$needs_rebuild" = "1" ]; then
    echo "build_plugin.sh: rebuilding plugin..."
    CLN_DIR="$CLN_DIR" SS_DIR="$SS_DIR" PLUGIN_SRC="$REPO_ROOT" \
        bash "$REPO_ROOT/build-plugin.sh"
else
    echo "build_plugin.sh: plugin up-to-date at $PLUGIN_OUT"
fi

# Re-export for downstream pytest runs.
echo "SUPERSCALAR_PLUGIN=$PLUGIN_OUT"
