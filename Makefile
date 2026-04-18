# Top-level Makefile — thin convenience wrapper over the real work,
# which is done by build-plugin.sh, tests/build_plugin.sh, and pytest.
# These targets exist so `make test`, `make build`, `make lint` work
# with no arguments from any dev environment.

.PHONY: build test test-build test-clean lint

# Default target: build the plugin.
build:
	@bash build-plugin.sh

# Build the plugin AND run pytest.
# Isolates the build as a separate target so CI can cache / parallelize.
#
# pyln-testing locates lightningd via $LIGHTNINGD and `lightningd` on PATH;
# if neither points at our bLIP-56 fork build, pyln silently picks up the
# system `/usr/local/bin/lightningd` (may be a stale or upstream build)
# and tests hang at `plugins_init`. These vars make the target self-contained.
CLN_DIR ?= /root/lightning
SS_PLUGIN_PATH ?= /root/cln-blip56/plugins/superscalar
test: test-build
	@PATH=$(CLN_DIR)/lightningd:$(CLN_DIR)/cli:$$PATH \
	 LIGHTNINGD=$(CLN_DIR)/lightningd/lightningd \
	 SUPERSCALAR_PLUGIN=$(SS_PLUGIN_PATH) \
	 pytest tests/

# Ensure the plugin binary is present and up-to-date.
# Safe to invoke repeatedly; fast path if nothing changed.
test-build:
	@bash tests/build_plugin.sh

# Wipe any pytest / build artifacts. Doesn't touch the plugin binary
# itself (that's the shared build output used by real nodes too).
test-clean:
	@rm -rf tests/__pycache__ tests/.pytest_cache .pytest_cache

# Stub: add clang-format / ruff / mypy later as the codebase grows.
lint:
	@echo "lint target not yet wired; consider clang-format on *.c / *.h"
