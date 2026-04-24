"""pytest fixtures for the superscalar-cln plugin test suite.

Uses pyln-testing's ``node_factory`` and ``bitcoind`` fixtures to spin up
CLN node subprocesses backed by a bitcoind regtest instance. Each test
gets a clean world; no state leaks between tests.

The plugin binary is built once per pytest session by ``tests/build_plugin.sh``
and located via ``SUPERSCALAR_PLUGIN`` env var (falls back to the default
build output path). Tests that need a plugin-loaded node ask for the
``ss_node_factory`` fixture instead of the raw ``node_factory``.

Helper conventions:
    - ``wait_for_log(node, pattern, timeout=30)``: block until the node's
      log matches the regex, or raise TimeoutError. Preferable to
      ``node.daemon.wait_for_log`` when you want a specific regex and a
      custom timeout.
    - ``datastore_has(node, key_path)``: polls ``listdatastore`` for up
      to 30s; returns True once the key exists.
    - ``create_two_party_factory(lsp, client, funding_sats=100_000)``:
      drives the ceremony end-to-end and returns the instance_id.

Do not import pyln-testing at module scope — it requires the CLN source
tree on disk, which isn't present in every dev environment. Import
inside fixtures so plain ``pytest --collect-only`` still works.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _default_plugin_path() -> Path:
    """Where we expect build_plugin.sh to have put the plugin binary."""
    # Matches the layout used by build-plugin.sh (it deposits the binary
    # at $CLN_DIR/plugins/superscalar, default /root/cln-blip56).
    cln_dir = os.environ.get("CLN_DIR", "/root/cln-blip56")
    return Path(cln_dir) / "plugins" / "superscalar"


@pytest.fixture(scope="session")
def plugin_path() -> Path:
    """Path to a built plugin binary.

    Resolution order:
      1. SUPERSCALAR_PLUGIN env var if set.
      2. Default path from build_plugin.sh.

    Fails the session (not just the test) if the binary is missing — if
    you're running pytest at all, you need this built first. Run
    ``make test`` or ``tests/build_plugin.sh`` to produce it.
    """
    override = os.environ.get("SUPERSCALAR_PLUGIN")
    path = Path(override) if override else _default_plugin_path()
    if not path.exists():
        pytest.exit(
            f"plugin binary not found at {path}.\n"
            "Run `make test` (or `tests/build_plugin.sh` directly) first.\n"
            "Override with SUPERSCALAR_PLUGIN=/absolute/path/to/superscalar.",
            returncode=2,
        )
    if not os.access(path, os.X_OK):
        pytest.exit(
            f"plugin at {path} is not executable. "
            "Did the build succeed?",
            returncode=2,
        )
    return path


@pytest.fixture
def ss_node_factory(node_factory, plugin_path):
    """Thin wrapper around pyln-testing's node_factory that auto-loads
    the superscalar plugin on every node spawned through it.

    Use like:
        def test_something(ss_node_factory):
            lsp, client = ss_node_factory.get_nodes(2)
            # both nodes already have the plugin loaded

    If a test wants plugin-free nodes (e.g. a neutral bitcoind peer),
    it can still request the raw ``node_factory`` — they coexist.
    """
    class _FactoryWrapper:
        def __init__(self, inner, plugin):
            self._inner = inner
            self._plugin = plugin

        def _inject(self, opts):
            if opts is None:
                opts = {}
            # Don't clobber an explicit plugin= the test set
            if "plugin" not in opts:
                opts["plugin"] = str(self._plugin)
            return opts

        def get_node(self, options=None, **kwargs):
            return self._inner.get_node(
                options=self._inject(options), **kwargs
            )

        def get_nodes(self, n, opts=None, **kwargs):
            if isinstance(opts, list):
                opts = [self._inject(o) for o in opts]
            else:
                opts = [self._inject(opts) for _ in range(n)]
            return self._inner.get_nodes(n, opts=opts, **kwargs)

        def __getattr__(self, name):
            # Anything we don't override falls through to the real factory.
            return getattr(self._inner, name)

    return _FactoryWrapper(node_factory, plugin_path)


def wait_for_log(node, pattern: str, timeout: float = 30.0) -> str:
    """Poll ``node.daemon.logs`` for a regex match. Return the matching
    line. Raise ``TimeoutError`` if not seen within ``timeout`` seconds.

    Matches pyln-testing's own ``wait_for_log`` but returns the line so
    callers can capture fields (e.g. an instance_id in the log)."""
    deadline = time.time() + timeout
    rx = re.compile(pattern)
    while time.time() < deadline:
        for line in node.daemon.logs:
            if rx.search(line):
                return line
        time.sleep(0.2)
    raise TimeoutError(
        f"log pattern {pattern!r} not seen within {timeout}s on {node.info.get('alias', '?')}"
    )


def datastore_has(node, key_path: list[str], timeout: float = 30.0) -> bool:
    """Poll ``listdatastore`` until the given key path has at least one
    entry or timeout expires. Returns True / False, never raises on
    timeout (tests decide whether that's fatal)."""
    # listdatastore takes a path prefix; any hit under it counts.
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = node.rpc.listdatastore(key_path)
            if r.get("datastore"):
                return True
        except Exception:
            # RPC might transiently fail during node startup; ignore.
            pass
        time.sleep(0.2)
    return False


def wait_for_ceremony_complete(lsp, iid: str,
                               timeout: float = 120.0) -> str:
    """Poll factory-list until the factory's ceremony field reports
    'complete'. Returns the final ceremony value (typically 'complete'
    on success). Raises TimeoutError if the ceremony doesn't advance
    within the timeout.

    Used by Phase 5b regtest tests to drive a full ceremony end-to-end
    and assert it landed, instead of just checking that factory-create
    returned an instance_id."""
    deadline = time.time() + timeout
    last_seen = "unknown"
    while time.time() < deadline:
        try:
            out = lsp.rpc.call("factory-list")
            for f in out.get("factories", []):
                if f["instance_id"] == iid:
                    last_seen = f.get("ceremony", "unknown")
                    if last_seen == "complete":
                        return last_seen
                    break
        except Exception:
            # RPC can transiently fail during plugin async work; ignore.
            pass
        time.sleep(0.5)
    raise TimeoutError(
        f"factory {iid} ceremony stalled at {last_seen!r} after "
        f"{timeout}s. Check both nodes' logs for custommsg 33001 "
        f"exchange progress."
    )


def create_two_party_factory(
    lsp,
    client,
    funding_sats: int = 100_000,
    timeout: float = 120.0,
    arity_mode: str | None = None,
) -> str:
    """Drive the happy-path two-party factory ceremony from LSP side.
    Returns the persisted ``instance_id``.

    Pre-conditions:
      - LSP and client nodes both have the plugin loaded.
      - LSP has ``funding_sats + fees`` confirmed on-chain.
      - At least one side has connected to the other.

    arity_mode: optional, one of "auto" | "arity_1" | "arity_2" |
    "arity_ps" (or the "ps" alias). When provided, threads through
    factory-create so both sides build the matching tree shape.

    This wraps the async ceremony in a synchronous call by polling the
    datastore for the meta blob to appear. Suitable for happy-path tests;
    adversarial tests that need to interrupt mid-ceremony should call
    ``factory-create`` directly and drive the log matching themselves.
    """
    client_id = client.info["id"]
    payload = {"funding_sats": funding_sats, "clients": [client_id]}
    if arity_mode is not None:
        payload["arity_mode"] = arity_mode
    r = lsp.rpc.call("factory-create", payload)
    iid = r["instance_id"]
    if not datastore_has(
        lsp, ["superscalar", "factories", iid], timeout=timeout
    ):
        raise AssertionError(
            f"factory {iid} never persisted to LSP datastore within {timeout}s — "
            "ceremony likely stalled. Check client log for 33001 custommsg receipt."
        )
    return iid
