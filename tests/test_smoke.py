"""Smoke test: does the plugin load cleanly on a CLN node, and does it
register the RPCs we expect?

This is the cheapest possible sanity check — no factory ceremony, no
bitcoind interaction beyond what pyln-testing does automatically. If
this fails, nothing else will pass either, so keep it first and fast.

Expected RPCs come from the plugin's ``commands[]`` array in
superscalar.c. If we add a new RPC and forget to add it here, this test
will still pass (we assert >= presence, not equality). That's
intentional: this file isn't the source of truth for the RPC list, the
plugin is.
"""
from __future__ import annotations

import pytest


# Must be present for basic factory lifecycle. If any of these go
# missing the plugin is broken.
REQUIRED_RPCS = [
    "factory-create",
    "factory-rotate",
    "factory-force-close",
    "factory-check-breach",
    "factory-ladder-status",
]


def test_plugin_loads(ss_node_factory):
    """One CLN node, plugin auto-loaded, basic RPC reachable."""
    node = ss_node_factory.get_node()
    # getinfo is a no-op CLN RPC; succeeding means the plugin didn't
    # crash the daemon on load.
    info = node.rpc.getinfo()
    assert "id" in info
    assert len(info["id"]) == 66  # compressed pubkey hex


def test_plugin_registers_required_rpcs(ss_node_factory):
    """Every RPC we consider part of the plugin's API surface should be
    visible in `help`. Missing ones are the most common way a plugin
    silently "works" but breaks downstream tests."""
    node = ss_node_factory.get_node()
    help_out = node.rpc.help()
    # help returns a list of { "command": "cmd params", "verbose": "..." }
    commands = {c["command"].split()[0] for c in help_out.get("help", [])}
    missing = [rpc for rpc in REQUIRED_RPCS if rpc not in commands]
    assert not missing, (
        f"plugin loaded but these RPCs are missing: {missing}. "
        f"Check commands[] in superscalar.c."
    )


def test_plugin_survives_restart(ss_node_factory):
    """Plugins that init-crash on first restart are a pain to diagnose.
    Catch it early: stop the node, start it again, assert the plugin is
    still functional."""
    node = ss_node_factory.get_node()
    node.rpc.getinfo()  # baseline
    node.restart()
    info = node.rpc.getinfo()
    assert "id" in info
    # factory-ladder-status is a pure read; if the plugin's ``init``
    # callback is broken, this will fail.
    ladder = node.rpc.call("factory-ladder-status")
    assert ladder.get("initialized") is True


@pytest.mark.slow
def test_two_nodes_connect_and_discover_protocols(ss_node_factory):
    """Minimal two-node sanity: plugin on both sides exchanges
    ``supported_factory_protocols`` via custommsg 33001 and logs it."""
    l1, l2 = ss_node_factory.get_nodes(2)
    l1.connect(l2)
    # Custommsg exchange is async; give it a few seconds.
    l1.daemon.wait_for_log(r"Peer .*supports .*SuperScalar", timeout=30)
    l2.daemon.wait_for_log(r"Peer .*supports .*SuperScalar", timeout=30)
