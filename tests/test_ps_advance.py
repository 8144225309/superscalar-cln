"""Tier 2.6 — Pseudo-Spilman leaf advance ceremony (factory-ps-advance).

End-to-end tests with a real LSP + client two-node setup asserting:
  - arity_mode="arity_ps" produces tree_mode=ps after ceremony
  - factory-ps-advance rejects non-PS factories and bad leaf_side
  - full PS advance ceremony completes (PROPOSE + PSIG + DONE)
  - chain_pos grows across repeated advances
  - chain entries persist to the datastore under ps_chain/{leaf}/{pos}
"""
from __future__ import annotations

import time
import pytest
from pyln.client import RpcError

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
    datastore_has,
)


def _setup_factory(ss_node_factory, arity_mode=None, funding_sats=100_000):
    """LSP+client ceremony driven to completion. Returns (lsp, client, iid)."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode=arity_mode)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _factory(lsp, iid):
    for f in lsp.rpc.call("factory-list")["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not in factory-list")


def _wait_metric(node, pattern, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if node.daemon.is_in_log(pattern):
            return True
        time.sleep(0.2)
    raise AssertionError(f"log pattern {pattern!r} not seen within {timeout}s")


def test_ps_factory_create_tree_mode(ss_node_factory):
    """arity_mode=arity_ps produces tree_mode=ps on factory-list for a
    real two-party ceremony (not just fake-client-IDs like test_arity)."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")
    f = _factory(lsp, iid)
    assert f["arity_mode"] == "arity_ps"
    assert f["tree_mode"] == "ps"


def test_ps_advance_rejects_non_ps_factory(ss_node_factory):
    """factory-ps-advance on a non-PS factory returns a clean error."""
    lsp, _client, iid = _setup_factory(ss_node_factory)  # default arity
    with pytest.raises(RpcError, match="arity is not ARITY_PS"):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})


def test_ps_advance_rejects_bad_leaf_side(ss_node_factory):
    """Out-of-range leaf_side is rejected cleanly."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")
    with pytest.raises(RpcError, match="leaf_side .* out of range"):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 99})


def test_ps_advance_happy_path(ss_node_factory):
    """Full PS advance ceremony: PROPOSE sent, client PSIG, LSP completes,
    DONE notification to all. Assert metrics fire at each phase and the
    chain[1] entry lands in the datastore."""
    lsp, client, iid = _setup_factory(ss_node_factory,
                                      arity_mode="arity_ps")

    r = lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
    assert r["status"] == "proposed"
    assert r["leaf_side"] == 0

    _wait_metric(lsp, r"SS_METRIC event=ps_advance_propose .* leaf=0")
    _wait_metric(client, r"SS_METRIC event=ps_advance_psig_sent leaf=0")
    _wait_metric(lsp,
                 r"SS_METRIC event=ps_advance .* leaf=0 chain_pos=1")
    _wait_metric(client,
                 r"SS_METRIC event=ps_advance_client_done leaf=0 chain_pos=1")

    assert datastore_has(
        lsp, ["superscalar", "factories", iid, "ps_chain"],
        timeout=5.0,
    ), "PS chain entry not persisted on LSP"


def test_ps_advance_chain_pos_grows(ss_node_factory):
    """Three sequential advances increment chain_pos 1 → 2 → 3 without
    state corruption."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")

    for expected_pos in (1, 2, 3):
        r = lsp.rpc.call("factory-ps-advance",
                         {"instance_id": iid, "leaf_side": 0})
        assert r["status"] == "proposed"
        _wait_metric(
            lsp,
            rf"SS_METRIC event=ps_advance .* leaf=0 chain_pos={expected_pos}",
        )


def test_ps_chain_persists_across_restart(ss_node_factory):
    """Review item 4: advance a PS leaf, restart the LSP, verify the
    plugin replays the persisted chain[0..N] from datastore so
    factory-list reflects the right arity/tree_mode and future operations
    can continue. We can't assert ps_chain_len directly via factory-list
    (not exposed today), but we CAN assert the persisted datastore keys
    survive the restart cycle."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")

    # Two advances so chain has both chain[0] + chain[1] + chain[2].
    for expected_pos in (1, 2):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        _wait_metric(
            lsp,
            rf"SS_METRIC event=ps_advance .* leaf=0 chain_pos={expected_pos}",
        )

    # Confirm chain entries are in datastore before restart.
    assert datastore_has(
        lsp, ["superscalar", "factories", iid, "ps_chain"],
        timeout=5.0,
    )

    lsp.restart()

    # After restart, the factory should still be in factory-list with
    # the right arity_mode + tree_mode (proves meta v14 round-trips) and
    # the ps_chain datastore entries should still exist.
    f = _factory(lsp, iid)
    assert f["arity_mode"] == "arity_ps"
    assert f["tree_mode"] == "ps"
    assert datastore_has(
        lsp, ["superscalar", "factories", iid, "ps_chain"],
        timeout=5.0,
    ), "PS chain datastore entries missing after restart"

    # And the plugin should have logged that it replayed chain entries.
    # ss_load_factories emits: "Loaded %d PS chain entries for leaf %d ..."
    assert lsp.daemon.is_in_log(
        r"Loaded \d+ PS chain entries for leaf 0"
    ), "plugin did not log PS chain replay on startup"
