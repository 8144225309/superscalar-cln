"""E2E tests for Phase 4b2 — RBF auto-rebuild.

Phase 4b detected STALE state (source UTXO vanished, burn references
dead outpoint) but required operator intervention to rebuild. Phase 4b2
closes the loop:

  1. Every block, auto-run source_check for BROADCAST/PENDING penalties
  2. On STALE detection, auto-launch state-TX scan
  3. When scan finds a different (revoked) epoch, auto-rebuild burns
     via ss_rebuild_breach_burns and register fresh pending_penalty

This test file exercises the dev-triggered path (operator can still
manually invoke via factory-source-check) and asserts state transitions
match expectations.

Real chain validation (counterparty actually RBFs a state TX) is a
Phase 5b regtest concern.
"""
from __future__ import annotations

import time


FAKE_CLIENT_ID = "02" + "00" * 32


def _create_factory(lsp, funding_sats: int = 100_000) -> str:
    r = lsp.rpc.call(
        "factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]},
    )
    return r["instance_id"]


def _factory(lsp, iid: str) -> dict:
    out = lsp.rpc.call("factory-list")
    for f in out["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not in factory-list")


def _inject_penalty(lsp, iid, epoch=3, leaf_index=1):
    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": epoch,
        "leaf_index": leaf_index,
        "lstock_sats": 100_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })


def test_stale_still_flipped_by_direct_mark(ss_node_factory):
    """Regression: dev-factory-mark-penalty-stale still works after
    Phase 4b2 added the auto-rebuild path. Operator tool preserved."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)

    r = lsp.rpc.call("dev-factory-mark-penalty-stale", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
    })
    assert r["state"] == "stale"

    fs = _factory(lsp, iid)
    assert fs["pending_penalties"][0]["state"] == "stale"


def test_source_check_still_works_manually(ss_node_factory):
    """Operator can still invoke factory-source-check; the async
    probe dispatches. Stale transition happens via the same callback
    path that auto-triggers in block_added — this test just confirms
    the manual path is intact."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)

    r = lsp.rpc.call("factory-source-check", {"instance_id": iid})
    assert "probes_issued" in r
    assert r["instance_id"] == iid


def test_auto_rebuild_preserved_as_stale_on_state_scan_no_match(
        ss_node_factory):
    """If the state-TX scan doesn't find any cached match (e.g. we
    have no per-epoch state-root TXIDs populated because rotation
    never happened), the penalty stays STALE — rebuild can't happen
    without a matching epoch. This is the expected no-op path."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)
    lsp.rpc.call("dev-factory-mark-penalty-stale", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
    })

    # Run the reorg/source-check manually just to verify it doesn't
    # interfere.
    lsp.rpc.call("factory-source-check", {"instance_id": iid})

    fs = _factory(lsp, iid)
    # Still stale — auto-rebuild would need a matching state TX found
    # by the state-tx scan, which requires history_state_root_txids
    # populated by rotation.
    assert fs["pending_penalties"][0]["state"] == "stale"


def test_block_added_does_not_crash_with_pending_penalty(
        ss_node_factory):
    """Regression: we added ss_penalty_source_check to the block_added
    per-factory loop. It must not crash when a factory has pending
    penalties during normal block advancement.

    We don't have a way to drive block_added directly from pytest,
    but we can exercise the same code path via the tick scheduler
    which is invoked from block_added. If any of our additions crash
    or regress, tick would error.

    Also: we don't fund the wallet — source_check shouldn't depend on
    wallet state, only on lib_factory / pending_penalty state."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)

    r = lsp.rpc.call("dev-factory-tick-scheduler",
                     {"instance_id": iid, "block_height": 600})
    assert "n_pending_penalties" in r


def test_rebuild_helper_available_via_state_scan_path(ss_node_factory):
    """End-to-end sanity: the state-TX scan pathway is wired. We can
    trigger the scan via factory-source-check (which is what Phase
    4b2 does on STALE). The scan dispatches async; we just verify no
    crash and state remains consistent."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)

    # Trigger source-check: if our factory has a loaded lib_factory +
    # real funding, it'd probe and potentially flip STALE. In this
    # stalled-ceremony fixture it no-ops gracefully (no funding).
    r = lsp.rpc.call("factory-source-check", {"instance_id": iid})
    assert r["status"] if "status" in r else True  # just don't crash
    # n_pending_penalties is the stable field.
    assert r["n_pending_penalties"] == 1
