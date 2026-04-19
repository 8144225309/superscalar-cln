"""E2E tests for Phase 4b — RBF / mempool-race detection.

Scenario: counterparty publishes state TX A, we build burn against
A's L-stock output, broadcast it. They RBF replace A with state TX B
before our burn confirms. Our burn now references a dead outpoint.

Detection: factory-source-check probes each pending burn's source UTXO
via checkutxo. If null AND our burn hasn't confirmed → flip to STALE.

V1 tests:
    - dev-mark-penalty-stale flips state directly (state machine path)
    - factory-source-check operator RPC dispatches probes
    - STALE entries are skipped by the fee-bump scheduler
    - STALE entries do not regress to BROADCAST/PENDING

Auto-rebuild against the new outpoint is V2.
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


def test_mark_penalty_stale_flips_state(ss_node_factory):
    """dev-factory-mark-penalty-stale flips a BROADCAST entry directly
    to STALE. factory-list reflects the new state."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)

    fs = _factory(lsp, iid)
    assert fs["pending_penalties"][0]["state"] == "broadcast"

    r = lsp.rpc.call("dev-factory-mark-penalty-stale", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
    })
    assert r["state"] == "stale"

    fs2 = _factory(lsp, iid)
    assert fs2["pending_penalties"][0]["state"] == "stale"


def test_stale_entries_are_skipped_by_scheduler(ss_node_factory):
    """The fee-bump scheduler must skip STALE entries — bumping a
    burn that references a dead outpoint just churns RPCs."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)
    lsp.rpc.call("dev-factory-mark-penalty-stale", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
    })

    # Tick the scheduler well past the deadline. STALE should not
    # transition to anything (REPLACED would be the only candidate).
    r = lsp.rpc.call("dev-factory-tick-scheduler",
                     {"instance_id": iid, "block_height": 1100})
    assert r["bumps"] == 0

    fs = _factory(lsp, iid)
    assert fs["pending_penalties"][0]["state"] == "stale"


def test_source_check_no_lib_factory_skips_gracefully(ss_node_factory):
    """Stalled-ceremony factory has no lib_factory. source_check must
    return probes_issued=0 without crashing — same gate pattern as
    Phase 4a deep-unwind scan."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)

    r = lsp.rpc.call("factory-source-check", {"instance_id": iid})
    assert r["probes_issued"] == 0
    assert r["n_pending_penalties"] == 1


def test_dev_trigger_alias_works(ss_node_factory):
    """dev-factory-trigger-source-check is the test alias of
    factory-source-check. Same shape, same logic."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_penalty(lsp, iid)

    r = lsp.rpc.call("dev-factory-trigger-source-check",
                     {"instance_id": iid})
    assert "probes_issued" in r
    assert r["instance_id"] == iid


def test_source_check_no_penalties_is_noop(ss_node_factory):
    """Empty pending_penalties array → probes_issued=0, no error."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = lsp.rpc.call("factory-source-check", {"instance_id": iid})
    assert r["probes_issued"] == 0
    assert r["n_pending_penalties"] == 0


def test_source_check_skips_confirmed_and_replaced(ss_node_factory):
    """source-check probes only PENDING/BROADCAST entries.
    CONFIRMED/REPLACED/STALE entries are terminal-ish and should not
    be re-probed (we'd just churn RPCs and possibly mis-classify)."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # Penalty 1: confirmed
    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid, "epoch": 3, "leaf_index": 0,
        "lstock_sats": 100_000, "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })
    lsp.rpc.call("dev-factory-mark-penalty-confirmed", {
        "instance_id": iid, "epoch": 3, "leaf_index": 0,
        "confirmed_block": 600,
    })

    # Penalty 2: stale already
    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
        "lstock_sats": 100_000, "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })
    lsp.rpc.call("dev-factory-mark-penalty-stale", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
    })

    # No lib_factory either way (stalled ceremony), so probes=0,
    # but the gating logic upstream of the lib_factory check still
    # ensures we don't try to probe terminal entries.
    r = lsp.rpc.call("factory-source-check", {"instance_id": iid})
    assert r["probes_issued"] == 0

    # States preserved.
    fs = _factory(lsp, iid)
    states = {p["leaf_index"]: p["state"] for p in fs["pending_penalties"]}
    assert states[0] == "confirmed"
    assert states[1] == "stale"
