"""E2E tests for Phase 3c2 — CPFP-via-anchor scheduler scaffolding.

Phase 3c2 v1 lands the state machine + scheduler + persistence + dev
RPCs. Actual TX construction (libwally PSBT + CLN signpsbt RPC chain)
is Phase 3c2.5.

These tests verify the contract that the scheduler tracks parent
TXs correctly through the state machine and dispatches "would bump"
intents at the right times. Real on-chain CPFP behavior (parent
actually getting confirmed via package relay) is for Phase 5b regtest
when the construction code lands.
"""
from __future__ import annotations

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


def test_inject_cpfp_persists_and_renders(ss_node_factory):
    """dev-factory-inject-cpfp registers a pending_cpfp_t.
    factory-list surfaces pending_cpfps[] with parent_kind, state,
    txid, anchor_vout, value_at_stake, deadline_block."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = lsp.rpc.call("dev-factory-inject-cpfp", {
        "instance_id": iid,
        "kind": "dist",
        "anchor_vout": 1,
        "value_at_stake": 50_000,
        "deadline_block": 1000,
        "parent_broadcast_block": 100,
    })
    assert r["n_pending_cpfps"] == 1

    fs = _factory(lsp, iid)
    cpfps = fs.get("pending_cpfps", [])
    assert len(cpfps) == 1
    pc = cpfps[0]
    assert pc["parent_kind"] == "dist"
    assert pc["state"] == "pending"
    assert pc["parent_vout_anchor"] == 1
    assert pc["parent_value_at_stake"] == 50_000
    assert pc["deadline_block"] == 1000


def test_scheduler_does_not_bump_until_threshold(ss_node_factory):
    """Scheduler must NOT fire CPFP intent until parent has been
    unconfirmed for >= CPFP_TRIGGER_THRESHOLD_BLOCKS (6). Tick within
    threshold returns intents=0."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-cpfp", {
        "instance_id": iid, "kind": "state", "anchor_vout": 1,
        "value_at_stake": 100_000, "deadline_block": 1000,
        "parent_broadcast_block": 100,
    })

    # Tick 5 blocks later — under threshold.
    r = lsp.rpc.call("dev-factory-tick-cpfp-scheduler",
                     {"instance_id": iid, "block_height": 105})
    assert r["intents"] == 0


def test_scheduler_fires_intent_after_threshold(ss_node_factory):
    """Past CPFP_TRIGGER_THRESHOLD_BLOCKS (6 blocks unconfirmed),
    scheduler fires its 'would bump' intent. V1 logs only; intents
    counter increments to track."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-cpfp", {
        "instance_id": iid, "kind": "kickoff", "anchor_vout": 1,
        "value_at_stake": 200_000, "deadline_block": 500,
        "parent_broadcast_block": 100,
    })

    # Tick 7 blocks later — past threshold. htlc_fee_bump_should_bump
    # returns true on first ever broadcast (last_feerate==0).
    r = lsp.rpc.call("dev-factory-tick-cpfp-scheduler",
                     {"instance_id": iid, "block_height": 107})
    assert r["intents"] == 1


def test_parent_confirmed_marks_resolved(ss_node_factory):
    """When parent confirms without our help (network bumped, OR fee
    was sufficient after all), mark RESOLVED. Scheduler tick after
    that returns intents=0."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-cpfp", {
        "instance_id": iid, "kind": "dist", "anchor_vout": 1,
        "value_at_stake": 100_000, "deadline_block": 1000,
        "parent_broadcast_block": 100,
    })

    lsp.rpc.call("dev-factory-mark-cpfp-parent-confirmed", {
        "instance_id": iid, "anchor_vout": 1, "confirmed_block": 105,
    })

    # Tick to drive the state transition.
    lsp.rpc.call("dev-factory-tick-cpfp-scheduler",
                 {"instance_id": iid, "block_height": 110})

    fs = _factory(lsp, iid)
    pc = fs["pending_cpfps"][0]
    assert pc["state"] == "resolved"
    assert pc["parent_confirmed_block"] == 105

    # Subsequent ticks no-op.
    r = lsp.rpc.call("dev-factory-tick-cpfp-scheduler",
                     {"instance_id": iid, "block_height": 200})
    assert r["intents"] == 0


def test_inject_dedup_by_parent_txid(ss_node_factory):
    """Re-injecting the same parent (same anchor_vout + kind +
    deadline → same synthetic txid) updates rather than duplicates.
    Prevents the cpfp table from filling on re-broadcast loops."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-cpfp", {
        "instance_id": iid, "kind": "dist", "anchor_vout": 1,
        "value_at_stake": 100_000, "deadline_block": 1000,
        "parent_broadcast_block": 100,
    })
    lsp.rpc.call("dev-factory-inject-cpfp", {
        "instance_id": iid, "kind": "dist", "anchor_vout": 1,
        "value_at_stake": 100_000, "deadline_block": 1000,
        "parent_broadcast_block": 100,
    })

    fs = _factory(lsp, iid)
    assert len(fs["pending_cpfps"]) == 1


def test_multiple_parent_kinds_independent(ss_node_factory):
    """Three parents (dist, state, kickoff) registered concurrently.
    Each tracked independently; scheduler fires intents per-entry."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    for kind, vout in [("dist", 1), ("state", 2), ("kickoff", 3)]:
        lsp.rpc.call("dev-factory-inject-cpfp", {
            "instance_id": iid, "kind": kind, "anchor_vout": vout,
            "value_at_stake": 100_000, "deadline_block": 1000,
            "parent_broadcast_block": 100,
        })

    fs = _factory(lsp, iid)
    assert len(fs["pending_cpfps"]) == 3
    kinds = sorted(pc["parent_kind"] for pc in fs["pending_cpfps"])
    assert kinds == ["dist", "kickoff", "state"]

    # All 3 past threshold → 3 intents fired.
    r = lsp.rpc.call("dev-factory-tick-cpfp-scheduler",
                     {"instance_id": iid, "block_height": 110})
    assert r["intents"] == 3
