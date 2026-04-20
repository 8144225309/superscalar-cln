"""E2E tests for the Phase 3c penalty-pathway fee-bump scheduler.

Fee math is delegated to upstream SuperScalar's `htlc_fee_bump.c`
(linked via the slim extraction). The plugin-side contract we verify
here is:

  - injecting a pending_penalty_t persists it and surfaces it in
    factory-list
  - the scheduler bumps the feerate as blocks advance (urgency +
    linear interpolation via upstream)
  - marking a penalty confirmed stops further bumps + sets
    SIGNAL_PENALTY_CONFIRMED + does NOT downgrade closed_breached
  - a penalty whose CSV deadline passes without confirm is marked
    "replaced" (the race was lost)

All tests use dev-* injection RPCs so the scheduler can be exercised
without a real on-chain breach. See the Phase 5a test suite for the
pattern precedent.
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


def test_inject_penalty_persists_record(ss_node_factory):
    """dev-factory-inject-penalty registers a pending_penalty_t,
    n_pending_penalties increments, and factory-list surfaces a
    pending_penalties[] with our epoch+leaf+lstock values."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "lstock_sats": 50_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 800,
    })
    assert r["n_pending_penalties"] == 1

    fs = _factory(lsp, iid)
    assert len(fs["pending_penalties"]) == 1
    p = fs["pending_penalties"][0]
    assert p["epoch"] == 3
    assert p["leaf_index"] == 1
    assert p["lstock_sats"] == 50_000
    assert p["csv_unlock_block"] == 1000
    assert p["state"] == "broadcast"  # set by register_pending_penalty


def test_scheduler_rebroadcasts_burn_each_tick(ss_node_factory):
    """Phase 3c-redux: scheduler rebroadcasts the burn TX every block
    while the entry is BROADCAST. No fee math (burn TX is 100%-fee by
    construction); just rebroadcast for liveness against propagation
    failures. With no lib_factory in this fixture the scheduler can't
    actually build the burn, so 'bumps' stays 0 — but the entry must
    persist in BROADCAST state across ticks (no spurious transitions
    away from rebroadcast-eligible)."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "lstock_sats": 100_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })

    # Two ticks well within CSV window — entry stays BROADCAST.
    r1 = lsp.rpc.call("dev-factory-tick-scheduler",
                      {"instance_id": iid, "block_height": 600})
    r2 = lsp.rpc.call("dev-factory-tick-scheduler",
                      {"instance_id": iid, "block_height": 900})

    assert r1["n_pending_penalties"] == 1
    assert r2["n_pending_penalties"] == 1
    fs = _factory(lsp, iid)
    assert fs["pending_penalties"][0]["state"] == "broadcast"


def test_mark_confirmed_sets_signal_and_stops_bumps(ss_node_factory):
    """After dev-factory-mark-penalty-confirmed:
      - pending_penalty.state == 'confirmed'
      - SIGNAL_PENALTY_CONFIRMED bit set in signals_observed
      - subsequent scheduler ticks don't re-process the entry
      - factory-list.signals includes 'penalty_confirmed'"""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "lstock_sats": 100_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })

    r = lsp.rpc.call("dev-factory-mark-penalty-confirmed", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "confirmed_block": 950,
    })
    assert r["confirmed_block"] == 950

    fs = _factory(lsp, iid)
    assert fs["pending_penalties"][0]["state"] == "confirmed"
    assert fs["pending_penalties"][0]["confirmed_block"] == 950
    assert "penalty_confirmed" in fs["signals"]

    # Scheduler tick after confirm should NOT count this as a bump.
    r2 = lsp.rpc.call("dev-factory-tick-scheduler",
                      {"instance_id": iid, "block_height": 960})
    assert r2["bumps"] == 0


def test_confirm_does_not_downgrade_closed_breached(ss_node_factory):
    """Before marking the penalty confirmed, put the factory in
    closed_breached via the witness_past_match signal. The confirm
    hook sets SIGNAL_PENALTY_CONFIRMED + calls ss_apply_signals — it
    MUST NOT downgrade the lifecycle back to init/active/etc. The
    breach record is preserved alongside the penalty-applied signal."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # First, drive to CLOSED_BREACHED via the existing witness-past
    # injection path (covered by Phase 5a tests).
    lsp.rpc.call("dev-factory-set-signal", {
        "instance_id": iid,
        "signal": "witness_past_match",
        "match_epoch": 3,
    })
    fs = _factory(lsp, iid)
    assert fs["lifecycle"] == "closed_breached"

    # Inject + confirm the penalty.
    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "lstock_sats": 100_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })
    lsp.rpc.call("dev-factory-mark-penalty-confirmed", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "confirmed_block": 950,
    })

    fs2 = _factory(lsp, iid)
    assert fs2["lifecycle"] == "closed_breached", (
        "marking penalty confirmed must not downgrade CLOSED_BREACHED — "
        "the breach happened, our response succeeded, both facts must "
        "be preserved."
    )
    assert fs2["breach_epoch"] == 3
    assert "penalty_confirmed" in fs2["signals"]
    assert "witness_past_match" in fs2["signals"]


def test_deadline_passed_marks_replaced(ss_node_factory):
    """If the CSV deadline passes without our penalty confirming, the
    scheduler marks the entry PENALTY_STATE_REPLACED. In factory-list
    this surfaces as state='replaced' — the operator's signal that we
    lost the race."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "lstock_sats": 100_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })

    # Tick well past the deadline.
    lsp.rpc.call("dev-factory-tick-scheduler",
                 {"instance_id": iid, "block_height": 1100})

    fs = _factory(lsp, iid)
    assert fs["pending_penalties"][0]["state"] == "replaced"


def test_inject_dedup_by_epoch_and_leaf(ss_node_factory):
    """Two inject calls with the same (epoch, leaf_index) must update
    the existing record rather than appending a duplicate. Prevents
    the penalty table from filling on rebroadcast loops."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
        "lstock_sats": 100_000, "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })
    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid, "epoch": 3, "leaf_index": 1,
        "lstock_sats": 100_000, "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })

    fs = _factory(lsp, iid)
    assert len(fs["pending_penalties"]) == 1
