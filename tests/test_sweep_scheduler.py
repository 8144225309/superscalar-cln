"""E2E tests for Phase 4d — CSV claim scheduler (state machine).

Algorithm ported from upstream sweeper.c. Phase 4d v1 lands the
state machine + persistence; actual sweep-TX construction is deferred
to 4d2. These tests drive the state transitions via dev RPCs and
assert the scheduler advances entries correctly:

    inject → PENDING → READY (after source confirm + CSV) →
      BROADCAST (via 4d2 integration hook / dev-mark) →
      CONFIRMED (after sweep conf threshold)
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


def test_inject_sweep_creates_pending_entry(ss_node_factory):
    """dev-factory-inject-sweep registers a pending_sweep_t.
    factory-list surfaces it with state=pending (no confirmed_block)."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 0,
        "amount_sats": 50_000,
        "csv_delay": 144,
    })
    assert r["n_pending_sweeps"] == 1

    fs = _factory(lsp, iid)
    sweeps = fs.get("pending_sweeps", [])
    assert len(sweeps) == 1
    s = sweeps[0]
    assert s["type"] == "factory_leaf"
    assert s["state"] == "pending"
    assert s["source_vout"] == 0
    assert s["amount_sats"] == 50_000
    assert s["csv_delay"] == 144


def test_pending_to_ready_requires_source_confirm_and_csv(ss_node_factory):
    """Scheduler tick advances PENDING → READY only when:
      (a) source_txid is confirmed (confirmed_block > 0), AND
      (b) current block >= confirmed_block + csv_delay.
    Asserting both gates exercise the conjunction."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # Inject with confirmed_block already stamped — ready to age.
    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 1,
        "amount_sats": 50_000,
        "csv_delay": 100,
        "confirmed_block": 1000,
    })

    # Tick BEFORE CSV matures: 1000 + 100 = 1100; tick at 1050 → no move.
    r1 = lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                      {"instance_id": iid, "block_height": 1050})
    assert r1["transitions"] == 0
    fs = _factory(lsp, iid)
    assert fs["pending_sweeps"][0]["state"] == "pending"

    # Tick at maturity (1100): should transition to READY.
    r2 = lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                      {"instance_id": iid, "block_height": 1100})
    assert r2["transitions"] == 1
    fs2 = _factory(lsp, iid)
    assert fs2["pending_sweeps"][0]["state"] == "ready"


def test_no_confirm_stays_pending(ss_node_factory):
    """If the source TX never confirms, scheduler MUST leave entries
    in PENDING regardless of block height advancement."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_timeout",
        "source_vout": 2,
        "amount_sats": 50_000,
        "csv_delay": 10,
    })  # no confirmed_block

    r = lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                     {"instance_id": iid, "block_height": 10_000})
    assert r["transitions"] == 0
    fs = _factory(lsp, iid)
    assert fs["pending_sweeps"][0]["state"] == "pending"


def test_ready_to_broadcast_via_mark_hook(ss_node_factory):
    """Simulates Phase 4d2 integration: READY entry gets marked
    BROADCAST with a synthetic sweep_txid. Scheduler transitions on
    subsequent ticks don't move broadcast entries backwards."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_lstock",
        "source_vout": 0,
        "amount_sats": 30_000,
        "csv_delay": 50,
        "confirmed_block": 500,
    })
    lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                 {"instance_id": iid, "block_height": 550})  # → READY

    lsp.rpc.call("dev-factory-mark-sweep-broadcast", {
        "instance_id": iid, "source_vout": 0, "broadcast_block": 555,
    })
    fs = _factory(lsp, iid)
    assert fs["pending_sweeps"][0]["state"] == "broadcast"
    assert fs["pending_sweeps"][0]["broadcast_block"] == 555

    # Advancing blocks without confirm shouldn't regress state.
    lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                 {"instance_id": iid, "block_height": 600})
    fs2 = _factory(lsp, iid)
    assert fs2["pending_sweeps"][0]["state"] == "broadcast"


def test_broadcast_to_confirmed_requires_conf_threshold(ss_node_factory):
    """Upstream sweeper requires >=3 confs to drop an entry. We mirror
    that: mark sweep_confirmed_block, then scheduler tick must be at
    confirmed_block + 2 (2 later blocks = 3 confs total) to transition
    to CONFIRMED."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 5,
        "amount_sats": 20_000,
        "csv_delay": 10,
        "confirmed_block": 100,
    })
    lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                 {"instance_id": iid, "block_height": 110})
    lsp.rpc.call("dev-factory-mark-sweep-broadcast", {
        "instance_id": iid, "source_vout": 5, "broadcast_block": 111,
    })
    lsp.rpc.call("dev-factory-mark-sweep-confirmed", {
        "instance_id": iid, "source_vout": 5,
        "sweep_confirmed_block": 112,
    })

    # Tick at confirmed_block (112) = 1 conf — not enough.
    r1 = lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                      {"instance_id": iid, "block_height": 112})
    assert r1["transitions"] == 0

    # Tick at confirmed_block + 2 (114) = 3 confs — transition.
    r2 = lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                      {"instance_id": iid, "block_height": 114})
    assert r2["transitions"] == 1
    fs = _factory(lsp, iid)
    assert fs["pending_sweeps"][0]["state"] == "confirmed"


def test_inject_dedup_by_source_vout(ss_node_factory):
    """Two injects with the same (source_txid, source_vout) update
    the existing entry, not append. Protects against double-tracking
    when a source is registered from multiple paths."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid, "type": "factory_leaf", "source_vout": 0,
        "amount_sats": 10_000, "csv_delay": 50,
    })
    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid, "type": "factory_leaf", "source_vout": 0,
        "amount_sats": 15_000, "csv_delay": 60,
    })

    fs = _factory(lsp, iid)
    assert len(fs["pending_sweeps"]) == 1
    # Amount + csv refreshed to the second injection's values.
    assert fs["pending_sweeps"][0]["amount_sats"] == 15_000
    assert fs["pending_sweeps"][0]["csv_delay"] == 60
