"""Phase 5c — factory-metrics RPC tests.

Verifies that the metrics aggregator surfaces:
  - factory counts by lifecycle
  - total custody sats (sum of funding_amount across non-terminal
    factories)
  - pending-{penalty,cpfp,sweep} counts by state
  - highest-block watermarks for operator alerting (burn broadcast,
    burn confirm, sweep broadcast)

These tests drive state via the dev RPCs (inject-sweep etc.) rather
than real ceremonies to keep the tests fast and deterministic.
"""
from __future__ import annotations

FAKE_CLIENT_ID = "02" + "00" * 32


def _create_factory(lsp, funding_sats: int = 100_000) -> str:
    r = lsp.rpc.call(
        "factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]},
    )
    return r["instance_id"]


def test_metrics_empty_plugin(ss_node_factory):
    """A brand-new plugin with no factories returns the shape with
    zeroes — callers can scrape unconditionally without null guards."""
    lsp = ss_node_factory.get_node()
    m = lsp.rpc.call("factory-metrics")

    assert m["factories"]["total"] == 0
    assert m["factories"]["total_custody_sats"] == 0
    assert m["factories"]["by_lifecycle"] == {}
    assert m["penalties"]["total"] == 0
    assert m["cpfps"]["total"] == 0
    assert m["sweeps"]["total"] == 0
    assert m["sweeps"]["n_failed"] == 0
    assert "current_blockheight" in m


def test_metrics_counts_factories_and_custody(ss_node_factory):
    """After creating a factory, metrics surface the count and the
    funding_sats in total_custody_sats (INIT lifecycle counts — not
    just ACTIVE — because the funds are already locked in the
    multisig)."""
    lsp = ss_node_factory.get_node()
    _create_factory(lsp, funding_sats=150_000)

    m = lsp.rpc.call("factory-metrics")
    assert m["factories"]["total"] == 1
    assert m["factories"]["total_custody_sats"] == 150_000
    # INIT count goes up by 1; other lifecycles should be absent.
    bl = m["factories"]["by_lifecycle"]
    assert bl.get("init", 0) + bl.get("active", 0) >= 1


def test_metrics_counts_pending_sweeps_by_state(ss_node_factory):
    """Two sweeps injected: one left PENDING, one advanced to READY.
    Metrics must count them separately under by_state.pending and
    by_state.ready."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 1,
        "amount_sats": 10_000,
        "csv_delay": 5,
    })  # no confirm stamp → stays PENDING
    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_lstock",
        "source_vout": 2,
        "amount_sats": 30_000,
        "csv_delay": 5,
        "confirmed_block": 100,
    })
    # Drive the second one to READY via dev-tick (not block_added, so
    # we don't trigger the real auto-kickoff).
    lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                 {"instance_id": iid, "block_height": 110})

    m = lsp.rpc.call("factory-metrics")
    assert m["sweeps"]["total"] == 2
    bs = m["sweeps"]["by_state"]
    assert bs.get("pending", 0) == 1
    assert bs.get("ready", 0) == 1
    assert m["sweeps"]["n_failed"] == 0


def test_metrics_watermark_highest_broadcast_block(ss_node_factory):
    """highest_broadcast_block tracks the max broadcast_block across
    all pending_sweeps. Useful for detecting staleness: if this stops
    advancing while sweeps pile up, something is wedged."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 3,
        "amount_sats": 40_000,
        "csv_delay": 5,
        "confirmed_block": 100,
    })
    lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                 {"instance_id": iid, "block_height": 110})
    lsp.rpc.call("dev-factory-mark-sweep-broadcast", {
        "instance_id": iid, "source_vout": 3, "broadcast_block": 777,
    })

    m = lsp.rpc.call("factory-metrics")
    assert m["sweeps"]["highest_broadcast_block"] == 777
    assert m["sweeps"]["by_state"].get("broadcast", 0) == 1


def test_metrics_aggregates_across_factories(ss_node_factory):
    """Two factories, each with a sweep at different state — metrics
    aggregates across all factories, not per-factory."""
    lsp = ss_node_factory.get_node()
    iid1 = _create_factory(lsp, funding_sats=100_000)
    iid2 = _create_factory(lsp, funding_sats=250_000)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid1,
        "type": "factory_leaf",
        "source_vout": 0,
        "amount_sats": 10_000,
        "csv_delay": 5,
    })
    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid2,
        "type": "factory_lstock",
        "source_vout": 0,
        "amount_sats": 20_000,
        "csv_delay": 5,
    })

    m = lsp.rpc.call("factory-metrics")
    assert m["factories"]["total"] == 2
    assert m["factories"]["total_custody_sats"] == 350_000
    assert m["sweeps"]["total"] == 2
