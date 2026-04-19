"""E2E tests for Phase 4a — proactive deep-unwind detection.

The Phase 3b classifier infrastructure already handles the `state TX
matches cached root` branch; Phase 4a's contribution is to run that
scan on every block_added (not just when SIGNAL_UTXO_SPENT fires),
closing the trustless gap where a counterparty confirms a state TX in
a block our plugin missed.

What we can test deterministically here (no real chain state):
    1. The proactive scan respects its gates — stalled-ceremony
       factories with no lib_factory are skipped cleanly
    2. The scan does NOT crash when triggered on a fresh factory
    3. factory-create + scan trigger is a non-regression on the
       existing Phase 3b/3c state machine

Algorithm correctness under real chain state will be covered by
regtest fixtures in Phase 5b.
"""
from __future__ import annotations

FAKE_CLIENT_ID = "02" + "00" * 32


def _create_factory(lsp, funding_sats: int = 100_000) -> str:
    r = lsp.rpc.call(
        "factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]},
    )
    return r["instance_id"]


def test_deep_unwind_scan_skips_stalled_ceremony(ss_node_factory):
    """Stalled-ceremony factory has no funding TX yet → scan MUST
    no-op with skipped="no_funding". factory-create builds the tree
    (lib_factory + nodes) immediately so we can't gate on that alone;
    real funding lands later, after NONCE exchange completes. The
    scan is pointless before funding confirms, so no_funding is the
    earliest valid gate."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = lsp.rpc.call("dev-factory-trigger-deep-unwind-scan",
                     {"instance_id": iid})
    assert "skipped" in r
    assert r["skipped"] == "no_funding"


def test_deep_unwind_scan_skips_closed_factory(ss_node_factory):
    """Once lifecycle is closed_*, the scan is redundant (classifier
    already latched). Skip cleanly."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # Drive to closed_cooperative via dist_txid_matched (Phase 3b).
    lsp.rpc.call("dev-factory-set-signal",
                 {"instance_id": iid, "signal": "dist_txid_matched"})

    r = lsp.rpc.call("dev-factory-trigger-deep-unwind-scan",
                     {"instance_id": iid})
    # Could be skipped for any of: no_funding (never funded),
    # lifecycle_closed (just set), or no_lib_factory. All are correct
    # — the contract is "does not launch the scan."
    assert "skipped" in r
    assert r["skipped"] in {
        "no_funding", "lifecycle_closed", "no_lib_factory",
    }


def test_deep_unwind_scan_trigger_rpc_stable(ss_node_factory):
    """Calling the trigger RPC with a default window and a custom
    window both succeed (argument handling)."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r1 = lsp.rpc.call("dev-factory-trigger-deep-unwind-scan",
                      {"instance_id": iid})
    assert r1["window"] == 2  # default

    r2 = lsp.rpc.call("dev-factory-trigger-deep-unwind-scan",
                      {"instance_id": iid, "window": 144})
    assert r2["window"] == 144


def test_deep_unwind_scan_does_not_regress_phase_3b(ss_node_factory):
    """Non-regression: trigger the proactive scan on a fresh factory,
    then inject a utxo_spent signal. Lifecycle should still flip to
    closed_externally — the scan path hasn't interfered with the
    classifier."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-trigger-deep-unwind-scan",
                 {"instance_id": iid})
    r = lsp.rpc.call("dev-factory-set-signal",
                     {"instance_id": iid, "signal": "utxo_spent"})
    assert r["lifecycle"] == "closed_externally"
