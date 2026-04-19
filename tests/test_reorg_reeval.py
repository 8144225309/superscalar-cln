"""E2E tests for Phase 4e — reorg re-evaluation of confirmed penalties.

The algorithm is ported from upstream SuperScalar's
`watchtower_on_reorg`. Core contract:

    For each pending_penalty in state=CONFIRMED:
        if getrawtransaction(burn_txid) errors or reports 0 confs:
            reset confirmed_block = 0
            flip state back to BROADCAST
            (scheduler will re-bump on next tick)

In this test environment the `burn_txid` is synthetic (Phase 3c dev
injection deterministically derives it from epoch+leaf), so bitcoind
has never seen it. getrawtransaction ALWAYS errors for these fake
txids. That's the ideal regtest for the "tx_gone → reset" path — we
mark a penalty confirmed, trigger the reorg-check, and assert the
state flips back.

We also test the gating (non-confirmed entries are ignored) and the
operator-facing factory-reorg-check RPC surface.
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


def _inject_and_confirm_penalty(lsp, iid, epoch=3, leaf_index=1):
    """Set up a pending_penalty_t in CONFIRMED state for the reorg
    check to find. Uses Phase 3c dev injection + mark-confirmed."""
    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": epoch,
        "leaf_index": leaf_index,
        "lstock_sats": 100_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })
    lsp.rpc.call("dev-factory-mark-penalty-confirmed", {
        "instance_id": iid,
        "epoch": epoch,
        "leaf_index": leaf_index,
        "confirmed_block": 950,
    })


def _wait_for_state(lsp, iid, expected_state, timeout=10.0):
    """Poll factory-list.pending_penalties[0].state until matches.
    The reorg check is async (getrawtransaction RPC); state flips in
    the callback. Returns the final state observed (may not match)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        fs = _factory(lsp, iid)
        if fs.get("pending_penalties"):
            last = fs["pending_penalties"][0]["state"]
            if last == expected_state:
                return last
        time.sleep(0.25)
    return last


def test_reorg_check_resets_confirmed_penalty(ss_node_factory):
    """Inject + mark confirmed → trigger reorg check → assert state
    flips back to 'broadcast' because bitcoind doesn't know the
    synthetic burn_txid (treated as 'tx_gone')."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_and_confirm_penalty(lsp, iid)

    # Baseline: state is confirmed before the check runs.
    fs = _factory(lsp, iid)
    assert fs["pending_penalties"][0]["state"] == "confirmed"

    r = lsp.rpc.call("dev-factory-trigger-reorg-check",
                     {"instance_id": iid})
    assert r["probes_issued"] == 1

    # Async callback fires; poll until state transitions.
    final = _wait_for_state(lsp, iid, "broadcast", timeout=10.0)
    assert final == "broadcast", (
        f"expected reorg check to flip state back to 'broadcast', "
        f"got {final!r}"
    )


def test_reorg_check_ignores_non_confirmed_entries(ss_node_factory):
    """A penalty in BROADCAST state (never confirmed) must not get a
    probe — there's nothing to re-validate. probes_issued=0."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # Inject but DO NOT mark confirmed. State stays "broadcast".
    lsp.rpc.call("dev-factory-inject-penalty", {
        "instance_id": iid,
        "epoch": 3,
        "leaf_index": 1,
        "lstock_sats": 100_000,
        "csv_unlock_block": 1000,
        "first_broadcast_block": 500,
    })

    r = lsp.rpc.call("dev-factory-trigger-reorg-check",
                     {"instance_id": iid})
    assert r["probes_issued"] == 0


def test_reorg_check_no_penalties_is_noop(ss_node_factory):
    """Factory with zero pending penalties → probes_issued=0, no
    error. Trivial guard but guards against NULL deref on empty array."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = lsp.rpc.call("dev-factory-trigger-reorg-check",
                     {"instance_id": iid})
    assert r["probes_issued"] == 0
    assert r["n_pending_penalties"] == 0


def test_factory_reorg_check_operator_rpc_works(ss_node_factory):
    """The operator-facing alias factory-reorg-check returns the same
    shape and drives the same logic as dev-factory-trigger-reorg-check.
    This is the RPC operators use from the CLI after observing a reorg
    in their bitcoind logs."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_and_confirm_penalty(lsp, iid, epoch=7, leaf_index=2)

    r = lsp.rpc.call("factory-reorg-check", {"instance_id": iid})
    assert r["probes_issued"] == 1
    assert r["instance_id"] == iid

    # And the reset should still happen asynchronously:
    final = _wait_for_state(lsp, iid, "broadcast", timeout=10.0)
    assert final == "broadcast"


def test_reorg_check_multiple_penalties_probes_each(ss_node_factory):
    """Two confirmed penalties → probes_issued=2 and both get reset
    asynchronously. Guards the loop logic in ss_penalty_reorg_check."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    _inject_and_confirm_penalty(lsp, iid, epoch=3, leaf_index=0)
    _inject_and_confirm_penalty(lsp, iid, epoch=3, leaf_index=1)

    r = lsp.rpc.call("dev-factory-trigger-reorg-check",
                     {"instance_id": iid})
    assert r["probes_issued"] == 2

    # Wait for both entries to flip to broadcast.
    deadline = time.time() + 10.0
    while time.time() < deadline:
        fs = _factory(lsp, iid)
        states = [p["state"] for p in fs["pending_penalties"]]
        if all(s == "broadcast" for s in states):
            return
        time.sleep(0.25)
    fs = _factory(lsp, iid)
    raise AssertionError(
        f"expected both penalties reset to 'broadcast', got states="
        f"{[p['state'] for p in fs['pending_penalties']]}"
    )
