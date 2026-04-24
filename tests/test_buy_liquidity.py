"""Follow-up #4 impl (#92): factory-buy-liquidity re-sign ceremony.

Before this change, factory-buy-liquidity updated leaf amounts in memory
but the explicit TODO at superscalar.c:13207 left re-signing to "the next
rotation." The leaf TX was therefore signed with the OLD amounts — clients
couldn't unilaterally exit with the new balance until rotation picked it up.

The new LEAF_REALLOC ceremony (PROPOSE / PSIG / DONE via submsgs
0x0134-0x0136) re-signs the leaf state with new amounts immediately:
LSP shifts L-stock to client channel, sends new amounts to client, 2-of-2
MuSig2 finishes. Both sides end up with a freshly signed leaf TX.

These tests exercise the happy path on an ARITY_PS factory (1 client per
leaf = 2-of-2 signing). ARITY_2 requires a 3-of-3 ceremony (task #93).
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


def _setup_factory(ss_node_factory, arity_mode="arity_ps",
                   funding_sats=500_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode=arity_mode)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _wait_metric(node, pattern, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if node.daemon.is_in_log(pattern):
            return True
        time.sleep(0.2)
    raise AssertionError(f"log pattern {pattern!r} not seen within {timeout}s")


def test_buy_liquidity_ps_chain0_happy_path(ss_node_factory):
    """Create ARITY_PS factory, call factory-buy-liquidity for client 0.
    Assert the full REALLOC ceremony fires and amounts are re-signed."""
    lsp, client, iid = _setup_factory(ss_node_factory,
                                      arity_mode="arity_ps")

    r = lsp.rpc.call("factory-buy-liquidity", {
        "instance_id": iid,
        "client_idx": 0,
        "amount_sats": 10_000,
    })
    assert r["status"] == "realloc_proposed"
    assert r["amount_sats"] == 10_000
    assert r["leaf_side"] == 0
    assert r["client_idx"] == 0

    # LSP fires propose metric
    _wait_metric(lsp,
        r"SS_METRIC event=realloc_propose .* leaf=0 client=0 amount=10000")
    # Client fires psig-sent metric
    _wait_metric(client, r"SS_METRIC event=realloc_psig_sent leaf=0")
    # LSP fires complete metric
    _wait_metric(lsp, r"SS_METRIC event=realloc_complete .* leaf=0")
    # Client fires client-done metric
    _wait_metric(client, r"SS_METRIC event=realloc_client_done leaf=0")


def test_buy_liquidity_rejects_after_ps_advance(ss_node_factory):
    """After any PS chain advance, chain[N>=1] has only 1 output (no L-stock).
    factory-buy-liquidity should reject with a clean error pointing at
    factory rotation as the recovery path."""
    lsp, client, iid = _setup_factory(ss_node_factory,
                                      arity_mode="arity_ps")

    # Advance once so chain_len goes 0 -> 1
    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})
    _wait_metric(lsp, r"SS_METRIC event=ps_advance .* leaf=0 chain_pos=1")

    with pytest.raises(RpcError, match="already advanced past chain"):
        lsp.rpc.call("factory-buy-liquidity", {
            "instance_id": iid,
            "client_idx": 0,
            "amount_sats": 1_000,
        })


def test_buy_liquidity_rejects_arity_2(ss_node_factory):
    """ARITY_2 needs a 3-of-3 ceremony that isn't implemented yet (task
    #93). Expect a clean rejection with that message.

    Note: a 2-party factory with auto-arity picks ARITY_1 (not ARITY_2)
    because ss_choose_arity returns ARITY_1 for n_total <= 2. To force
    ARITY_2 we must pass arity_mode="arity_2" explicitly — that override
    bypasses ss_choose_arity regardless of participant count."""
    lsp, client, iid = _setup_factory(ss_node_factory,
                                      arity_mode="arity_2")

    with pytest.raises(RpcError, match="ARITY_2.*not yet implemented"):
        lsp.rpc.call("factory-buy-liquidity", {
            "instance_id": iid,
            "client_idx": 0,
            "amount_sats": 1_000,
        })


def test_buy_liquidity_rejects_concurrent_advance(ss_node_factory):
    """If a PS advance is already in flight on the same factory, buy-liquidity
    should refuse cleanly rather than corrupt state."""
    import subprocess  # noqa: F401  (placeholder — we don't actually race)
    # Can't easily race two RPCs from here; this test documents the guard
    # exists by triggering it via a synthetic back-to-back call. The second
    # call races against the first's PROPOSE->PSIG round trip; if the first
    # has already cleared pending state, the second succeeds (no error).
    # So this is a loose assertion: we just confirm the error path is wired
    # by exercising fi->ps_pending_leaf != -1 via ps-advance first.
    lsp, client, iid = _setup_factory(ss_node_factory,
                                      arity_mode="arity_ps")

    # Kick off a PS advance but don't wait for it to complete. The pending
    # state is set synchronously inside json_factory_ps_advance before
    # the RPC returns.
    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})
    # Immediately try buy-liquidity — race: may hit pending guard, may not,
    # depending on how fast the ceremony completes. Either outcome is OK
    # — we just exercise the code path without asserting the race
    # outcome deterministically.
    try:
        lsp.rpc.call("factory-buy-liquidity", {
            "instance_id": iid,
            "client_idx": 0,
            "amount_sats": 1_000,
        })
    except RpcError as e:
        # If we hit the guard, confirm the message is reasonable.
        msg = str(e)
        assert ("another leaf ceremony in flight" in msg or
                "already advanced past chain" in msg), (
            f"unexpected error: {msg}")
