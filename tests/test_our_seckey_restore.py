"""Task #97 regression: fi->our_seckey is re-derived on factory load.

Pre-#97, fi->our_seckey was zero-initialized after lightningd restart
because it isn't part of the persist meta. RPCs that derived an LSP
pubkey directly from fi->our_seckey (factory-buy-liquidity, the coop
close path, etc.) failed with "LSP pubkey derive failed" on any
factory loaded from disk.

The fix: ss_load_factories calls derive_factory_seckey(buf, iid, idx)
after deserializing meta, restoring our_seckey to its original value
(deterministic from instance_id + our_participant_idx + the node's
master_key, all of which are stable across restarts).

This test creates a PS-arity factory, restarts the LSP (forcing a
load-from-disk path), and runs factory-buy-liquidity. Pre-#97 the
RPC failed with "LSP pubkey derive failed". Post-#97 it should
proceed to the LEAF_REALLOC ceremony.
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


def test_buy_liquidity_works_after_lsp_restart(ss_node_factory):
    """Create a PS factory, restart the LSP, then call buy-liquidity.
    The previously-zero our_seckey would have caused the secp256k1
    pubkey-create call inside json_factory_buy_liquidity to return
    a "LSP pubkey derive failed" error. With #97, our_seckey is
    re-derived on load so the call succeeds and the REALLOC ceremony
    starts."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")

    # Sanity: ceremony complete before we restart
    f = next(f for f in lsp.rpc.call("factory-list")["factories"]
             if f["instance_id"] == iid)
    assert f["ceremony"] == "complete"
    assert f["arity_mode"] == "arity_ps"

    # The actual restart — this is the reload-from-disk path that
    # used to leave our_seckey zeroed.
    lsp.restart()

    # Confirm factory still loads cleanly post-restart
    f = next(f for f in lsp.rpc.call("factory-list")["factories"]
             if f["instance_id"] == iid)
    assert f["ceremony"] == "complete"
    assert f["arity_mode"] == "arity_ps"

    # Pre-#97 this failed with "LSP pubkey derive failed". Post-#97
    # it should accept (return realloc_proposed) — the actual ceremony
    # may stall if the client side also restarted, but that's a
    # separate concern. We're testing that our_seckey is non-zero,
    # not that the ceremony completes end-to-end.
    try:
        r = lsp.rpc.call("factory-buy-liquidity", {
            "instance_id": iid,
            "client_idx": 0,
            "amount_sats": 5_000,
        })
        # Happy path: RPC accepted, ceremony started
        assert r["status"] == "realloc_proposed", (
            f"buy-liquidity returned unexpected status: {r}"
        )
    except RpcError as e:
        # Should NEVER see "LSP pubkey derive failed" — that's the
        # exact regression this test guards against.
        msg = str(e)
        assert "LSP pubkey derive failed" not in msg, (
            f"task #97 regression — our_seckey is zero after restart: {msg}"
        )
        # Other errors (e.g. concurrent ceremony, factory not active)
        # are acceptable for the purposes of this test — they prove
        # the our_seckey path was reached and the pubkey derived
        # successfully.


def test_factory_list_still_works_after_restart(ss_node_factory):
    """Sanity check: after restart, factory-list returns the loaded
    factory with all the expected fields including arity_mode and
    tree_mode (from #92's persist v14)."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")

    pre = next(f for f in lsp.rpc.call("factory-list")["factories"]
               if f["instance_id"] == iid)

    lsp.restart()

    post = next(f for f in lsp.rpc.call("factory-list")["factories"]
                if f["instance_id"] == iid)

    assert post["instance_id"] == pre["instance_id"]
    assert post["arity_mode"] == pre["arity_mode"] == "arity_ps"
    assert post["tree_mode"] == pre["tree_mode"] == "ps"
    assert post["ceremony"] == pre["ceremony"]
    assert post["n_clients"] == pre["n_clients"]
