"""PS coverage Layer 1 / Batch 1: metadata + structural tests.

Covers fast-running checks that don't require an advance ceremony:
  - tree_mode='ps' is reported and survives plugin restart
  - Custom allocations on ARITY_PS are honored at chain[0]
  - factory-create with no arity_mode does NOT auto-pick PS
    (current ss_choose_arity returns ARITY_1/ARITY_2; PS is opt-in)
"""
from __future__ import annotations

import pytest

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import (
    decode_tx,
    get_signed_txs_for_factory,
    output_sats,
)


def _setup_ps(ss_node_factory, funding_sats=200_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode="arity_ps")
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def test_tree_mode_ps_survives_lsp_restart(ss_node_factory):
    """factory-list reports tree_mode='ps' AND arity_mode='arity_ps'
    both before and after an LSP restart. The plugin re-derives mode
    from the persisted arity_mode byte; a regression in load could
    silently fall back to default DW."""
    lsp, _client, iid = _setup_ps(ss_node_factory)

    pre = next(f for f in lsp.rpc.call("factory-list")["factories"]
               if f["instance_id"] == iid)
    assert pre["tree_mode"] == "ps"
    assert pre["arity_mode"] == "arity_ps"

    lsp.restart()

    post = next(f for f in lsp.rpc.call("factory-list")["factories"]
                if f["instance_id"] == iid)
    assert post["tree_mode"] == "ps", (
        f"tree_mode regression after restart: {post['tree_mode']}")
    assert post["arity_mode"] == "arity_ps", (
        f"arity_mode regression after restart: {post['arity_mode']}")
    # Identity sanity
    assert post["instance_id"] == pre["instance_id"]
    assert post["n_clients"] == pre["n_clients"]
    assert post["epoch"] == pre["epoch"]


def test_factory_create_default_arity_is_not_ps(ss_node_factory):
    """ARITY_PS is opt-in, never the default. ss_choose_arity returns
    ARITY_1 (n_total <= 2) or ARITY_2 (n_total > 2). A regression that
    silently turns on PS for the default case would surprise operators
    who rely on DW invalidation."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)

    # 2-party (n_total=2) → expect arity_1
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=200_000,
                                   timeout=60.0)  # NO arity_mode passed
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    f = next(x for x in lsp.rpc.call("factory-list")["factories"]
             if x["instance_id"] == iid)
    assert f["arity_mode"] == "arity_1", (
        f"default arity for 2-party should be arity_1, got "
        f"{f['arity_mode']}")
    assert f["tree_mode"] == "dw", (
        "default tree mode should be DW, never auto-PS")


def test_ps_custom_allocations_rejected_at_factory_create(ss_node_factory):
    """ARITY_PS factories must reject the allocations parameter at
    factory-create. apply_allocations_to_leaves doesn't currently
    rewrite chain[0] outputs (setup_ps_leaf_outputs hardcodes a
    50/50 channel/L-stock split), so accepting allocations would
    silently ignore them and surprise operators. Until PS-aware
    allocation logic lands, the RPC must fail-fast with a clear
    message pointing at arity_1 / arity_2 alternatives."""
    from pyln.client import RpcError

    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)

    client_id = client.info["id"]
    with pytest.raises(RpcError, match="not supported for ARITY_PS"):
        lsp.rpc.call("factory-create", {
            "funding_sats": 200_000,
            "clients": [client_id],
            "arity_mode": "arity_ps",
            "allocations": [80_000],
        })
