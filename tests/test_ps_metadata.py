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


@pytest.mark.xfail(
    reason="apply_allocations_to_leaves does not currently rewrite "
           "ARITY_PS chain[0] outputs; setup_ps_leaf_outputs hardcodes "
           "a 50/50 channel/L-stock split that survives the allocation "
           "pass. Either apply_allocations needs PS-aware logic, or PS "
           "factories should reject the allocations parameter at "
           "factory-create. Filed as design-divergence finding from "
           "Layer 1 PS coverage work.",
    strict=True)
def test_ps_custom_allocations_honored_at_chain0(ss_node_factory):
    """Pass an explicit allocations array to factory-create on an
    ARITY_PS factory and verify chain[0]'s channel output matches the
    requested per-client allocation. With a 1-client factory and
    allocation=[80_000], chain[0]'s channel output should be near
    80_000 sats (post tree fees)."""
    funding_sats = 200_000
    requested_alloc = 80_000  # below the natural ~50/50 split

    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)

    client_id = client.info["id"]
    iid = lsp.rpc.call("factory-create", {
        "funding_sats": funding_sats,
        "clients": [client_id],
        "arity_mode": "arity_ps",
        "allocations": [requested_alloc],
    })["instance_id"]

    # Ceremony completes
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)

    # Find chain[0] (a 2-output TX in signed_txs).
    signed = get_signed_txs_for_factory(lsp, iid)
    chain0_outs = None
    for _node_idx, raw_tx in signed.items():
        decoded = decode_tx(lsp, raw_tx.hex())
        if len(decoded["vout"]) == 2:
            chain0_outs = output_sats(decoded)
            break
    assert chain0_outs, "no 2-output TX found — chain[0] missing"

    # chain[0] outputs are [channel, L-stock]. Channel should be close
    # to the requested allocation. Allow ±2000 sats for tree-fee accounting.
    channel_amt = chain0_outs[0]
    diff = abs(channel_amt - requested_alloc)
    assert diff <= 2000, (
        f"requested allocation {requested_alloc} sats but chain[0] "
        f"channel output is {channel_amt} sats (diff {diff}) — "
        "custom allocation not being applied to PS leaf")
    # L-stock gets the remainder (minus tree fees)
    lstock_amt = chain0_outs[1]
    assert lstock_amt > 100_000, (
        f"L-stock got only {lstock_amt} sats; client took {channel_amt} "
        f"out of {funding_sats} — L-stock should hold the rest")
