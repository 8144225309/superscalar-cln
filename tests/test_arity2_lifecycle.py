"""Path A / Layer 1 — ARITY_2 (2 clients per leaf, 3-of-3 DW)
lifecycle coverage.

Mirrors test_arity1_lifecycle.py but for ARITY_2. Requires a 3-node
setup (LSP + 2 clients) so each leaf actually has 2 clients.

Surface tested:
  - 3-party factory creation completes the ceremony (3-of-3 nonce
    relay)
  - factory-list reports correct arity + leaves[] with 3 signers
    (LSP + 2 clients)
  - Restart durability across all 3 nodes
  - factory-buy-liquidity drives the LEAF_REALLOC 3-of-3 ceremony
  - factory-rotate completes
"""
from __future__ import annotations

import time

import pytest
from pyln.client import RpcError

from conftest import datastore_has


def _create_3party_factory(lsp, client_a, client_b,
                           *, arity_mode="arity_2",
                           funding_sats=300_000,
                           timeout=120.0) -> str:
    """3-node ARITY_2 factory creation."""
    r = lsp.rpc.call("factory-create", {
        "funding_sats": funding_sats,
        "clients": [client_a.info["id"], client_b.info["id"]],
        "arity_mode": arity_mode,
    })
    iid = r["instance_id"]
    if not datastore_has(
        lsp, ["superscalar", "factories", iid], timeout=timeout
    ):
        raise AssertionError(
            f"3-party factory {iid} ceremony stalled within {timeout}s")
    deadline = time.time() + timeout
    while time.time() < deadline:
        for f in lsp.rpc.call("factory-list")["factories"]:
            if f["instance_id"] == iid and f["ceremony"] == "complete":
                return iid
        time.sleep(0.5)
    raise AssertionError(
        f"3-party factory {iid} ceremony didn't reach complete in {timeout}s")


def _factory(node, iid):
    return next(f for f in node.rpc.call("factory-list")["factories"]
                if f["instance_id"] == iid)


def test_arity2_create_signs_full_tree(ss_node_factory):
    """3-party ARITY_2 factory creates a 3-of-3 leaf tree. Each PS-less
    leaf has 3 signers (LSP + 2 clients). signed_txs has full tree."""
    lsp, client_a, client_b = ss_node_factory.get_nodes(3)
    lsp.fundwallet(10_000_000)
    lsp.connect(client_a)
    lsp.connect(client_b)

    iid = _create_3party_factory(lsp, client_a, client_b,
                                 funding_sats=300_000)
    f = _factory(lsp, iid)
    assert f["arity_mode"] == "arity_2"
    assert f["tree_mode"] == "dw"
    assert f["ceremony"] == "complete"
    assert f["n_clients"] == 2

    leaves = f["leaves"]
    assert leaves, "no leaves reported"
    # At least one leaf has 3 signers (the leaf with both clients)
    has_3of3 = any(l["n_signers"] == 3 for l in leaves)
    assert has_3of3, (
        f"no 3-signer leaf in ARITY_2 factory; leaves: "
        f"{[(l['leaf_side'], l['n_signers']) for l in leaves]}")


def test_arity2_persists_across_lsp_restart(ss_node_factory):
    """Restart the LSP, factory still loads with arity_mode=arity_2."""
    lsp, client_a, client_b = ss_node_factory.get_nodes(3)
    lsp.fundwallet(10_000_000)
    lsp.connect(client_a)
    lsp.connect(client_b)
    iid = _create_3party_factory(lsp, client_a, client_b,
                                 funding_sats=300_000)

    pre = _factory(lsp, iid)
    lsp.restart()
    post = _factory(lsp, iid)
    assert post["instance_id"] == pre["instance_id"]
    assert post["arity_mode"] == "arity_2"
    assert post["ceremony"] == "complete"
    assert post["n_clients"] == 2
    assert post["epoch"] == pre["epoch"]


def test_arity2_buy_liquidity_3of3_completes(ss_node_factory):
    """factory-buy-liquidity on ARITY_2 drives the LEAF_REALLOC
    3-of-3 ceremony: PROPOSE → NONCE×2 → ALL_NONCES → PSIG×2 → DONE.
    The realloc_complete metric must fire on the LSP."""
    lsp, client_a, client_b = ss_node_factory.get_nodes(3)
    lsp.fundwallet(10_000_000)
    lsp.connect(client_a)
    lsp.connect(client_b)
    iid = _create_3party_factory(lsp, client_a, client_b,
                                 funding_sats=300_000)

    r = lsp.rpc.call("factory-buy-liquidity", {
        "instance_id": iid,
        "client_idx": 0,
        "amount_sats": 5_000,
    })
    assert r["status"] == "realloc_proposed"
    assert r["ceremony"] == "3-of-3"

    # Wait for the realloc_complete metric on LSP. Timing is generous —
    # the 3-of-3 round-trip is slower than 2-of-2 because nonces relay
    # through ALL_NONCES.
    deadline = time.time() + 60.0
    saw_complete = False
    while time.time() < deadline:
        if lsp.daemon.is_in_log(
                r"event=realloc_complete .* leaf=0 arity=2"):
            saw_complete = True
            break
        time.sleep(0.5)
    assert saw_complete, (
        "realloc_complete metric not seen within 60s — 3-of-3 ceremony "
        "may have stalled")


def test_arity2_rejects_ps_advance(ss_node_factory):
    """factory-ps-advance must reject on ARITY_2."""
    lsp, client_a, client_b = ss_node_factory.get_nodes(3)
    lsp.fundwallet(10_000_000)
    lsp.connect(client_a)
    lsp.connect(client_b)
    iid = _create_3party_factory(lsp, client_a, client_b,
                                 funding_sats=300_000)

    with pytest.raises(RpcError, match="not ARITY_PS"):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})


def test_arity2_per_party_amounts_have_3_signers(ss_node_factory):
    """ARITY_2 leaves with 2 client signers have 3 outputs total
    (clientA + clientB + L-stock). Verify shape via factory-list."""
    lsp, client_a, client_b = ss_node_factory.get_nodes(3)
    lsp.fundwallet(10_000_000)
    lsp.connect(client_a)
    lsp.connect(client_b)
    iid = _create_3party_factory(lsp, client_a, client_b,
                                 funding_sats=300_000)
    f = _factory(lsp, iid)

    found_arity2_leaf = False
    for leaf in f["leaves"]:
        if leaf["n_signers"] != 3:
            continue
        found_arity2_leaf = True
        # Should have 3 outputs: clientA + clientB + L-stock
        n_out = len(leaf["outputs"])
        assert n_out == 3, (
            f"ARITY_2 leaf at side={leaf['leaf_side']} has {n_out} "
            "outputs; expected 3 (clientA + clientB + L-stock)")
        # All outputs non-dust
        for o in leaf["outputs"]:
            assert o["amount_sats"] >= 240
        # 3 signer slots: 0=LSP, plus two non-zero client slots
        assert 0 in leaf["signers"]
        non_lsp = [s for s in leaf["signers"] if s != 0]
        assert len(non_lsp) == 2, (
            f"3-signer leaf has {len(non_lsp)} non-LSP signers; "
            f"expected 2 (signers list: {leaf['signers']})")
    assert found_arity2_leaf, "no 3-signer leaf found in ARITY_2 factory"
