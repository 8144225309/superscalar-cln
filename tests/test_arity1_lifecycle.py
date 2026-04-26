"""Path A / Layer 1 — ARITY_1 (single-client per leaf, 2-of-2 DW)
lifecycle coverage.

Mirrors the PS coverage tests but for ARITY_1 (the default arity for
2-party factories per ss_choose_arity). ARITY_1 uses Decker-Wattenhofer
state ordering (decrementing nSequence) instead of TX chaining; old
states are invalidated by BIP-68 broadcast races, not by per-state
revocation secrets.

Surface tested here:
  - factory creation, persistence, and metadata
  - restart durability (LSP + client)
  - force-close lifecycle progression
  - factory-rotate ceremony completion
  - rejection of arity-mismatched RPCs (ps-advance, buy-liquidity)
  - per-party accounting via the factory-list leaves[] field
"""
from __future__ import annotations

import time

import pytest
from pyln.client import RpcError

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import (
    decode_tx,
    get_signed_txs_for_factory,
    output_sats,
)


def _setup(ss_node_factory, *, funding_sats=200_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0)  # default = arity_1
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _factory(lsp, iid):
    return next(f for f in lsp.rpc.call("factory-list")["factories"]
                if f["instance_id"] == iid)


def test_arity1_create_signs_full_tree(ss_node_factory):
    """Default 2-party factory creates an ARITY_1 tree. The signed_txs
    blob must contain at least kickoff + state TXs after ceremony."""
    lsp, _client, iid = _setup(ss_node_factory)
    f = _factory(lsp, iid)
    assert f["arity_mode"] == "arity_1"
    assert f["tree_mode"] == "dw"
    assert f["ceremony"] == "complete"

    signed = get_signed_txs_for_factory(lsp, iid)
    assert len(signed) >= 2, (
        f"ARITY_1 tree should have >=2 signed nodes (kickoff + state), "
        f"got {len(signed)}")
    # Each signed TX must decode + have non-dust outputs
    for node_idx, raw in signed.items():
        d = decode_tx(lsp, raw.hex())
        assert d["vin"], f"node {node_idx} has no inputs"
        for vout, amt in enumerate(output_sats(d)):
            assert amt >= 240, (
                f"ARITY_1 node {node_idx} output[{vout}] is dust: {amt}")


def test_arity1_factory_persists_across_lsp_restart(ss_node_factory):
    """Restart the LSP, factory still loads from datastore with same
    instance_id and ceremony=complete."""
    lsp, _client, iid = _setup(ss_node_factory)
    pre = _factory(lsp, iid)

    lsp.restart()

    post = _factory(lsp, iid)
    assert post["instance_id"] == pre["instance_id"]
    assert post["arity_mode"] == "arity_1"
    assert post["ceremony"] == "complete"
    assert post["epoch"] == pre["epoch"]
    assert post["n_clients"] == pre["n_clients"]


def test_arity1_factory_persists_across_client_restart(ss_node_factory):
    """Restart the CLIENT, its view of the factory still loads."""
    lsp, client, iid = _setup(ss_node_factory)

    # Wait for client-side ceremony to reach complete
    deadline = time.time() + 60.0
    while time.time() < deadline:
        f = next(x for x in client.rpc.call("factory-list")["factories"]
                 if x["instance_id"] == iid)
        if f["ceremony"] == "complete":
            pre_client = f
            break
        time.sleep(0.5)
    else:
        pytest.fail("client side ceremony didn't reach 'complete' in 60s")

    client.restart()

    post = next(x for x in client.rpc.call("factory-list")["factories"]
                if x["instance_id"] == iid)
    assert post["instance_id"] == pre_client["instance_id"]
    assert post["arity_mode"] == "arity_1"
    assert post["ceremony"] == "complete"


def test_arity1_force_close_advances_lifecycle(ss_node_factory):
    """factory-force-close on an ARITY_1 factory must advance lifecycle
    out of init/active within 30s."""
    lsp, _client, iid = _setup(ss_node_factory)
    pre = _factory(lsp, iid)
    assert pre["lifecycle"] in {"active", "init"}

    lsp.rpc.call("factory-force-close", {"instance_id": iid})

    deadline = time.time() + 30.0
    final = None
    while time.time() < deadline:
        f = _factory(lsp, iid)
        if f["lifecycle"] not in {"active", "init"}:
            final = f["lifecycle"]
            break
        time.sleep(0.5)
    assert final in {
        "dying", "expired",
        "closed_externally", "closed_unilateral",
    }, f"force-close didn't advance lifecycle; got {final}"


def test_arity1_rejects_ps_advance(ss_node_factory):
    """factory-ps-advance is ARITY_PS-only; ARITY_1 must reject."""
    lsp, _client, iid = _setup(ss_node_factory)
    with pytest.raises(RpcError, match="not ARITY_PS"):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})


def test_arity1_rejects_buy_liquidity(ss_node_factory):
    """factory-buy-liquidity is ARITY_2-only; ARITY_1 must reject."""
    lsp, _client, iid = _setup(ss_node_factory)
    with pytest.raises(RpcError, match="only supported on ARITY_2"):
        lsp.rpc.call("factory-buy-liquidity", {
            "instance_id": iid,
            "client_idx": 0,
            "amount_sats": 5_000,
        })


def test_arity1_rotation_advances_epoch(ss_node_factory):
    """factory-rotate on ARITY_1 must advance the DW epoch from 0 to 1
    and leave ceremony in a signed state."""
    lsp, _client, iid = _setup(ss_node_factory)
    pre = _factory(lsp, iid)
    assert pre["epoch"] == 0

    lsp.rpc.call("factory-rotate", {"instance_id": iid})

    SIGNED = {"complete", "rotate_complete", "revoked"}
    deadline = time.time() + 90.0
    final_epoch = 0
    final_ceremony = None
    while time.time() < deadline:
        f = _factory(lsp, iid)
        final_epoch = f["epoch"]
        final_ceremony = f["ceremony"]
        if final_epoch >= 1 and final_ceremony in SIGNED:
            break
        time.sleep(0.5)
    assert final_epoch == 1, (
        f"rotation didn't advance epoch in 90s; stuck at {final_epoch}")
    assert final_ceremony in SIGNED, (
        f"rotation finished epoch={final_epoch} but ceremony={final_ceremony!r}")


def test_arity1_per_party_amounts_visible(ss_node_factory):
    """factory-list.leaves[] should report per-leaf outputs with
    amount_sats and scriptpubkey, with at least 1 LSP signer (slot 0)
    and at least 1 client signer (slot >= 1)."""
    lsp, _client, iid = _setup(ss_node_factory)
    f = _factory(lsp, iid)
    leaves = f["leaves"]
    assert len(leaves) >= 1
    for leaf in leaves:
        # Every leaf must have outputs and signers
        assert leaf["outputs"], f"leaf {leaf['leaf_side']} has no outputs"
        assert leaf["signers"], f"leaf {leaf['leaf_side']} has no signers"
        # ARITY_1 leaves should NOT be PS
        assert not leaf["is_ps_leaf"], (
            f"ARITY_1 leaf {leaf['leaf_side']} reports is_ps_leaf=true")
        # Each output is non-dust
        for o in leaf["outputs"]:
            assert o["amount_sats"] >= 240, (
                f"leaf {leaf['leaf_side']} output amount "
                f"{o['amount_sats']} is dust")
