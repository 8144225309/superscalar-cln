"""Path A / Layer 3 — gcov-driven rejection-path + uncovered-branch
coverage for ARITY_1 / ARITY_2.

Layer 2 (gcov on the L1 suite) flagged these gaps:
  - json_factory_force_close: 58% — bad iid length, factory not
    found, no lib_factory handle paths uncovered
  - apply_allocations_to_leaves: 10% — entire body dead because no
    test passes a non-default allocations array

These tests close the gaps with targeted inputs.
"""
from __future__ import annotations

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
                                   timeout=60.0)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


# --- json_factory_force_close rejection paths ---

def test_force_close_rejects_bad_iid_length(ss_node_factory):
    """Pass 63-char iid; expect length error."""
    lsp = ss_node_factory.get_node()
    with pytest.raises(RpcError, match="Bad instance_id length"):
        lsp.rpc.call("factory-force-close",
                     {"instance_id": "a" * 63})


def test_force_close_rejects_unknown_factory(ss_node_factory):
    """Valid 64-hex iid that doesn't match any tracked factory."""
    lsp = ss_node_factory.get_node()
    with pytest.raises(RpcError, match="Factory not found"):
        lsp.rpc.call("factory-force-close",
                     {"instance_id": "ab" * 32})


# --- apply_allocations_to_leaves: ARITY_1 with custom allocations ---

def test_arity1_custom_allocations_applied(ss_node_factory):
    """factory-create on ARITY_1 (default 2-party) with allocations=[N]
    must rewrite the leaf's client output to N sats. Covers the body
    of apply_allocations_to_leaves which previously only had its
    early-return path executed."""
    funding_sats = 300_000
    requested_alloc = 50_000  # well below default 80% client share

    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)

    iid = lsp.rpc.call("factory-create", {
        "funding_sats": funding_sats,
        "clients": [client.info["id"]],
        "allocations": [requested_alloc],
    })["instance_id"]
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)

    f = next(x for x in lsp.rpc.call("factory-list")["factories"]
             if x["instance_id"] == iid)
    assert f["arity_mode"] == "arity_1"

    # Find the client leaf — leaf with a non-LSP signer
    client_leaves = [
        l for l in f["leaves"]
        if any(s != 0 for s in l["signers"])
    ]
    assert client_leaves, "no client leaf in ARITY_1 factory"
    leaf = client_leaves[0]
    # ARITY_1 leaf has 2 outputs: client + L-stock. The client output
    # comes first (signer order).
    outs = leaf["outputs"]
    assert len(outs) == 2, (
        f"ARITY_1 leaf should have 2 outputs (client + L-stock), "
        f"got {len(outs)}")
    client_amt = outs[0]["amount_sats"]
    # Allow ±2000 sats for tree-fee accounting
    diff = abs(client_amt - requested_alloc)
    assert diff <= 2000, (
        f"requested allocation {requested_alloc} sats but client "
        f"output is {client_amt} sats (diff {diff}) — "
        "apply_allocations_to_leaves didn't rewrite the leaf")

    # And the leaf should also be in signed_txs
    signed = get_signed_txs_for_factory(lsp, iid)
    assert signed, "no signed TXs after ceremony"
    # Pick a 2-output TX (the leaf)
    found_leaf = False
    for raw in signed.values():
        d = decode_tx(lsp, raw.hex())
        if len(d["vout"]) == 2:
            on_chain = output_sats(d)[0]
            if abs(on_chain - requested_alloc) <= 2000:
                found_leaf = True
                break
    assert found_leaf, (
        f"no signed leaf TX has client output near {requested_alloc}; "
        "factory-list reports it but signed TX disagrees — "
        "apply_allocations_to_leaves call didn't propagate to signing")


def test_arity1_custom_allocations_reject_oversize(ss_node_factory):
    """allocations sum > 80% of funding must reject."""
    funding_sats = 200_000
    huge = 200_000  # exceeds 80% cap

    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)

    with pytest.raises(RpcError, match="exceeds 80%"):
        lsp.rpc.call("factory-create", {
            "funding_sats": funding_sats,
            "clients": [client.info["id"]],
            "allocations": [huge],
        })


def test_arity1_custom_allocations_length_mismatch(ss_node_factory):
    """allocations array length must equal n_clients."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)

    with pytest.raises(RpcError, match="allocations length"):
        lsp.rpc.call("factory-create", {
            "funding_sats": 200_000,
            "clients": [client.info["id"]],
            "allocations": [50_000, 50_000],  # 2 entries, 1 client
        })
