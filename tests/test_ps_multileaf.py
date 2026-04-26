"""PS coverage Layer 1 / Batch 4: multi-leaf independence.

3-node setup (LSP + 2 clients) where the ARITY_PS factory has multiple
client leaves. Advancing one leaf's chain must not perturb the other
leaf's chain state. Without this property, a single client's activity
could break their peer's leaf.
"""
from __future__ import annotations

import time

from conftest import datastore_has
from _accounting import (
    get_ps_chain_entry,
    wait_metric,
)


def _create_3party_ps_factory(lsp, client_a, client_b,
                              funding_sats=300_000,
                              timeout=120.0) -> str:
    """3-node ARITY_PS factory creation. Mirrors create_two_party_factory
    but with 2 clients in the ceremony."""
    lsp.rpc.call("factory-create", {
        "funding_sats": funding_sats,
        "clients": [client_a.info["id"], client_b.info["id"]],
        "arity_mode": "arity_ps",
    })
    # Find the iid via factory-list (factory-create returns it but we
    # need to wait for the ceremony anyway)
    deadline = time.time() + 5.0
    iid = None
    while time.time() < deadline:
        for f in lsp.rpc.call("factory-list")["factories"]:
            if f["arity_mode"] == "arity_ps" \
                    and f["n_clients"] == 2 \
                    and f["ceremony"] != "complete":
                iid = f["instance_id"]
                break
        if iid:
            break
        time.sleep(0.2)
    assert iid is not None, "couldn't find newly-created PS factory"
    if not datastore_has(
        lsp, ["superscalar", "factories", iid], timeout=timeout
    ):
        raise AssertionError(
            f"3-party PS factory {iid} ceremony stalled within {timeout}s")
    # Wait for ceremony complete
    deadline = time.time() + timeout
    while time.time() < deadline:
        for f in lsp.rpc.call("factory-list")["factories"]:
            if f["instance_id"] == iid and f["ceremony"] == "complete":
                return iid
        time.sleep(0.5)
    raise AssertionError(
        f"3-party PS factory {iid} ceremony didn't reach complete in "
        f"{timeout}s")


def _all_ps_leaf_node_indices(lsp, iid: str) -> list[int]:
    """Find all node indices that have a chain[0] entry persisted (i.e.
    every PS client leaf in this factory)."""
    nidxs = []
    for nidx in range(0, 32):
        if get_ps_chain_entry(lsp, iid, nidx, 0) is not None:
            nidxs.append(nidx)
    return nidxs


def _chain_len_for_leaf(lsp, iid: str, nidx: int) -> int:
    """Probe how many chain entries are persisted for a given leaf
    node index. Returns the highest chain_pos with a valid entry, +1
    (so 0 if only chain[0] exists)."""
    pos = 0
    while True:
        e = get_ps_chain_entry(lsp, iid, nidx, pos + 1)
        if e is None:
            return pos
        pos += 1


def test_ps_multileaf_advance_does_not_perturb_peer(ss_node_factory):
    """Build a 3-party ARITY_PS factory (LSP + 2 clients = 3
    participants → 3 leaves under ARITY_PS's one-leaf-per-participant
    rule). Identify the two PS client leaves. Advance the chain on
    leaf 0, then verify leaf 1's chain length is still 0 (only chain[0]
    persisted).

    Without leaf isolation, a single client's advance could trigger
    a re-sign or state mutation on a sibling leaf — breaking that
    peer's ability to force-close from their own chain[0]."""
    lsp, client_a, client_b = ss_node_factory.get_nodes(3)
    lsp.fundwallet(10_000_000)
    lsp.connect(client_a)
    lsp.connect(client_b)

    iid = _create_3party_ps_factory(lsp, client_a, client_b,
                                    funding_sats=300_000)

    leaves = _all_ps_leaf_node_indices(lsp, iid)
    assert len(leaves) >= 2, (
        f"3-party ARITY_PS factory should have >=2 PS leaves "
        f"(one per client); found {len(leaves)} via persisted "
        f"chain[0]: {leaves}")

    # Advance leaf 0 twice
    for pos in (1, 2):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        wait_metric(lsp, rf"event=ps_advance .* leaf=0 chain_pos={pos}",
                    timeout=30.0)

    # Leaf 0 should now show chain_len 2; the OTHER leaves should
    # still show chain_len 0.
    leaf0_chain = _chain_len_for_leaf(lsp, iid, leaves[0])
    assert leaf0_chain == 2, (
        f"leaf 0 chain_len after 2 advances should be 2, got "
        f"{leaf0_chain}")
    for other in leaves[1:]:
        other_chain = _chain_len_for_leaf(lsp, iid, other)
        assert other_chain == 0, (
            f"leaf at node {other} chain_len was perturbed by leaf 0 "
            f"advances: got {other_chain}, expected 0 — leaf isolation "
            "is broken")
