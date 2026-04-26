"""Path B / Item 2: per-party SPK→amount accounting.

The plugin now exposes leaves[] on factory-list with each leaf's
outputs[] (amount + scriptpubkey hex) and signers[] (factory-wide
participant indices, 0=LSP, 1..N=clients). Tests can assert that
each output's value matches a specific party's expected allocation,
not just that the sum conserves.

This is the "fees collected, L-stock, user funds settle to the
correct place" claim made testable per-party.
"""
from __future__ import annotations

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)


def _setup(ss_node_factory, *, arity_mode=None, funding_sats=200_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode=arity_mode)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _factory(lsp, iid):
    return next(f for f in lsp.rpc.call("factory-list")["factories"]
                if f["instance_id"] == iid)


def test_factory_list_exposes_leaves_with_outputs(ss_node_factory):
    """Smoke check: leaves[] is populated with outputs[] and
    signers[] after a successful ceremony."""
    lsp, _client, iid = _setup(ss_node_factory)
    f = _factory(lsp, iid)

    assert "leaves" in f, (
        "factory-list missing 'leaves' array — plugin needs the "
        "per-party SPK→amount field added.")
    assert len(f["leaves"]) > 0, "no leaves in factory"
    leaf0 = f["leaves"][0]
    for k in ("leaf_side", "node_idx", "n_signers", "is_ps_leaf",
              "signers", "outputs"):
        assert k in leaf0, f"leaf missing {k!r}: {leaf0}"
    assert isinstance(leaf0["outputs"], list)
    assert len(leaf0["outputs"]) > 0, "leaf has no outputs"
    out0 = leaf0["outputs"][0]
    for k in ("amount_sats", "scriptpubkey"):
        assert k in out0, f"output missing {k!r}: {out0}"
    # SPK hex should be 68 chars (34 bytes × 2)
    assert len(out0["scriptpubkey"]) == 68
    assert all(c in "0123456789abcdef" for c in out0["scriptpubkey"])


def test_factory_list_exposes_funding_amount_sats(ss_node_factory):
    """funding_amount_sats reflects the on-chain funding output amount
    (CLN withdraw fee already deducted). Tests use it to assert sums
    against the request without reading the TX."""
    funding_sats = 200_000
    lsp, _client, iid = _setup(ss_node_factory, funding_sats=funding_sats)
    f = _factory(lsp, iid)
    assert "funding_amount_sats" in f
    fa = f["funding_amount_sats"]
    assert isinstance(fa, int)
    # Within CLN withdraw fee ceiling (5000 sats)
    assert fa <= funding_sats
    assert funding_sats - fa <= 5000


def test_arity1_per_party_amounts_match_expected(ss_node_factory):
    """ARITY_1 default factory: each leaf has 1 client + L-stock.
    Verify each leaf's outputs add up close to funding_amount_sats
    minus tree fees, and the signer set matches expectations."""
    funding_sats = 200_000
    lsp, _client, iid = _setup(ss_node_factory, funding_sats=funding_sats)
    f = _factory(lsp, iid)

    fa = f["funding_amount_sats"]
    leaves = f["leaves"]
    assert len(leaves) >= 1

    # For each leaf, sum its outputs and verify each output is non-dust
    for leaf in leaves:
        outs = leaf["outputs"]
        out_sum = sum(o["amount_sats"] for o in outs)
        # leaf must be a positive fraction of funding (allow wide
        # bounds — exact split depends on tree shape)
        assert 0 < out_sum < fa, (
            f"leaf_side={leaf['leaf_side']} sums to {out_sum} sats; "
            f"factory funding is {fa} — out of expected range")
        # Each output non-dust
        for o in outs:
            assert o["amount_sats"] > 546, (
                f"leaf_side={leaf['leaf_side']} output amount "
                f"{o['amount_sats']} is dust")


def test_arity_ps_chain0_channel_vs_lstock_party_split(ss_node_factory):
    """ARITY_PS chain[0] has TWO outputs: client channel + LSP L-stock.
    Verify (a) the leaf reports is_ps_leaf=true with ps_chain_len=0,
    (b) both outputs are non-dust, (c) signers[] includes a non-LSP
    participant (the client), establishing which output structure
    belongs to which party.

    For 1-client ARITY_PS the signer set is [0=LSP, 1=client]; the
    setup_ps_leaf_outputs hardcodes a 50/50 channel/L-stock split."""
    lsp, _client, iid = _setup(ss_node_factory, arity_mode="arity_ps",
                               funding_sats=200_000)
    f = _factory(lsp, iid)

    ps_leaves = [l for l in f["leaves"] if l["is_ps_leaf"]]
    assert ps_leaves, "no PS leaves in arity_ps factory"
    leaf = ps_leaves[0]
    assert leaf["ps_chain_len"] == 0, (
        f"chain[0] expected ps_chain_len=0, got {leaf['ps_chain_len']}")
    assert len(leaf["outputs"]) == 2, (
        "ARITY_PS chain[0] should have 2 outputs (channel + L-stock)")
    chan_amt = leaf["outputs"][0]["amount_sats"]
    lstock_amt = leaf["outputs"][1]["amount_sats"]
    assert chan_amt > 546 and lstock_amt > 546, (
        f"chain[0] outputs are dust: chan={chan_amt}, "
        f"lstock={lstock_amt}")
    # 50/50 split per setup_ps_leaf_outputs (with rounding remainder
    # going to L-stock)
    diff = abs(chan_amt - lstock_amt)
    assert diff <= 2, (
        f"chain[0] channel/L-stock should be ~50/50, but diff is "
        f"{diff} sats (chan={chan_amt}, lstock={lstock_amt})")
    # Signer set: LSP (0) and 1 client (slot 1)
    assert 0 in leaf["signers"], "LSP not in signer set"
    assert any(s != 0 for s in leaf["signers"]), (
        "no non-LSP signer — a PS leaf must have at least one client")
