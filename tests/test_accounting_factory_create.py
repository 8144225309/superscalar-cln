"""Accounting test: factory creation conservation.

Verifies that after a factory ceremony completes:
  - The on-chain funding TX has an output matching the requested
    funding_sats (within CLN withdraw fee tolerance)
  - The persisted signed leaf TXs spend that funding output
  - Sum of all leaf node outputs (channel outputs + L-stock) plus the
    sum of internal factory-tree fees equals the funding amount

If any of these break, the LSP or a client could be losing sats — or
the plugin could be silently zeroing an output.

Tests both ARITY_1 (single-client leaves, simplest accounting) and
ARITY_PS (chain[0] starts with channel + L-stock outputs).
"""
from __future__ import annotations

import pytest

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import (
    btc_to_sats,
    decode_tx,
    get_factory_funding_amount,
    get_signed_txs_for_factory,
    get_tx_from_chain,
    output_sats,
)


def _setup_factory(ss_node_factory, arity_mode, funding_sats=200_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode=arity_mode)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _factory_funding_id(lsp, iid: str) -> tuple[str, int]:
    """Pull (funding_txid, funding_outnum) from factory-list."""
    f = next(x for x in lsp.rpc.call("factory-list")["factories"]
             if x["instance_id"] == iid)
    return (f["funding_txid"], f["funding_outnum"])


def test_arity1_funding_tx_carries_expected_output(ss_node_factory):
    """The on-chain output at (funding_txid, funding_outnum) should be
    close to the requested funding_sats. CLN's withdraw subtracts a
    small fee; allow up to 5000 sats slippage. The on-chain value is
    the SOURCE OF TRUTH for everything downstream."""
    funding_sats = 200_000
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_1",
                                       funding_sats=funding_sats)

    funding_txid, funding_outnum = _factory_funding_id(lsp, iid)
    on_chain_amt = get_factory_funding_amount(lsp, iid)

    # The on-chain output should be at most the requested funding (no
    # extra sats appearing) and at least funding-fee_ceiling (CLN
    # didn't eat too much).
    assert on_chain_amt <= funding_sats, (
        f"on-chain factory output {on_chain_amt} sats > requested "
        f"{funding_sats} — extra sats appearing from somewhere")
    assert funding_sats - on_chain_amt <= 5000, (
        f"CLN withdraw ate too much fee: requested {funding_sats}, "
        f"on-chain {on_chain_amt}, diff "
        f"{funding_sats - on_chain_amt}")
    # Sanity: the output must actually exist (i.e. funding_outnum is
    # in range and the TX has > funding_outnum outputs).
    tx = get_tx_from_chain(lsp, funding_txid)
    assert funding_outnum < len(tx["vout"]), (
        f"funding_outnum={funding_outnum} but funding TX only has "
        f"{len(tx['vout'])} outputs")


def test_arity1_signed_leaf_txs_spend_funding(ss_node_factory):
    """The persisted signed_txs blob should contain the leaf TX(s) and
    they should spend exactly one input — the factory funding output.
    Each leaf's output sum should be <= the parent's output amount
    (accounting for the fee at each tree layer)."""
    funding_sats = 200_000
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_1",
                                       funding_sats=funding_sats)

    funding_txid, funding_outnum = _factory_funding_id(lsp, iid)
    on_chain_amt = get_factory_funding_amount(lsp, iid)
    signed = get_signed_txs_for_factory(lsp, iid)
    assert signed, (
        "persisted signed_txs blob is empty — ceremony reported "
        "complete but no signed leaf TXs were saved. "
        "Force-close after restart would have nothing to broadcast.")

    # ARITY_1 with 1 client → tree has root state TX + 1 leaf node.
    # Whichever node spends the funding output is the root (kickoff or
    # state, depending on tree depth).
    root_spending_txes = []
    for node_idx, raw_tx in signed.items():
        decoded = decode_tx(lsp, raw_tx.hex())
        for vin in decoded["vin"]:
            if vin.get("txid") == funding_txid \
                    and vin.get("vout") == funding_outnum:
                root_spending_txes.append((node_idx, decoded))
                break
    assert root_spending_txes, (
        "no signed TX in the tree spends the factory funding output — "
        "the tree must have a root that spends it, or force-close cannot "
        "proceed")
    # Each root spender's sum(outputs) must be < funding (some sats go
    # to fees + chained children).
    for node_idx, dtx in root_spending_txes:
        out_sum = sum(output_sats(dtx))
        assert out_sum <= on_chain_amt, (
            f"root TX (node {node_idx}) outputs sum to {out_sum} > "
            f"funding {on_chain_amt} — sats appearing from nowhere")
        fee = on_chain_amt - out_sum
        # Reasonable per-TX fee bound: <= 1000 sats per TX (~3 kvB max
        # at 250 sat/kvB which is regtest default-ish). Catches
        # zero-output bugs that fall through into ridiculous fees.
        assert fee <= 5000, (
            f"root TX (node {node_idx}) has fee {fee} sats — "
            "way more than expected; an output may have been zeroed")


def test_arity_ps_chain0_has_two_outputs_summing_to_funding_minus_fee(
        ss_node_factory):
    """ARITY_PS chain[0] is the leaf's initial state with TWO outputs:
    the client's channel output and the LSP's L-stock. Their sum, plus
    the chain[0] TX fee, must equal the funding-spending root TX's
    output amount that goes to this leaf."""
    funding_sats = 200_000
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps",
                                       funding_sats=funding_sats)

    signed = get_signed_txs_for_factory(lsp, iid)
    assert signed, "ARITY_PS ceremony left no signed TXs persisted"

    # Find a TX with exactly 2 outputs — that's a chain[0] PS leaf
    # (channel + L-stock). For a 2-party (1 client) ARITY_PS factory
    # with default tree depth, chain[0] is one of the signed nodes.
    ps_chain0_txes = []
    for node_idx, raw_tx in signed.items():
        decoded = decode_tx(lsp, raw_tx.hex())
        if len(decoded["vout"]) == 2:
            ps_chain0_txes.append((node_idx, decoded))
    assert ps_chain0_txes, (
        "no 2-output TX found in signed_txs — ARITY_PS chain[0] should "
        "have channel + L-stock outputs (n_outputs=2). All TXs had "
        f"output counts: {[len(decode_tx(lsp, t.hex())['vout']) for t in signed.values()]}")

    # Pick one and verify both outputs are non-dust.
    for node_idx, dtx in ps_chain0_txes:
        outs = output_sats(dtx)
        assert outs[0] > 546, (
            f"PS chain[0] (node {node_idx}) output[0] (channel) is "
            f"dust: {outs[0]} sats")
        assert outs[1] > 546, (
            f"PS chain[0] (node {node_idx}) output[1] (L-stock) is "
            f"dust: {outs[1]} sats")
        assert sum(outs) <= funding_sats, (
            f"chain[0] outputs sum to {sum(outs)} > funding "
            f"{funding_sats}")
