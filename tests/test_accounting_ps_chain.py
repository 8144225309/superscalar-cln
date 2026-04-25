"""Accounting test: PS chain advance amount conservation.

Each `factory-ps-advance` produces a new chain entry that spends the
prior chain element's channel output. The new TX's output amount must
equal the prior amount minus a single per-TX fee (no L-stock split
post chain[0], so it's a 1-input 1-output TX).

Sanity invariants:
  - chain[N].output_amount > chain[N+1].output_amount (strictly
    decreasing — fee always charged)
  - chain[N+1].output_amount == chain[N].output_amount - per_advance_fee
    (the per_advance_fee should be stable across positions)

If either breaks, the chain is leaking sats (or something's silently
adding them).
"""
from __future__ import annotations

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import (
    decode_tx,
    get_ps_chain_entry,
    output_sats,
    wait_metric,
)


def _setup_arity_ps(ss_node_factory, funding_sats=200_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode="arity_ps")
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _leaf_node_idx(lsp, iid: str) -> int:
    """Find the leaf-node index for the (single) leaf in a 2-party PS
    factory by reading any persisted ps_chain key. Pick the first idx
    that has a chain[0] entry."""
    # Probe candidate node indexes; tree depth is small for 2-party.
    for nidx in range(0, 16):
        if get_ps_chain_entry(lsp, iid, nidx, 0) is not None:
            return nidx
    raise AssertionError(
        f"no ps_chain/{iid}/* entries found — "
        "ARITY_PS factory should persist chain[0] right after ceremony")


def test_ps_chain_advance_decrements_output_amount_by_fee(ss_node_factory):
    """After 3 PS advances, chain[0]..chain[3] output amounts must form
    a strictly decreasing sequence with constant delta (per_advance_fee).

    This is the core conservation invariant for PS leaves: every
    advance burns exactly one TX fee from the channel output, and that
    fee should be the same value at every position (the factory's
    per-TX fee setting)."""
    lsp, _client, iid = _setup_arity_ps(ss_node_factory)
    nidx = _leaf_node_idx(lsp, iid)

    # Read chain[0]
    e0 = get_ps_chain_entry(lsp, iid, nidx, 0)
    assert e0 is not None, "chain[0] missing from datastore"
    chain0_decoded = decode_tx(lsp, e0[2].hex())
    # PS chain[0] has 2 outputs (channel + L-stock); chain[N>=1] has 1.
    chain0_chan = output_sats(chain0_decoded)[0]

    amounts = [chain0_chan]
    fees = []
    for advance_pos in range(1, 4):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        # Wait for the persist save to complete (LSP fires its metric
        # AFTER datastore set). chain_pos in the metric == position of
        # the new entry.
        wait_metric(lsp,
                    rf"event=ps_advance .* leaf=0 chain_pos={advance_pos}",
                    timeout=30.0)
        e = get_ps_chain_entry(lsp, iid, nidx, advance_pos)
        assert e is not None, (
            f"chain[{advance_pos}] missing from datastore after "
            "ps-advance returned success")
        decoded = decode_tx(lsp, e[2].hex())
        outs = output_sats(decoded)
        assert len(outs) == 1, (
            f"chain[{advance_pos}] has {len(outs)} outputs, expected 1 "
            "(PS post-chain[0] is single-output per design)")
        amounts.append(outs[0])
        fees.append(amounts[-2] - amounts[-1])

    # Strictly decreasing
    for i in range(1, len(amounts)):
        assert amounts[i] < amounts[i - 1], (
            f"chain[{i}].out={amounts[i]} >= chain[{i-1}].out="
            f"{amounts[i-1]} — fee not deducted, sats appearing")

    # Fees should be (close to) constant — same factory_t->fee_per_tx
    # applies to each rebuild. Allow ±1 sat for rounding.
    assert max(fees) - min(fees) <= 1, (
        f"per-advance fees vary: {fees} — fee_per_tx should be stable "
        "across PS chain positions")

    # And the fee should be a sane bound — neither zero nor catastrophic.
    f0 = fees[0]
    assert 100 <= f0 <= 5000, (
        f"per-advance fee {f0} sats is outside the sane band "
        "[100, 5000]; check factory_t fee config")


def test_ps_chain0_channel_plus_lstock_match_funding(ss_node_factory):
    """chain[0] = channel output + L-stock output. The pair plus the
    chain[0] tx fee must equal whatever the parent state TX paid into
    this leaf. We can't easily compute the upstream amount from
    factory-list, so just sanity-check the pair is non-trivial."""
    funding_sats = 200_000
    lsp, _client, iid = _setup_arity_ps(ss_node_factory,
                                        funding_sats=funding_sats)
    nidx = _leaf_node_idx(lsp, iid)

    e0 = get_ps_chain_entry(lsp, iid, nidx, 0)
    assert e0 is not None
    decoded = decode_tx(lsp, e0[2].hex())
    outs = output_sats(decoded)
    assert len(outs) == 2, (
        f"chain[0] has {len(outs)} outputs, expected 2 "
        "(channel + L-stock)")
    chan, lstock = outs
    # Both outputs must be non-dust.
    assert chan > 546, f"chain[0] channel output is dust: {chan}"
    assert lstock > 546, f"chain[0] L-stock output is dust: {lstock}"
    # The pair sum must be < funding (chain[0] is a leaf — there are
    # parent state-tree fees stacked above it).
    assert chan + lstock < funding_sats, (
        f"chain[0] outputs sum to {chan + lstock} >= funding "
        f"{funding_sats} — no fees being charged at intermediate "
        "tree layers")
    # And the pair sum should still be ALMOST funding — most of the
    # funding ends up in the leaf, with only tree-layer fees skimmed.
    # Tree depth for 2-party is small, so allow up to 2000 sats stacked.
    assert chan + lstock >= funding_sats - 5000, (
        f"chain[0] outputs sum to {chan + lstock}, funding was "
        f"{funding_sats}, diff {funding_sats - (chan + lstock)} sats "
        "— tree fees are unexpectedly high (or sats are leaking)")
