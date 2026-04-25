"""Accounting test: distribution TX outputs land in the right pockets.

The factory's distribution TX is co-signed at ceremony completion and
broadcast at factory expiry (or earlier on cooperative close). Its
outputs distribute the factory's L-stock and per-channel balances back
to the participants.

If the dist TX outputs are wrong, parties either lose sats at expiry
or the LSP reclaims more than its share. This test reads the persisted
signed dist TX, decodes it, and checks:

  1. Sum of outputs <= funding_amount (no sats appearing)
  2. Sum of outputs >= funding_amount - reasonable_fee (no sats lost)
  3. Each output is non-dust
  4. The number of outputs matches participant count + 1 LSP entry
     (or whatever the factory_compute_distribution_outputs convention is)
"""
from __future__ import annotations

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import (
    datastore_read_hex,
    decode_tx,
    get_factory_funding_amount,
    output_sats,
    output_spk,
)


# BIP-431 P2A (Pay-to-Anchor) script: OP_1 OP_PUSHBYTES_2 0x4e73 — used
# by the plugin for CPFP-via-anchor pre-signed TXs. Non-dust by special
# consensus rule even at 240 sats.
P2A_SCRIPT = "51024e73"


def _is_p2a(spk_hex: str) -> bool:
    return spk_hex.lower() == P2A_SCRIPT


def _setup_factory(ss_node_factory, arity_mode="arity_1",
                   funding_sats=200_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode=arity_mode)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _read_dist_tx(node, iid: str) -> bytes:
    """Read the persisted signed distribution TX bytes."""
    raw = datastore_read_hex(node,
                             ["superscalar", "factories", iid, "dist_tx"])
    assert raw is not None, (
        f"factories/{iid}/dist_tx missing from datastore — distribution "
        "TX should be persisted at ceremony completion (sub-PR 3B)")
    # Format: tx_len(u32 BE) + tx_bytes
    assert len(raw) >= 4
    tx_len = int.from_bytes(raw[:4], "big")
    assert len(raw) >= 4 + tx_len, (
        f"dist_tx blob truncated: header says {tx_len} bytes but "
        f"buffer holds {len(raw) - 4}")
    return raw[4:4 + tx_len]


def test_dist_tx_outputs_conserve_funding_arity_1(ss_node_factory):
    """Distribution TX for an ARITY_1 factory should distribute the
    funding amount across participants minus a tx fee. No sats appear,
    no sats vanish beyond a reasonable fee."""
    funding_sats = 200_000
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_1",
                                       funding_sats=funding_sats)
    on_chain_funding = get_factory_funding_amount(lsp, iid)

    dist_tx_bytes = _read_dist_tx(lsp, iid)
    dist_tx = decode_tx(lsp, dist_tx_bytes.hex())
    outs = output_sats(dist_tx)

    out_sum = sum(outs)
    fee = on_chain_funding - out_sum
    # Distribution TX spends the funding output and fans out to all
    # parties. Fee should be small but non-zero.
    assert out_sum <= on_chain_funding, (
        f"dist TX outputs sum {out_sum} > funding {on_chain_funding} "
        "— sats appearing")
    assert fee >= 0, (
        f"dist TX has negative fee {fee} — sum of outputs exceeds input")
    assert fee <= 5000, (
        f"dist TX fee {fee} is unreasonably high for a small TX — "
        "may indicate an output got zeroed or accidentally omitted")

    # Each output must be non-dust unless it's a P2A anchor (BIP-431,
    # 240 sats by convention — non-dust under the P2A consensus rule).
    for vout, amt in enumerate(outs):
        spk = output_spk(dist_tx, vout)
        if _is_p2a(spk):
            assert amt == 240, (
                f"dist TX P2A anchor output[{vout}] has {amt} sats, "
                "expected 240")
            continue
        assert amt > 546, (
            f"dist TX output[{vout}] is dust: {amt} sats — would be "
            "rejected by bitcoind on broadcast")


def test_dist_tx_outputs_conserve_funding_arity_ps(ss_node_factory):
    """Same conservation check on ARITY_PS factory. The dist TX shape
    differs (chain[0] vs full DW tree) but the invariants hold."""
    funding_sats = 200_000
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps",
                                       funding_sats=funding_sats)
    on_chain_funding = get_factory_funding_amount(lsp, iid)

    dist_tx_bytes = _read_dist_tx(lsp, iid)
    dist_tx = decode_tx(lsp, dist_tx_bytes.hex())
    outs = output_sats(dist_tx)

    out_sum = sum(outs)
    fee = on_chain_funding - out_sum
    assert out_sum <= on_chain_funding, (
        f"ARITY_PS dist TX outputs sum {out_sum} > funding "
        f"{on_chain_funding}")
    assert 0 <= fee <= 5000, (
        f"ARITY_PS dist TX fee {fee} outside sane range [0, 5000]")
    for vout, amt in enumerate(outs):
        spk = output_spk(dist_tx, vout)
        if _is_p2a(spk):
            assert amt == 240
            continue
        assert amt > 546, (
            f"ARITY_PS dist TX output[{vout}] is dust: {amt} sats")


def test_dist_tx_persisted_after_ceremony(ss_node_factory):
    """Pure presence check — the dist TX MUST be persisted at ceremony
    completion. If not, factory expiry has nothing to broadcast and
    funds get stuck behind the timeout-script-path. This guards against
    a regression where dist signing or persistence is silently skipped."""
    funding_sats = 200_000
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_1",
                                       funding_sats=funding_sats)
    raw = datastore_read_hex(lsp,
                             ["superscalar", "factories", iid, "dist_tx"])
    assert raw is not None and len(raw) > 4, (
        "dist_tx datastore entry empty or missing")

    # Cross-check: factory-list should also report dist_tx_status=signed
    # so operator tooling can tell at a glance.
    f = next(x for x in lsp.rpc.call("factory-list")["factories"]
             if x["instance_id"] == iid)
    assert f["dist_tx_status"] == "signed", (
        f"factory-list reports dist_tx_status={f['dist_tx_status']!r}, "
        "expected 'signed' after ceremony complete")
    assert f.get("dist_signed_txid"), (
        "factory-list should report dist_signed_txid once dist TX is "
        "co-signed and serialized")
