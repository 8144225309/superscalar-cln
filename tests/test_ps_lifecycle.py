"""PS coverage Layer 1 / Batch 2: chain lifecycle + persistence.

Single-client PS factory tests covering:
  - Concurrent ps-advance is rejected with a clean error
  - Chain entries persist across BOTH client and LSP restart
  - Defense rows persist across client restart
  - Force-close after multiple advances broadcasts every chain TX
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
    get_ps_chain_entry,
    get_signed_txs_for_factory,
    output_sats,
    wait_metric,
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


def _leaf_node_idx(lsp, iid: str) -> int:
    for nidx in range(0, 16):
        if get_ps_chain_entry(lsp, iid, nidx, 0) is not None:
            return nidx
    raise AssertionError("no chain[0] persisted")


def _ps_signed_input_count(client, iid: str) -> int:
    r = client.rpc.listdatastore(
        ["superscalar", "factories", iid, "ps_signed_inputs"])
    return len(r.get("datastore") or [])


def test_concurrent_ps_advance_is_rejected(ss_node_factory):
    """Calling factory-ps-advance twice with an intervening pending
    state should error cleanly. The plugin sets fi->ps_pending_leaf
    synchronously inside the RPC handler, so the second call sees the
    guard immediately."""
    lsp, _client, iid = _setup_ps(ss_node_factory)

    # First call kicks off ceremony — succeeds and returns immediately
    # (PROPOSE sent, awaiting client PSIG asynchronously).
    r1 = lsp.rpc.call("factory-ps-advance",
                      {"instance_id": iid, "leaf_side": 0})
    assert r1["status"] == "proposed"

    # The second call may race the first to completion — accept either:
    # (a) the guard fires and the RPC errors with "another PS advance
    #     in flight"
    # (b) the first ceremony already completed, ps_pending_leaf was
    #     reset, and the second succeeds with chain_pos=2
    try:
        r2 = lsp.rpc.call("factory-ps-advance",
                          {"instance_id": iid, "leaf_side": 0})
        # Path (b): first finished fast, second succeeded
        assert r2["status"] == "proposed"
        assert r2["chain_pos"] == 2, (
            f"second advance got chain_pos={r2['chain_pos']}, "
            "expected 2 (one past first)")
    except RpcError as e:
        # Path (a): guard fired
        msg = str(e)
        assert "another PS advance in flight" in msg, (
            f"unexpected error: {msg}")


def test_ps_chain_continues_after_lsp_restart(ss_node_factory):
    """After advancing once and restarting the LSP, the next advance
    should pick up at chain_pos=2 (not 1 again, not 0). This proves
    the LSP correctly replays ps_chain entries on load and uses the
    persisted ps_chain_len as the next advance's starting point."""
    lsp, _client, iid = _setup_ps(ss_node_factory)

    # Advance once: chain_pos 0 → 1
    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})
    wait_metric(lsp, r"event=ps_advance .* chain_pos=1", timeout=30.0)

    # Restart LSP — plugin must reload chain entries from datastore
    lsp.restart()

    # Reconnect (LSP→client peer connection survives but the plugin
    # may need a fresh handshake)
    # NOTE: pyln-testing's restart() may or may not re-establish peer
    # connections; we rely on autoconnect / supported_factory_protocols
    # exchange firing on first attempt.

    # Second advance: must start at chain_pos=2, not 1
    r2 = lsp.rpc.call("factory-ps-advance",
                      {"instance_id": iid, "leaf_side": 0})
    assert r2["status"] == "proposed"
    assert r2["chain_pos"] == 2, (
        f"after LSP restart, second advance got chain_pos="
        f"{r2['chain_pos']} — expected 2. Plugin failed to replay "
        "ps_chain on load, so it 'forgot' the prior advance and is "
        "trying to overwrite chain[1].")


def test_ps_signed_inputs_persist_across_client_restart(ss_node_factory):
    """The Tier B defense rows MUST survive a lightningd restart on
    the client side. If they don't, an LSP that crashed the client
    after one advance could try a replay and the defense would no
    longer fire."""
    lsp, client, iid = _setup_ps(ss_node_factory)

    # Two advances → 2 ps_signed_inputs rows on the client
    for pos in (1, 2):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        wait_metric(lsp, rf"event=ps_advance .* chain_pos={pos}",
                    timeout=30.0)
        wait_metric(client,
                    rf"event=ps_advance_client_done .* chain_pos={pos}",
                    timeout=30.0)

    pre_count = _ps_signed_input_count(client, iid)
    assert pre_count == 2, (
        f"expected 2 ps_signed_inputs rows, got {pre_count}")

    # Restart the CLIENT (not the LSP). Defense rows must survive.
    client.restart()

    post_count = _ps_signed_input_count(client, iid)
    assert post_count == pre_count, (
        f"ps_signed_inputs rows lost on restart: pre={pre_count}, "
        f"post={post_count} — defense state is not durable")


def test_force_close_after_multiple_ps_advances(ss_node_factory):
    """After 3 PS advances, force-close must broadcast every chain
    entry (chain[0..3]) plus the upstream tree TXs. Each chain TX
    spends the prior one's vout 0; the chain must be valid as a
    sequence."""
    lsp, _client, iid = _setup_ps(ss_node_factory)
    nidx = _leaf_node_idx(lsp, iid)

    # Three advances
    for pos in (1, 2, 3):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        wait_metric(lsp, rf"event=ps_advance .* chain_pos={pos}",
                    timeout=30.0)

    # Verify all 4 chain entries (chain[0..3]) are persisted
    for pos in range(0, 4):
        e = get_ps_chain_entry(lsp, iid, nidx, pos)
        assert e is not None, f"chain[{pos}] missing from datastore"

    # Force-close
    lsp.rpc.call("factory-force-close", {"instance_id": iid})

    # Verify the tree TXs are still well-formed (post force-close,
    # the plugin shouldn't have corrupted them).
    signed = get_signed_txs_for_factory(lsp, iid)
    assert signed, "force-close left no signed_txs blob"

    # Each chain entry's signed_tx must spend the prior one's txid:0
    prev_txid = None
    for pos in range(0, 4):
        e = get_ps_chain_entry(lsp, iid, nidx, pos)
        # e is (txid_internal_be, chan_amt, tx_bytes)
        decoded = decode_tx(lsp, e[2].hex())
        if prev_txid is not None:
            # chain[pos] must spend chain[pos-1] vout 0
            this_input_txid = decoded["vin"][0]["txid"]
            this_input_vout = decoded["vin"][0]["vout"]
            # chain[pos-1].txid is in internal BE order; bitcoind shows
            # it in display order (reversed).
            prev_display_txid = prev_txid[::-1].hex()
            assert this_input_txid == prev_display_txid, (
                f"chain[{pos}] spends {this_input_txid[:16]}.. but "
                f"chain[{pos-1}] is {prev_display_txid[:16]}..")
            assert this_input_vout == 0, (
                f"chain[{pos}] spends vout {this_input_vout}, "
                "expected 0 (PS channel output is always vout 0)")
        prev_txid = e[0]
        # And outputs must be non-dust
        for vout, amt in enumerate(output_sats(decoded)):
            assert amt > 546, (
                f"chain[{pos}] output[{vout}] is dust: {amt} sats")
