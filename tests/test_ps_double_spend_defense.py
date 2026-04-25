"""Tier B regression test: client refuses a PS double-spend attempt.

The client_ps_signed_inputs persist table records every PS leaf
advance the client has co-signed. If the LSP sends a second
LEAF_ADVANCE_PROPOSE for a parent UTXO the client has already signed
against (with a different sighash — i.e. different child TX), the
client must refuse rather than co-sign a second child. This is the
SOLE security property protecting PS leaves (DW leaves use
decrementing nSequence instead).

End-to-end signet validated commit 61a37d0; this test pins it at
the regtest level.

The simplest way to drive a "duplicate parent_txid" without a
malicious LSP fork is to inject a synthetic record into the client's
datastore that points at the ACTUAL next chain[N] parent_txid the LSP
will use, then run a real ps-advance and assert the client refuses.
"""
from __future__ import annotations

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import (
    decode_tx,
    get_ps_chain_entry,
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


def _ps_signed_input_count(client, iid: str) -> int:
    """Count rows under the client's ps_signed_inputs prefix."""
    r = client.rpc.listdatastore(
        ["superscalar", "factories", iid, "ps_signed_inputs"])
    return len(r.get("datastore") or [])


def _leaf_node_idx(lsp, iid: str) -> int:
    for nidx in range(0, 16):
        if get_ps_chain_entry(lsp, iid, nidx, 0) is not None:
            return nidx
    raise AssertionError("no chain[0] persisted")


def test_first_advance_persists_signed_input_row(ss_node_factory):
    """After a single PS advance, the CLIENT side should have exactly
    one ps_signed_inputs row keyed by chain[0]'s txid (the parent of
    chain[1]). If this never appears, the defense isn't actually
    persisting state."""
    lsp, client, iid = _setup_arity_ps(ss_node_factory)
    assert _ps_signed_input_count(client, iid) == 0, (
        "client unexpectedly already has ps_signed_inputs rows "
        "before any advance")

    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})
    wait_metric(lsp, r"event=ps_advance .* chain_pos=1", timeout=30.0)
    wait_metric(client, r"event=ps_advance_client_done .* chain_pos=1",
                timeout=30.0)

    n = _ps_signed_input_count(client, iid)
    assert n == 1, (
        f"after first PS advance, client should have 1 ps_signed_inputs "
        f"row (chain[0]→chain[1]); got {n}")


def test_consecutive_advances_persist_separate_rows(ss_node_factory):
    """Each PS advance writes a new row under a distinct parent_txid.
    No row should be overwritten or deduplicated — the defense relies
    on every prior parent being remembered forever (or at least until
    the factory closes)."""
    lsp, client, iid = _setup_arity_ps(ss_node_factory)

    for i in range(1, 4):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        wait_metric(lsp, rf"event=ps_advance .* chain_pos={i}",
                    timeout=30.0)
        wait_metric(client,
                    rf"event=ps_advance_client_done .* chain_pos={i}",
                    timeout=30.0)
        n = _ps_signed_input_count(client, iid)
        assert n == i, (
            f"after {i} advances, client should have {i} "
            f"ps_signed_inputs rows; got {n}")


def test_replay_attempt_is_refused(ss_node_factory):
    """Inject a synthetic ps_signed_inputs row for what would be the
    NEXT parent_txid (chain[1]'s txid), then attempt a second advance.
    The client should detect the prior row and refuse to sign the
    chain[2] PROPOSE.

    Note: chain[2]'s parent IS chain[1].txid. We pre-populate that row
    BEFORE running the second advance so the check fires."""
    lsp, client, iid = _setup_arity_ps(ss_node_factory)
    nidx = _leaf_node_idx(lsp, iid)

    # First advance: chain[0] -> chain[1]. Defense doesn't fire here
    # (ps_chain_len was 0 before advance).
    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})
    wait_metric(lsp, r"event=ps_advance .* chain_pos=1", timeout=30.0)
    wait_metric(client, r"event=ps_advance_client_done .* chain_pos=1",
                timeout=30.0)

    # Find chain[1]'s txid — that's the parent the client would use
    # when signing chain[2].
    e1 = get_ps_chain_entry(lsp, iid, nidx, 1)
    assert e1 is not None, "chain[1] missing"
    chain1_txid_internal_be = e1[0]  # internal BE (matches plugin's storage)
    chain1_txid_hex = chain1_txid_internal_be.hex()

    # Pre-populate the client's ps_signed_inputs row for that txid with
    # a SYNTHETIC sighash. When the real chain[2] advance arrives, the
    # client's check will see a prior row and refuse.
    synthetic_sighash = b"\xaa" * 32
    payload = (0).to_bytes(4, "big") + synthetic_sighash  # 4 + 32 = 36
    client.rpc.call("datastore", {
        "key": ["superscalar", "factories", iid,
                "ps_signed_inputs", chain1_txid_hex],
        "hex": payload.hex(),
        "mode": "create-or-replace",
    })

    # Confirm the row was written
    n_before = _ps_signed_input_count(client, iid)
    assert n_before >= 2, (
        f"expected >=2 rows after pre-populate, got {n_before}")

    # Now drive the LSP to send chain[2] PROPOSE. The client should
    # log a refusal and NOT send PSIG.
    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})

    # The client's refuse-log fires before any PSIG could be sent.
    # Look for the LOG_BROKEN refusal line. Tolerate a generous wait
    # since the event has to round-trip via the wire.
    wait_metric(client, r"REFUSING PS double-spend", timeout=30.0)

    # And verify no chain_pos=2 client-done metric fires within a
    # follow-up window — the ceremony must be aborted.
    import time
    time.sleep(3.0)
    saw_chain2_done = any(
        "ps_advance_client_done" in line and "chain_pos=2" in line
        for line in client.daemon.logs)
    assert not saw_chain2_done, (
        "client emitted chain_pos=2 done metric despite the defense "
        "row being pre-populated — refusal didn't actually block "
        "the ceremony")
