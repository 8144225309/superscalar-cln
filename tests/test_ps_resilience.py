"""PS coverage Layer 1 / Batch 3: resilience + recovery paths.

Covers behavior under stress / failure:
  - PS_PENDING_TIMEOUT_BLOCKS clears stale ceremony state after 3 blocks
  - Rotation while PS at chain[N>0] resets chain to chain[0] in the new
    epoch

Both tests in this file are currently xfail with documented reasons.
The behaviors they probe DO need test coverage; the regtest test
infrastructure isn't reliably driving them. Promote to passing once
the noted gaps are closed.
"""
from __future__ import annotations

import time

import pytest

from pyln.testing.utils import sync_blockheight

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import wait_metric


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


def test_ps_pending_clears_after_timeout_blocks(ss_node_factory):
    """PS_PENDING_TIMEOUT_BLOCKS=3: if a ps-advance is in flight and the
    client never responds, the LSP's per-block scheduler must clear
    ps_pending_leaf after 3 blocks elapse so a new advance can be
    started. Without this the leaf is wedged forever after a single
    network blip during PROPOSE→PSIG.

    Drives the timeout via dev-superscalar-tick rather than
    bitcoind.generate_block — pyln-testing's --developer mode doesn't
    propagate block_added notifications to the plugin, so synthetic
    block ticks are the reliable way to exercise the per-block
    scheduler from regtest. Production code path is the same
    (ss_clear_ps_pending called when current_blockheight >
    start_block + PS_PENDING_TIMEOUT_BLOCKS)."""
    lsp, client, iid = _setup_ps(ss_node_factory)
    client_id = client.info["id"]

    # Disconnect first so PROPOSE has nowhere to go
    try:
        lsp.rpc.disconnect(client_id, force=True)
    except Exception:
        pass

    # Start the advance — pending state set synchronously in the handler
    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})

    state_pre = lsp.rpc.call("dev-superscalar-state",
                             {"instance_id": iid})
    start_block = state_pre["ps_pending_start_block"]
    assert state_pre["ps_pending_leaf"] == 0, (
        f"expected ps_pending_leaf=0 after advance, got "
        f"{state_pre['ps_pending_leaf']}")

    # Tick to start_block + PS_PENDING_TIMEOUT_BLOCKS (3) — boundary,
    # should NOT yet trigger cleanup.
    r_below = lsp.rpc.call("dev-superscalar-tick",
                           {"to_height": start_block + 3})
    assert r_below["ps_pending_cleared"] == 0, (
        "tick to start_block + 3 should not clear pending — the "
        "condition is strictly >, not >=")

    # Tick to start_block + 4 — strictly exceeds threshold, must clear.
    r_above = lsp.rpc.call("dev-superscalar-tick",
                           {"to_height": start_block + 4})
    assert r_above["ps_pending_cleared"] == 1, (
        f"tick to start_block + 4 should clear 1 pending advance, "
        f"got cleared={r_above['ps_pending_cleared']}")

    # Confirm via probe that ps_pending_leaf is now -1
    s_post = lsp.rpc.call("dev-superscalar-state",
                          {"instance_id": iid})
    assert s_post["ps_pending_leaf"] == -1, (
        f"after tick-driven timeout, ps_pending_leaf should be -1, "
        f"got {s_post['ps_pending_leaf']}")

    # Now reconnect and verify a fresh advance proceeds without
    # the in-flight guard firing. chain_pos may be 1 OR 2 here:
    # factory_advance_leaf_unsigned ratchets ps_chain_len at the
    # FIRST advance's RPC handler, even if the ceremony then fails
    # (documented upstream contract — the ratchet doesn't persist
    # an unsigned chain entry, but the in-memory counter advances).
    # The meaningful assertion is "no in-flight guard, ceremony can
    # progress", not the specific chain_pos number.
    lsp.connect(client)
    r = lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
    assert r["status"] == "proposed"
    assert r["chain_pos"] in {1, 2}, (
        f"after timeout cleanup, fresh advance should report "
        f"chain_pos=1 or 2 (depending on whether the failed first "
        f"attempt's ratchet was preserved); got {r['chain_pos']}")


def test_rotation_resets_ps_chain_to_chain0(ss_node_factory):
    """After rotation, every PS leaf's chain state resets to chain[0]
    in the new epoch. Without this reset, post-rotation advances
    would try to spend chain entries from a tree that no longer
    matches the on-chain root.

    Verify by:
      1. Setup PS factory, advance twice → chain_pos=2 in epoch 0
      2. factory-rotate → epoch 1
      3. Wait for rotation complete
      4. Try a fresh ps-advance → must report chain_pos=1, not 3.
         (Rotation built fresh chain[0]; first new advance is chain[1].)"""
    lsp, _client, iid = _setup_ps(ss_node_factory)

    # Two advances in epoch 0
    for pos in (1, 2):
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        wait_metric(lsp, rf"event=ps_advance .* chain_pos={pos}",
                    timeout=30.0)

    # Trigger rotation
    lsp.rpc.call("factory-rotate", {"instance_id": iid})

    # Wait for the rotation's ceremony state to stabilize at a signed
    # state — epoch advances at the START of factory-rotate (during the
    # RPC handler), but the ceremony bounces through ROTATING (sending
    # PROPOSE/ALL_NONCES/PSIG) before reaching ROTATE_COMPLETE (or
    # REVOKED after REVOKE_ACK). ps-advance accepts ceremony in
    # {COMPLETE=5, ROTATE_COMPLETE=8, REVOKED=9}.
    SIGNED_STATES = {5, 8, 9}
    deadline = time.time() + 90.0
    final_state = None
    final_epoch = 0
    while time.time() < deadline:
        s = lsp.rpc.call("dev-superscalar-state", {"instance_id": iid})
        final_state = s["ceremony"]
        final_epoch = s["epoch"]
        if final_epoch >= 1 and final_state in SIGNED_STATES:
            break
        time.sleep(0.5)
    assert final_epoch == 1, (
        f"rotation didn't advance epoch in 90s — got {final_epoch}")
    assert final_state in SIGNED_STATES, (
        f"rotation finished epoch={final_epoch} but ceremony stayed at "
        f"{final_state}; expected one of "
        f"{{COMPLETE=5, ROTATE_COMPLETE=8, REVOKED=9}}. The dist-TX "
        "re-sign may have hung on this PS factory.")

    # Now advance in the new epoch — chain_pos should be 1, not 3
    r = lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
    assert r["status"] == "proposed"
    assert r["chain_pos"] == 1, (
        f"post-rotation advance got chain_pos={r['chain_pos']}, "
        "expected 1 — rotation failed to reset PS chain state. "
        "The tree was rebuilt at the new epoch; chain[N>0] entries "
        "from the old epoch are no longer valid and the next advance "
        "must start from chain[0].")
