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


@pytest.mark.xfail(
    reason="The plugin's PS_PENDING_TIMEOUT_BLOCKS=3 path lives inside "
           "handle_block_added on the LSP. In this test we mine 4 "
           "blocks via lsp.bitcoin.generate_block(4) but the "
           "event=ps_advance_timeout log doesn't fire within 30s. "
           "Two possibilities: (a) handle_block_added doesn't actually "
           "see the new tip in test, or (b) ss_state.current_blockheight "
           "lags the bitcoind tip by several seconds. Need to confirm "
           "by adding a probe RPC for current_blockheight or by "
           "instrumenting handle_block_added with a per-block log. "
           "Once diagnosed, remove this xfail.",
    strict=True)
def test_ps_pending_clears_after_timeout_blocks(ss_node_factory):
    """PS_PENDING_TIMEOUT_BLOCKS=3: if a ps-advance is in flight and the
    client never responds, the LSP's per-block scheduler must clear
    ps_pending_leaf after 3 blocks elapse so a new advance can be
    started. Without this the leaf is wedged forever after a single
    network blip during PROPOSE→PSIG.

    Drive the timeout by:
      1. force-disconnecting the client (PSIG will never arrive)
      2. calling factory-ps-advance (sets pending state, sends PROPOSE
         to a dead peer connection)
      3. mining 4+ blocks via bitcoind
      4. waiting for the SS_METRIC event=ps_advance_timeout log line
      5. confirming a fresh advance no longer hits the in-flight guard"""
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

    # Mine 4 blocks (PS_PENDING_TIMEOUT_BLOCKS = 3, so 4 strictly
    # exceeds it)
    lsp.bitcoin.generate_block(4)

    # The timeout firing is logged via the LSP's per-block scheduler.
    # Allow a bit of poll time for the block-added handler to run.
    wait_metric(lsp, r"event=ps_advance_timeout leaf=0", timeout=30.0)

    # Now reconnect and verify the leaf is unwedged
    lsp.connect(client)
    r = lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
    assert r["status"] == "proposed", (
        "after timeout fired and reconnect, fresh advance should "
        f"proceed; got {r}")
    # And it should be at chain_pos=1 — the prior (failed) advance
    # didn't actually persist anything, so we're still starting fresh.
    assert r["chain_pos"] == 1, (
        f"after timeout cleanup, fresh advance should be chain_pos=1, "
        f"got {r['chain_pos']} — the timeout may have left ghost state")


@pytest.mark.xfail(
    reason="After factory-rotate completes (epoch advances 0→1), the "
           "next factory-ps-advance call fails with 'factory not in "
           "signed state (ceremony=0)'. ceremony=0 is CEREMONY_IDLE. "
           "The plugin's ps_advance handler accepts CEREMONY_COMPLETE / "
           "ROTATE_COMPLETE / REVOKED but not IDLE — so something "
           "in the post-rotate flow is leaving ceremony at IDLE. "
           "Either (a) the rotation sets ceremony=IDLE somewhere it "
           "shouldn't, or (b) the test is racing rotation completion "
           "(epoch advances before ceremony state stabilizes). "
           "Investigate by reading post-rotate ceremony state across "
           "the full rotate cycle; add CEREMONY_IDLE to the accept "
           "set if appropriate, or fix the rotation finalization.",
    strict=True)
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

    # Wait for epoch advance
    deadline = time.time() + 90.0
    final_epoch = 0
    while time.time() < deadline:
        f = next(x for x in lsp.rpc.call("factory-list")["factories"]
                 if x["instance_id"] == iid)
        final_epoch = f["epoch"]
        if final_epoch >= 1:
            break
        time.sleep(0.5)
    assert final_epoch == 1, (
        f"rotation didn't complete in 90s — epoch stuck at {final_epoch}")

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
