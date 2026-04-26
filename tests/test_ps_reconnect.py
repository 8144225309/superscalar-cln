"""PS coverage Layer 1 / Batch 4: reconnect mid-advance.

If the LSP-client peer connection drops between PROPOSE-send and
PSIG-receipt, the advance ceremony must either (a) recover via the
plugin's reconnect resend logic, or (b) cleanly abort via
PS_PENDING_TIMEOUT_BLOCKS. This test takes the recovery path: drop
the connection right after the RPC returns, immediately reconnect,
and verify the ceremony completes.

Pattern mirrors test_rotation_reconnect.py — the disconnect is racy
by design; CLN's connectd may or may not re-deliver in-flight
custommsgs depending on exact timing. We accept either outcome:
ceremony completes (great) or explicit timeout-then-resume.
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
    reason="LSP-side cached_ps_propose_wire resend on peer_connected "
           "is now wired (commit 92cbaa6 follow-up), but the client "
           "side bails on duplicate LEAF_ADVANCE_PROPOSE because its "
           "own ps_pending_leaf is already set from the first attempt. "
           "Making the client idempotent on duplicate PROPOSE for the "
           "same leaf+chain_pos would close the gap, but needs careful "
           "thought about replay vs MuSig nonce-reuse — the second "
           "PROPOSE could carry a different LSP pubnonce. Two-step "
           "fix: (a) client matches duplicate by (leaf,chain_pos) and "
           "ignores if its own PSIG was already sent, (b) re-uses the "
           "stashed secnonce instead of generating fresh.",
    strict=True)
def test_ps_advance_completes_after_disconnect_reconnect(ss_node_factory):
    """Issue ps-advance, immediately flap the peer connection, then
    wait for the ceremony to complete via the chain_pos=1 metric.
    Either the in-flight custommsgs re-deliver on reconnect (CLN
    connectd queues them), or the timeout+retry path eventually
    catches up.

    Uses a 90s window — generous because the timeout path takes
    PS_PENDING_TIMEOUT_BLOCKS (3) blocks to clear, plus block
    generation time."""
    lsp, client, iid = _setup_ps(ss_node_factory)
    client_id = client.info["id"]

    # Kick off the advance — returns immediately after PROPOSE goes out
    r = lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
    assert r["status"] == "proposed"

    # Race: disconnect right after, before client can reply with PSIG
    try:
        lsp.rpc.disconnect(client_id, force=True)
    except Exception:
        pass  # already disconnected is fine
    time.sleep(0.5)
    lsp.connect(client)

    # The advance should EVENTUALLY land. If connectd re-delivered
    # the queued PROPOSE/PSIG/DONE messages on reconnect, we'll see
    # it within seconds. If not, the PS_PENDING_TIMEOUT_BLOCKS path
    # would clear pending state — but THAT path doesn't auto-retry,
    # so the operator would need to re-call. This test accepts the
    # happy-path resume only: 60s window, then either pass or fail.
    try:
        wait_metric(lsp, r"event=ps_advance .* chain_pos=1",
                    timeout=60.0)
    except TimeoutError:
        # Plugin's connectd-resume didn't pick up the dropped
        # ceremony. This is a known limitation: PS advance has no
        # explicit retry on reconnect like ROTATE_PROPOSE does.
        # Re-issue manually after the timeout cleared.
        try:
            lsp.bitcoin.generate_block(4)  # force PS_PENDING_TIMEOUT
            wait_metric(lsp, r"event=ps_advance_timeout leaf=0",
                        timeout=15.0)
        except TimeoutError:
            pass
        # Now retry — pending should be clear
        lsp.rpc.call("factory-ps-advance",
                     {"instance_id": iid, "leaf_side": 0})
        wait_metric(lsp, r"event=ps_advance .* chain_pos=1",
                    timeout=30.0)
