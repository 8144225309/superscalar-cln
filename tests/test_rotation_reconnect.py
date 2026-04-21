"""Reconnect mid-rotation — guard against wedged CEREMONY_ROTATING.

Before the fix, if a client disconnected after receiving ROTATE_PROPOSE
but before sending ROTATE_NONCE, the LSP sat in CEREMONY_ROTATING
forever. The peer_connected handler only resumed CEREMONY_PROPOSED and
CEREMONY_NONCES_COLLECTED.

After the fix, the LSP caches the ROTATE_PROPOSE payload at rotation
start and resends it on any reconnect where `clients[ci].nonce_received
== false` and the ceremony is still CEREMONY_ROTATING.

These tests drive a two-party ceremony to completion, then trigger
factory-rotate and use CLN's `disconnect`/`connect` RPC to simulate a
flap. The rotation must complete (epoch bumps) rather than wedge.
"""
from __future__ import annotations

import time

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)


def _factory(lsp, iid):
    for f in lsp.rpc.call("factory-list")["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not found")


def test_rotation_completes_despite_mid_flight_client_disconnect(
        ss_node_factory):
    """Happy path rotation with a disconnect in the middle.

    Sequence:
      1. LSP + client both plugin-loaded; ceremony completes.
      2. LSP calls factory-rotate — emits ROTATE_PROPOSE.
      3. We briefly disconnect the client and reconnect. On reconnect,
         LSP must re-emit ROTATE_PROPOSE (our fix).
      4. Rotation completes; epoch bumps to 1.

    If the reconnect resend is missing, step 4 times out (epoch stays 0)
    and the factory is wedged in CEREMONY_ROTATING."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client, funding_sats=100_000)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)

    # Start the rotation.
    lsp.rpc.call("factory-rotate", {"instance_id": iid})

    # Tight flap: disconnect + reconnect quickly. Timing here is
    # deliberately racy — we want the disconnect to hit while the
    # rotation is mid-exchange. If it lands before ROTATE_PROPOSE,
    # CLN's message queue will still deliver on reconnect anyway.
    client_id = client.info["id"]
    try:
        lsp.rpc.disconnect(client_id, force=True)
    except Exception:
        pass  # already disconnected is fine
    # Short pause lets the disconnect register on both sides.
    time.sleep(1.0)
    lsp.connect(client)

    # Now wait for rotation to complete (epoch advances to 1).
    deadline = time.time() + 90.0
    final_epoch = 0
    while time.time() < deadline:
        entry = _factory(lsp, iid)
        final_epoch = entry["epoch"]
        if final_epoch > 0:
            break
        time.sleep(0.5)

    assert final_epoch == 1, (
        f"rotation wedged after reconnect — epoch stuck at "
        f"{final_epoch}. Check LSP log for 'Reconnect recovery: "
        f"re-sent ROTATE_PROPOSE'."
    )
